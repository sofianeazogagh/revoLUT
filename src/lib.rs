#[cfg(test)]
extern crate quickcheck;
#[cfg(test)]
#[macro_use(quickcheck)]
extern crate quickcheck_macros;

use aligned_vec::ABox;
use num_complex::Complex;
use rayon::iter::{IntoParallelIterator, ParallelBridge, ParallelIterator};
use serde::{Deserialize, Serialize};
use std::io::{Read, Write};
use std::{fs, io};
// use std::process::Output;
use std::sync::OnceLock;
use std::time::Instant;
use tfhe::shortint::{CarryModulus, MessageModulus};
use tfhe::{core_crypto::prelude::polynomial_algorithms::*, core_crypto::prelude::*};
// use tfhe::core_crypto::prelude::polynomial_algorithms::polynomial_wrapping_monic_monomial_mul_assign;
use tfhe::shortint::parameters::ClassicPBSParameters;
use tfhe::shortint::prelude::CiphertextModulus;

// Fast Fourier Transform
use concrete_fft::c64;
use dyn_stack::{GlobalPodBuffer, PodStack, ReborrowMut};
use tfhe::core_crypto::entities::FourierPolynomial;
use tfhe::core_crypto::fft_impl::fft64::math::fft::FftView;

use rand::Rng;

mod blind_sort;
mod blind_topk;
pub mod lut;
pub mod nlwe;
pub mod packed_lut;
pub mod radix;

pub type LWE = LweCiphertext<Vec<u64>>;
pub type GLWE = GlweCiphertext<Vec<u64>>;
pub type Poly = Polynomial<Vec<u64>>;

pub fn random_lut(param: ClassicPBSParameters) -> LUT {
    let size = param.message_modulus.0;
    let mut rng = rand::thread_rng();
    let array: Vec<u64> = (0..size).map(|_| rng.gen_range(0..size as u64)).collect();
    LUT::from_vec(&array, &key(param), &mut Context::from(param))
}

/// gets a cached key or generate a new one
pub fn key(param: ClassicPBSParameters) -> &'static PrivateKey {
    let bitsize = param.message_modulus.0.ilog2() as usize;
    static KEYS: OnceLock<Vec<OnceLock<PrivateKey>>> = OnceLock::new();
    KEYS.get_or_init(|| Vec::from_iter((0..9).map(|_| OnceLock::new())))[bitsize].get_or_init(
        || {
            // println!("looking for PrivateKey{}", bitsize);
            // let start = Instant::now();
            let result =
                PrivateKey::from_file(&format!("PrivateKey{}", bitsize)).unwrap_or_else(|| {
                    println!("cache miss, generating PrivateKey{}", bitsize);
                    PrivateKey::to_file(&mut Context::from(param))
                });
            // println!("took {:?}", Instant::now() - start);
            result
        },
    )
}

// Polynomial multiplication using FFT
pub(crate) fn polynomial_fft_wrapping_mul<Scalar, OutputCont, LhsCont, RhsCont>(
    output: &mut Polynomial<OutputCont>,
    lhs: &Polynomial<LhsCont>,
    rhs: &Polynomial<RhsCont>,
    fft: FftView,
    stack: &mut PodStack,
) where
    Scalar: UnsignedTorus,
    OutputCont: ContainerMut<Element = Scalar>,
    LhsCont: Container<Element = Scalar>,
    RhsCont: Container<Element = Scalar>,
{
    assert_eq!(lhs.polynomial_size(), rhs.polynomial_size());
    let n = lhs.polynomial_size().0;

    let mut fourier_lhs = FourierPolynomial {
        data: vec![c64::default(); n / 2],
    };
    let mut fourier_rhs = FourierPolynomial {
        data: vec![c64::default(); n / 2],
    };

    fft.forward_as_torus(fourier_lhs.as_mut_view(), lhs.as_view(), stack.rb_mut());
    fft.forward_as_integer(fourier_rhs.as_mut_view(), rhs.as_view(), stack.rb_mut());

    for (a, b) in fourier_lhs.data.iter_mut().zip(fourier_rhs.data.iter()) {
        *a *= *b;
    }

    fft.backward_as_torus(output.as_mut_view(), fourier_lhs.as_view(), stack.rb_mut());
}

// FFT initialization
pub(crate) fn init_fft(polynomial_size: PolynomialSize) -> (Fft, GlobalPodBuffer) {
    let fft = Fft::new(polynomial_size);
    let fft_view = fft.as_view();

    let mem = GlobalPodBuffer::new(
        fft_view
            .forward_scratch()
            .unwrap()
            .and(fft_view.backward_scratch().unwrap()),
    );

    (fft, mem)
}

// Context
pub struct Context {
    parameters: ClassicPBSParameters,
    big_lwe_dimension: LweDimension,
    delta: u64,
    full_message_modulus: usize,
    pub signed_decomposer: SignedDecomposer<u64>,
    pub encryption_generator: EncryptionRandomGenerator<ActivatedRandomGenerator>,
    secret_generator: SecretRandomGenerator<ActivatedRandomGenerator>,
    box_size: usize,
    ciphertext_modulus: CiphertextModulus,
}

impl Context {
    pub fn from(parameters: ClassicPBSParameters) -> Context {
        let big_lwe_dimension =
            LweDimension(parameters.polynomial_size.0 * parameters.glwe_dimension.0);
        let full_message_modulus = parameters.message_modulus.0 * parameters.carry_modulus.0;
        let delta = (1u64 << 63) / (full_message_modulus) as u64;

        //FIXME : voir a quoi correspond le +1
        let signed_decomposer = SignedDecomposer::new(
            DecompositionBaseLog(full_message_modulus.ilog2() as usize + 1),
            DecompositionLevelCount(1),
        ); // a changer peut-être pour les autres params

        // Request the best seeder possible, starting with hardware entropy sources and falling back to
        // /dev/random on Unix systems if enabled via cargo features
        let mut boxed_seeder = new_seeder();
        // Get a mutable reference to the seeder as a trait object from the Box returned by new_seeder
        let seeder = boxed_seeder.as_mut();

        // Create a generator which uses a CSPRNG to generate secret keys
        let secret_generator =
            SecretRandomGenerator::<ActivatedRandomGenerator>::new(seeder.seed());

        // Create a generator which uses two CSPRNGs to generate public masks and secret encryption
        // noise
        let encryption_generator =
            EncryptionRandomGenerator::<ActivatedRandomGenerator>::new(seeder.seed(), seeder);

        let box_size = parameters.polynomial_size.0 / full_message_modulus as usize;
        let ciphertext_modulus = CiphertextModulus::new_native();

        Context {
            parameters,
            big_lwe_dimension,
            delta,
            full_message_modulus,
            signed_decomposer,
            secret_generator,
            encryption_generator,
            box_size,
            ciphertext_modulus,
        }
    }

    // getters for each (private) parameters
    pub fn small_lwe_dimension(&self) -> LweDimension {
        self.parameters.lwe_dimension
    }
    pub fn big_lwe_dimension(&self) -> LweDimension {
        self.big_lwe_dimension
    }
    pub fn glwe_dimension(&self) -> GlweDimension {
        self.parameters.glwe_dimension
    }
    pub fn polynomial_size(&self) -> PolynomialSize {
        self.parameters.polynomial_size
    }
    pub fn lwe_modular_std_dev(&self) -> StandardDev {
        self.parameters.lwe_noise_distribution.gaussian_std_dev()
    }
    pub fn glwe_modular_std_dev(&self) -> StandardDev {
        self.parameters.glwe_noise_distribution.gaussian_std_dev()
    }
    pub fn pbs_base_log(&self) -> DecompositionBaseLog {
        self.parameters.pbs_base_log
    }
    pub fn pbs_level(&self) -> DecompositionLevelCount {
        self.parameters.pbs_level
    }
    pub fn ks_level(&self) -> DecompositionLevelCount {
        self.parameters.ks_level
    }
    pub fn ks_base_log(&self) -> DecompositionBaseLog {
        self.parameters.ks_base_log
    }
    pub fn pfks_level(&self) -> DecompositionLevelCount {
        self.parameters.pbs_level
    }
    pub fn pfks_base_log(&self) -> DecompositionBaseLog {
        self.parameters.pbs_base_log
    }
    pub fn pfks_modular_std_dev(&self) -> StandardDev {
        self.parameters.glwe_noise_distribution.gaussian_std_dev()
    }
    pub fn message_modulus(&self) -> MessageModulus {
        self.parameters.message_modulus
    }
    pub fn carry_modulus(&self) -> CarryModulus {
        self.parameters.carry_modulus
    }
    pub fn delta(&self) -> u64 {
        self.delta
    }
    pub fn full_message_modulus(&self) -> usize {
        self.full_message_modulus
    }
    pub fn box_size(&self) -> usize {
        self.box_size
    }
    pub fn ciphertext_modulus(&self) -> CiphertextModulus {
        self.ciphertext_modulus
    }
    pub fn cbs_level(&self) -> DecompositionLevelCount {
        self.parameters.ks_level
    }
    pub fn cbs_base_log(&self) -> DecompositionBaseLog {
        self.parameters.ks_base_log
    }
    pub fn parameters(&self) -> ClassicPBSParameters {
        self.parameters
    }
    // pub fn signed_decomposer(&self) -> SignedDecomposer<u64> {self.signed_decomposer}
}

#[derive(Serialize, Deserialize, Clone)]
pub struct PrivateKey {
    pub small_lwe_sk: LweSecretKey<Vec<u64>>,
    // big_lwe_sk: LweSecretKey<Vec<u64>>,
    pub glwe_sk: GlweSecretKey<Vec<u64>>,
    pub public_key: PublicKey,
}

impl PrivateKey {
    /// Generate a PrivateKey which contain also the PublicKey
    pub fn new(ctx: &mut Context) -> PrivateKey {
        let n = ctx.full_message_modulus();
        println!(
            "----- Generating keys for message in param {} ({} bits) ----- \n",
            n.ilog2(),
            n
        );
        // Generate an LweSecretKey with binary coefficients
        print!("generating small lwe key: ",);
        let _ = io::stdout().flush();
        let start = Instant::now();
        let lwe_sk =
            LweSecretKey::generate_new_binary(ctx.small_lwe_dimension(), &mut ctx.secret_generator);
        println!("{:?}", Instant::now() - start);

        // Generate a GlweSecretKey with binary coefficients
        print!("generating glwe key: ");
        let _ = io::stdout().flush();
        let start = Instant::now();
        let glwe_sk = GlweSecretKey::generate_new_binary(
            ctx.glwe_dimension(),
            ctx.polynomial_size(),
            &mut ctx.secret_generator,
        );
        println!("{:?}", Instant::now() - start);

        // Create a copy of the GlweSecretKey re-interpreted as an LweSecretKey
        // let big_lwe_sk = glwe_sk.clone().into_lwe_secret_key();

        // Generate the bootstrapping key, we use the parallel variant for performance reason
        print!("generating std bootstrapping key: ");
        let _ = io::stdout().flush();
        let start = Instant::now();
        let std_bootstrapping_key = par_allocate_and_generate_new_lwe_bootstrap_key(
            &lwe_sk,
            &glwe_sk,
            ctx.pbs_base_log(),
            ctx.pbs_level(),
            ctx.parameters.glwe_noise_distribution,
            ctx.ciphertext_modulus(),
            &mut ctx.encryption_generator,
        );
        println!("{:?}", Instant::now() - start);

        // Create the empty bootstrapping key in the Fourier domain
        print!("convert std bootstrapping key to fourrier bootstrapping key: ");
        let _ = io::stdout().flush();
        let start = Instant::now();
        let mut fourier_bsk = FourierLweBootstrapKey::new(
            std_bootstrapping_key.input_lwe_dimension(),
            std_bootstrapping_key.glwe_size(),
            std_bootstrapping_key.polynomial_size(),
            std_bootstrapping_key.decomposition_base_log(),
            std_bootstrapping_key.decomposition_level_count(),
        );

        // Use the conversion function (a memory optimized version also exists but is more complicated
        // to use) to convert the standard bootstrapping key to the Fourier domain
        convert_standard_lwe_bootstrap_key_to_fourier(&std_bootstrapping_key, &mut fourier_bsk);
        println!("{:?}", Instant::now() - start);
        // We don't need the standard bootstrapping key anymore
        print!("dropping std bootstrapping key: ");
        let _ = io::stdout().flush();
        let start = Instant::now();
        drop(std_bootstrapping_key);
        println!("{:?}", Instant::now() - start);

        print!("generating lwe keyswitch key: ");
        let _ = io::stdout().flush();
        let start = Instant::now();
        let mut lwe_ksk = LweKeyswitchKey::new(
            0u64,
            ctx.ks_base_log(),
            ctx.ks_level(),
            ctx.big_lwe_dimension(),
            ctx.small_lwe_dimension(),
            ctx.ciphertext_modulus(),
        );

        generate_lwe_keyswitch_key(
            &glwe_sk.as_lwe_secret_key(),
            &lwe_sk,
            &mut lwe_ksk,
            ctx.parameters.lwe_noise_distribution,
            &mut ctx.encryption_generator,
        );
        println!("{:?}", Instant::now() - start);

        // Create Packing Key Switch
        //
        // Private Functional Packing Key Switch Key
        print!("generating lwe private functional packing keyswitch key: ");
        let _ = io::stdout().flush();
        // let start = Instant::now();
        let mut pfpksk = LwePrivateFunctionalPackingKeyswitchKey::new(
            0,
            ctx.pfks_base_log(),
            ctx.pfks_level(),
            ctx.big_lwe_dimension(),
            ctx.glwe_dimension().to_glwe_size(),
            ctx.polynomial_size(),
            ctx.ciphertext_modulus(),
        );


        print!("generating lwe private functional packing keyswitch key list: ");
        let _ = io::stdout().flush();
        let cbs_pfpksk = par_allocate_and_generate_new_circuit_bootstrap_lwe_pfpksk_list(
            &glwe_sk.as_lwe_secret_key(),
            &glwe_sk,
            ctx.pfks_base_log(),
            ctx.pfks_level(),
            ctx.parameters.glwe_noise_distribution,
            ctx.ciphertext_modulus(),
            &mut ctx.encryption_generator,
        );

        // // Here there is some freedom for the choice of the last polynomial from algorithm 2
        // // By convention from the paper the polynomial we use here is the constant -1
        // let mut last_polynomial = Polynomial::new(0, ctx.polynomial_size());
        // // Set the constant term to u64::MAX == -1i64
        // // last_polynomial[0] = u64::MAX;
        // last_polynomial[0] = 1_u64;
        // // Generate the LWE private functional packing keyswitch key
        // par_generate_lwe_private_functional_packing_keyswitch_key(
        //     &glwe_sk.as_lwe_secret_key(),
        //     &glwe_sk,
        //     &mut pfpksk,
        //     ctx.parameters.glwe_noise_distribution,
        //     &mut ctx.encryption_generator,
        //     |x| x,
        //     &last_polynomial,
        // );
        // println!("{:?}", Instant::now() - start);

        // Public Packing Key Switch
        print!("generating lwe packing keyswitch key: ");
        let _ = io::stdout().flush();
        let start = Instant::now();
        let packing_ksk = allocate_and_generate_new_lwe_packing_keyswitch_key(
            &glwe_sk.as_lwe_secret_key(),
            &glwe_sk,
            ctx.pbs_base_log(),
            ctx.pbs_level(),
            ctx.parameters.glwe_noise_distribution,
            ctx.ciphertext_modulus(),
            &mut ctx.encryption_generator,
        );
        println!("{:?}", Instant::now() - start);

        println!("----- Keys generated -----");
        //
        let public_key = PublicKey {
            lwe_ksk,
            fourier_bsk,
            pfpksk,
            packing_ksk,
            cbs_pfpksk,
            // mb_pbs_key: multi_bit_bsk,
        };

        PrivateKey {
            small_lwe_sk: lwe_sk,
            glwe_sk,
            public_key,
        }
    }

    /// Generate a new private key and save it to file PrivateKeyN
    pub fn to_file(ctx: &mut Context) -> PrivateKey {
        let key = Self::new(ctx);
        let n = ctx.full_message_modulus().ilog2();
        let _ = fs::write(
            format!("PrivateKey{}", n),
            bincode::serialize(&key).unwrap(),
        );
        key
    }

    /// Load a private key from a file instead of generating it
    pub fn from_file(path: &str) -> Option<PrivateKey> {
        fs::read(path)
            .ok()
            .and_then(|buf| bincode::deserialize(&buf).ok())
    }

    // getters for each attribute
    pub fn get_small_lwe_sk(&self) -> &LweSecretKey<Vec<u64>> {
        &self.small_lwe_sk
    }

    pub fn get_big_lwe_sk(&self) -> LweSecretKey<&[u64]> {
        self.glwe_sk.as_lwe_secret_key()
    }
    pub fn get_glwe_sk(&self) -> &GlweSecretKey<Vec<u64>> {
        &self.glwe_sk
    }
    pub fn get_public_key(&self) -> &PublicKey {
        &self.public_key
    }

    pub fn allocate_and_encrypt_lwe(&self, input: u64, ctx: &mut Context) -> LWE {
        let plaintext = Plaintext(ctx.delta().wrapping_mul(input));

        // Allocate a new LweCiphertext and encrypt our plaintext
        let lwe_ciphertext: LweCiphertextOwned<u64> = allocate_and_encrypt_new_lwe_ciphertext(
            &self.get_big_lwe_sk(),
            plaintext,
            ctx.parameters.lwe_noise_distribution,
            ctx.ciphertext_modulus(),
            &mut ctx.encryption_generator,
        );
        lwe_ciphertext
    }

    pub fn lwe_encrypt_with_modulus(&self, x: u64, modulus: u64, ctx: &mut Context) -> LWE {
        // we still consider the padding bit
        let delta = (1u64 << 63) / modulus;
        let pt = Plaintext(x * delta);
        let lwe_ciphertext = allocate_and_encrypt_new_lwe_ciphertext(
            &self.get_big_lwe_sk(),
            pt,
            ctx.parameters.lwe_noise_distribution,
            ctx.ciphertext_modulus(),
            &mut ctx.encryption_generator,
        );
        lwe_ciphertext
    }

    pub fn allocate_and_encrypt_lwe_big_key(&self, input: u64, ctx: &mut Context) -> LWE {
        let plaintext = Plaintext(ctx.delta().wrapping_mul(input));

        // Allocate a new LweCiphertext and encrypt our plaintext
        let lwe_ciphertext: LweCiphertextOwned<u64> = allocate_and_encrypt_new_lwe_ciphertext(
            &self.glwe_sk.as_lwe_secret_key(),
            plaintext,
            ctx.parameters.lwe_noise_distribution,
            ctx.ciphertext_modulus(),
            &mut ctx.encryption_generator,
        );
        lwe_ciphertext
    }

    pub fn allocate_and_trivially_encrypt_lwe(&self, input: u64, ctx: &Context) -> LWE {
        let plaintext = Plaintext(ctx.delta().wrapping_mul(input));
        // Allocate a new LweCiphertext and encrypt trivially our plaintext
        let lwe_ciphertext: LweCiphertextOwned<u64> =
            allocate_and_trivially_encrypt_new_lwe_ciphertext(
                ctx.big_lwe_dimension().to_lwe_size(),
                plaintext,
                ctx.ciphertext_modulus(),
            );
        lwe_ciphertext
    }

    fn decode(params: ClassicPBSParameters, x: u64) -> u64 {
        let delta = (1u64 << 63) / (params.message_modulus.0 * params.carry_modulus.0) as u64;

        //The bit before the message
        let rounding_bit = delta >> 1;

        //compute the rounding bit
        let rounding = (x & rounding_bit) << 1;

        // add the rounding bit and divide by delta
        x.wrapping_add(rounding) / delta
    }

    pub fn decrypt_without_decoding(&self, ciphertext: &LWE) -> Plaintext<u64> {
        decrypt_lwe_ciphertext(&self.get_big_lwe_sk(), &ciphertext)
    }

    pub fn decrypt_lwe(&self, ciphertext: &LWE, ctx: &Context) -> u64 {
        // Decrypt the PBS multiplication result
        let plaintext: Plaintext<u64> = decrypt_lwe_ciphertext(&self.get_big_lwe_sk(), &ciphertext);
        let result = ctx.signed_decomposer.closest_representable(plaintext.0) / ctx.delta();
        result % ctx.full_message_modulus() as u64
    }

    pub fn decrypt_lwe_without_reduction(&self, ciphertext: &LWE, ctx: &Context) -> u64 {
        // Decrypt the PBS multiplication result
        let plaintext: Plaintext<u64> = decrypt_lwe_ciphertext(&self.get_big_lwe_sk(), &ciphertext);
        // let result: u64 = ctx.signed_decomposer.closest_representable(plaintext.0) / ctx.delta();
        let decoded = Self::decode(ctx.parameters, plaintext.0);
        decoded
    }

    pub fn decrypt_lwe_delta(&self, ciphertext: &LWE, delta: u64, ctx: &Context) -> u64 {
        // Decrypt the PBS multiplication result
        let plaintext: Plaintext<u64> = decrypt_lwe_ciphertext(&self.get_big_lwe_sk(), &ciphertext);
        let result: u64 = ctx.signed_decomposer.closest_representable(plaintext.0) / delta
            % ctx.full_message_modulus() as u64;
        result
    }

    pub fn decrypt_lwe_vector(&self, ciphertext: &Vec<LWE>, ctx: &Context) -> Vec<u64> {
        ciphertext
            .iter()
            .map(|ct| self.decrypt_lwe(ct, ctx))
            .collect()
    }

    pub fn decrypt_lwe_vector_without_mod(&self, ciphertext: &Vec<LWE>, ctx: &Context) -> Vec<u64> {
        ciphertext
            .iter()
            .map(|ct| self.decrypt_lwe_without_reduction(ct, ctx))
            .collect()
    }

    pub fn decrypt_lwe_small_key(&self, ciphertext: &LWE, ctx: &Context) -> u64 {
        // Decrypt the PBS multiplication result
        let plaintext: Plaintext<u64> = decrypt_lwe_ciphertext(&self.small_lwe_sk, &ciphertext);
        let result: u64 = ctx.signed_decomposer.closest_representable(plaintext.0) / ctx.delta()
            % ctx.full_message_modulus() as u64;
        result
    }

    pub fn allocate_and_encrypt_glwe(
        &self,
        pt_list: PlaintextList<Vec<u64>>,
        ctx: &mut Context,
    ) -> GLWE {
        let mut output_glwe = GlweCiphertext::new(
            0,
            ctx.glwe_dimension().to_glwe_size(),
            ctx.polynomial_size(),
            ctx.ciphertext_modulus(),
        );
        encrypt_glwe_ciphertext(
            self.get_glwe_sk(),
            &mut output_glwe,
            &pt_list,
            ctx.parameters.glwe_noise_distribution,
            &mut ctx.encryption_generator,
        );
        output_glwe
    }

    pub fn allocate_and_trivially_encrypt_glwe(
        &self,
        pt_list: PlaintextList<Vec<u64>>,
        ctx: &mut Context,
    ) -> GLWE {
        let mut output_glwe = GlweCiphertext::new(
            0,
            ctx.glwe_dimension().to_glwe_size(),
            ctx.polynomial_size(),
            ctx.ciphertext_modulus(),
        );
        trivially_encrypt_glwe_ciphertext(&mut output_glwe, &pt_list);
        output_glwe
    }

    pub fn encrypt_glwe(
        &self,
        output_glwe: &mut GLWE,
        pt: PlaintextList<Vec<u64>>,
        ctx: &mut Context,
    ) {
        encrypt_glwe_ciphertext(
            self.get_glwe_sk(),
            output_glwe,
            &pt,
            ctx.parameters.glwe_noise_distribution,
            &mut ctx.encryption_generator,
        );
    }

    pub fn allocate_and_encrypt_glwe_from_vec(&self, vec: &Vec<u64>, ctx: &mut Context) -> GLWE {
        let encoded_vec = self.encode_plaintext_list_from_vec(vec, ctx);
        let output_glwe = self.allocate_and_encrypt_glwe(encoded_vec, ctx);
        output_glwe
    }

    pub fn encode_plaintext_list_from_vec(
        &self,
        vec: &Vec<u64>,
        ctx: &Context,
    ) -> PlaintextList<Vec<u64>> {
        let mut encoded_vec: Vec<u64> = vec.iter().map(|x| x * ctx.delta()).collect();
        if encoded_vec.len() < ctx.polynomial_size().0 {
            encoded_vec.resize(ctx.polynomial_size().0, 0_u64);
        }
        PlaintextList::from_container(encoded_vec)
    }

    pub fn allocate_and_encrypt_glwe_with_modulus(
        &self,
        vec: &Vec<u64>,
        modulus: u64,
        ctx: &mut Context,
    ) -> GLWE {
        let delta = (1 << 63) / modulus;
        let mut encoded_vec: Vec<u64> = vec.iter().map(|x| x * delta).collect();
        if encoded_vec.len() < ctx.polynomial_size().0 {
            encoded_vec.resize(ctx.polynomial_size().0, 0_u64);
        }
        let pt = PlaintextList::from_container(encoded_vec);
        let output_glwe = self.allocate_and_encrypt_glwe(pt, ctx);
        output_glwe
    }

    pub fn decrypt_and_decode_glwe_as_neg(&self, input_glwe: &GLWE, ctx: &Context) -> Vec<u64> {
        let mut plaintext_res = PlaintextList::new(0, PlaintextCount(ctx.polynomial_size().0));
        decrypt_glwe_ciphertext(&self.get_glwe_sk(), &input_glwe, &mut plaintext_res);

        // To round our 4 bits of message
        // In the paper we return the complicated sum times -1, so here we invert that -1, otherwise we
        // could apply the wrapping_neg on our function and remove it here
        let decoded: Vec<_> = plaintext_res
            .iter()
            .map(|x| {
                (ctx.signed_decomposer.closest_representable(*x.0) / ctx.delta()).wrapping_neg()
                    % ctx.full_message_modulus() as u64
            })
            .collect();

        decoded
    }

    pub fn decrypt_and_decode_glwe(&self, input_glwe: &GLWE, ctx: &Context) -> Vec<u64> {
        let mut plaintext_res = PlaintextList::new(0, PlaintextCount(ctx.polynomial_size().0));
        decrypt_glwe_ciphertext(&self.get_glwe_sk(), &input_glwe, &mut plaintext_res);

        // To round our 4 bits of message
        // In the paper we return the complicated sum times -1, so here we invert that -1, otherwise we
        // could apply the wrapping_neg on our function and remove it here
        let decoded: Vec<_> = plaintext_res
            .iter()
            .map(|x| {
                (ctx.signed_decomposer.closest_representable(*x.0) / ctx.delta())
                    % ctx.full_message_modulus() as u64
            })
            .collect();

        decoded
    }

    pub fn decrypt_ggsw(
        &self,
        input_ggsw: &GgswCiphertext<Vec<u64>>,
        private_key: &PrivateKey,
    ) -> u64 {
        let plain = decrypt_constant_ggsw_ciphertext(&private_key.get_glwe_sk(), &input_ggsw);
        plain.0
    }

    pub fn debug_small_lwe(&self, string: &str, ciphertext: &LWE, ctx: &Context) {
        // Decrypt the PBS multiplication result
        let plaintext: Plaintext<u64> =
            decrypt_lwe_ciphertext(&self.get_small_lwe_sk(), &ciphertext);
        let result: u64 = ctx.signed_decomposer.closest_representable(plaintext.0) / ctx.delta();
        println!("{} {}", string, result);
    }

    pub fn debug_lwe_delta(&self, string: &str, ciphertext: &LWE, delta: u64, ctx: &Context) {
        // Decrypt the PBS multiplication result
        let plaintext: Plaintext<u64> = decrypt_lwe_ciphertext(&self.get_big_lwe_sk(), &ciphertext);
        let result: u64 = ctx.signed_decomposer.closest_representable(plaintext.0) / delta;
        println!("{} {}", string, result);
    }

    pub fn debug_lwe(&self, string: &str, ciphertext: &LWE, ctx: &Context) {
        // Decrypt the PBS multiplication result
        let plaintext: Plaintext<u64> = decrypt_lwe_ciphertext(&self.get_big_lwe_sk(), &ciphertext);
        let result: u64 = ctx.signed_decomposer.closest_representable(plaintext.0) / ctx.delta();
        println!("{} {}", string, result);
    }

    pub fn debug_glwe(&self, string: &str, input_glwe: &GLWE, ctx: &Context) {
        let mut plaintext_res = PlaintextList::new(0, PlaintextCount(ctx.polynomial_size().0));
        decrypt_glwe_ciphertext(&self.get_glwe_sk(), &input_glwe, &mut plaintext_res);

        // To round our bits of message
        let decoded: Vec<_> = plaintext_res
            .iter()
            .map(|x| {
                (ctx.signed_decomposer.closest_representable(*x.0) / ctx.delta())
                    % ctx.full_message_modulus() as u64
            })
            .collect();

        println!("{} {:?}", string, decoded);
    }

    pub fn debug_glwe_without_reduction(
        &self,
        string: &str,
        input_glwe: &GLWE,
        ctx: &Context,
        index: usize,
    ) {
        let mut plaintext_res = PlaintextList::new(0, PlaintextCount(ctx.polynomial_size().0));
        decrypt_glwe_ciphertext(&self.get_glwe_sk(), &input_glwe, &mut plaintext_res);

        // To round our bits of message
        let decoded: Vec<_> = plaintext_res
            .iter()
            .map(|x| (ctx.signed_decomposer.closest_representable(*x.0) / ctx.delta()))
            .collect();

        println!("{} {:?}", string, decoded[index]);
    }

    pub fn lwe_noise(&self, ct: &LWE, expected_plaintext: u64, ctx: &Context) -> f64 {
        // plaintext = b - a*s = Delta*m + e
        let mut plaintext = decrypt_lwe_ciphertext(&self.get_big_lwe_sk(), &ct);

        // plaintext = plaintext - Delta*m = e
        plaintext.0 = plaintext.0.wrapping_sub(ctx.delta() * expected_plaintext);

        ((plaintext.0 as i64).abs() as f64).log2()
    }

    pub fn lwe_noise_small_sk(&self, ct: &LWE, expected_plaintext: u64, ctx: &Context) -> f64 {
        // plaintext = b - a*s = Delta*m + e
        let mut plaintext = decrypt_lwe_ciphertext(&self.get_small_lwe_sk(), &ct);
        // plaintext = plaintext - Delta*m = e
        plaintext.0 = plaintext.0.wrapping_sub(ctx.delta() * expected_plaintext);

        ((plaintext.0 as i64).abs() as f64).log2()
    }

    pub fn lwe_noise_delta(&self, ct: &LWE, expected_pt: u64, delta: u64) -> f64 {
        // pt = b - a*s = Delta*m + e
        let mut pt = decrypt_lwe_ciphertext(&self.get_big_lwe_sk(), &ct);
        // pt = pt - Delta*m = e (encoded_ptxt is Delta*m)
        pt.0 = pt.0.wrapping_sub(delta * expected_pt);

        ((pt.0 as i64).abs() as f64).log2()
    }

    pub fn glwe_noise(&self, glwe: &GLWE, expected_pt: &Vec<u64>, ctx: &Context) -> Vec<f64> {
        // Plaintext_list = B(X) - A(X)*S(X) + E(X)
        let mut plaintext_res = PlaintextList::new(0, PlaintextCount(ctx.polynomial_size().0));
        decrypt_glwe_ciphertext(&self.get_glwe_sk(), &glwe, &mut plaintext_res);

        // E = Plaintext_list - Delta*expected_pt
        let e: Vec<_> = plaintext_res
            .iter()
            .zip(expected_pt.iter())
            .map(|(x, &expected)| x.0.wrapping_sub(ctx.delta() * expected))
            .collect();

        // log2(abs(ei))
        e.iter()
            .map(|x| ((*x as i64).abs() as f64).log2())
            .collect::<Vec<f64>>()
    }

    pub fn encrypt_matrix(&self, mut ctx: &mut Context, matrix: &Vec<Vec<u64>>) -> Vec<LUT> {
        let mut ct_matrix: Vec<LUT> = Vec::new();
        for line in matrix {
            let ct_line = LUT::from_vec(line, self, &mut ctx);
            ct_matrix.push(ct_line);
        }
        return ct_matrix;
    }

    pub fn encrypt_matrix_with_padding(
        &self,
        mut ctx: &mut Context,
        matrix: &Vec<Vec<u64>>,
    ) -> Vec<LUT> {
        let mut ct_matrix: Vec<LUT> = Vec::new();

        for line in matrix {
            let ct_line = LUT::from_vec(line, self, &mut ctx);
            ct_matrix.push(ct_line);
        }
        for _i in ct_matrix.len()..ctx.message_modulus().0 {
            let ct_padding = LUT::from_vec(&vec![0u64], self, &mut ctx);
            ct_matrix.push(ct_padding);
        }
        return ct_matrix;
    }

    pub fn decrypt_and_print_matrix(&self, ctx: &Context, ct_matrix: &Vec<LUT>) {
        let mut result = Vec::new();
        for i in ct_matrix {
            let res = (*i).print(&self, &ctx);
            result.push(res);
        }
        println!("{:?}", result);
    }
}

#[derive(Serialize, Deserialize, Clone)]
pub struct PublicKey {
    // utilKey ou ServerKey ou CloudKey
    pub lwe_ksk: LweKeyswitchKey<Vec<u64>>,
    pub fourier_bsk: FourierLweBootstrapKey<ABox<[Complex<f64>]>>,
    pub pfpksk: LwePrivateFunctionalPackingKeyswitchKey<Vec<u64>>,
    pub packing_ksk: LwePackingKeyswitchKey<Vec<u64>>,
    pub cbs_pfpksk: LwePrivateFunctionalPackingKeyswitchKeyList<Vec<u64>>,

    // pub mb_pbs_key: FourierLweMultiBitBootstrapKeyOwned,
}

impl PublicKey {
    pub fn lwe_half(&self, lwe: &LWE, ctx: &Context) -> LWE {
        let mut result_lwe = LweCiphertext::new(
            0_u64,
            ctx.big_lwe_dimension().to_lwe_size(),
            ctx.ciphertext_modulus(),
        );
        result_lwe
            .as_mut()
            .iter_mut()
            .zip(lwe.as_ref().iter())
            .for_each(|(dst, &lhs)| *dst = lhs >> 1);
        return result_lwe;
    }

    pub fn wrapping_neg_lwe(&self, lwe: &mut LWE) {
        for ai in lwe.as_mut() {
            *ai = (*ai).wrapping_neg();
        }
    }

    pub fn neg_lwe(&self, lwe: &LWE, ctx: &Context) -> LWE {
        let mut neg_lwe = LweCiphertext::new(
            0_u64,
            ctx.big_lwe_dimension().to_lwe_size(),
            ctx.ciphertext_modulus(),
        );
        neg_lwe
            .as_mut()
            .iter_mut()
            .zip(lwe.as_ref().iter())
            .for_each(|(dst, &lhs)| *dst = lhs.wrapping_neg());
        return neg_lwe;
    }

    pub fn not_lwe(&self, lwe: &LWE, ctx: &Context) -> LWE {
        let mut not_lwe = self.allocate_and_trivially_encrypt_lwe(1, ctx);
        lwe_ciphertext_sub_assign(&mut not_lwe, &lwe);
        not_lwe
    }

    // res = LWE1 + scalar * LWE2
    pub fn lwe_mul_add(&self, lwe1: &LWE, lwe2: &LWE, scalar: u64) -> LWE {
        let mut res = lwe2.clone();
        lwe_ciphertext_cleartext_mul_assign(&mut res, Cleartext(scalar)); // res = scalar * lwe2
        lwe_ciphertext_add_assign(&mut res, lwe1);
        res
    }

    // LWE = LWE + scalar * LWE
    pub fn lwe_mul_add_assign(&self, lwe: &mut LWE, scalar: u64) {
        let mut res = lwe.clone();
        lwe_ciphertext_cleartext_mul_assign(&mut res, Cleartext(scalar)); // res = scalar * lwe
        lwe_ciphertext_add_assign(lwe, &res);
    }

    /// Reduce the plaintext modulus in `ct` from `big_modulus` to `message_modulus`.
    pub fn lower_precision(&self, ct: &mut LWE, ctx: &Context, big_modulus: u64) {
        let small_delta = (1u64 << 63) / big_modulus;

        let small_modulus = ctx.message_modulus().0 as u64;
        let precision_ratio = (1u64 << 63) / (small_delta * small_modulus);
        assert!(precision_ratio > 1);

        let shift = Plaintext(((small_delta * (precision_ratio - 1)) / 2).wrapping_neg());
        lwe_ciphertext_plaintext_add_assign(ct, shift);

        // Bootstrap
        self.bootstrap_lwe(ct, ctx);
    }

    pub fn allocate_and_trivially_encrypt_lwe(&self, input: u64, ctx: &Context) -> LWE {
        let plaintext = Plaintext(ctx.delta().wrapping_mul(input));
        // Allocate a new LweCiphertext and encrypt trivially our plaintext
        let lwe_ciphertext: LweCiphertextOwned<u64> =
            allocate_and_trivially_encrypt_new_lwe_ciphertext(
                ctx.big_lwe_dimension().to_lwe_size(),
                plaintext,
                ctx.ciphertext_modulus(),
            );
        lwe_ciphertext
    }

    pub fn allocate_and_trivially_encrypt_glwe(
        &self,
        pt_list: PlaintextList<Vec<u64>>,
        ctx: &Context,
    ) -> GLWE {
        let mut output_glwe = GlweCiphertext::new(
            0,
            ctx.glwe_dimension().to_glwe_size(),
            ctx.polynomial_size(),
            ctx.ciphertext_modulus(),
        );
        trivially_encrypt_glwe_ciphertext(&mut output_glwe, &pt_list);
        output_glwe
    }

    pub fn leq_scalar(&self, ct_input: &LWE, scalar: u64, ctx: &Context) -> LWE {
        let cmp_scalar_accumulator = LUT::from_function(|x| (x <= scalar as u64) as u64, ctx);
        self.blind_array_access(&ct_input, &cmp_scalar_accumulator, ctx)
    }

    pub fn lt_scalar(&self, ct_input: &LWE, scalar: u64, ctx: &Context) -> LWE {
        let cmp_scalar_accumulator = LUT::from_function(|x| (x < scalar as u64) as u64, ctx);
        self.blind_array_access(&ct_input, &cmp_scalar_accumulator, ctx)
    }

    pub fn geq_scalar(&self, ct_input: &LWE, scalar: u64, ctx: &Context) -> LWE {
        let cmp_scalar_accumulator = LUT::from_function(|x| (x >= scalar) as u64, ctx);
        self.blind_array_access(&ct_input, &cmp_scalar_accumulator, ctx)
    }

    pub fn gt_scalar(&self, ct_input: &LWE, scalar: u64, ctx: &Context) -> LWE {
        let cmp_scalar_accumulator = LUT::from_function(|x| (x > scalar as u64) as u64, ctx);
        self.blind_array_access(&ct_input, &cmp_scalar_accumulator, ctx)
    }

    pub fn eq_scalar(&self, ct_input: &LWE, scalar: u64, ctx: &Context) -> LWE {
        let eq_scalar_accumulator = LUT::from_function(|x| (x == scalar as u64) as u64, ctx);
        self.blind_array_access(&ct_input, &eq_scalar_accumulator, ctx)
    }

    // Simulate a multiplication of an LWE by an encrypted bit using a LUT
    pub fn lwe_mul_encrypted_bit(&self, lwe: &LWE, bit: &LWE, ctx: &Context) -> LWE {
        let lwe_cp = lwe.clone();
        let zero = self.allocate_and_trivially_encrypt_lwe(0, ctx);
        self.cmux(zero, lwe_cp, bit, ctx)
    }

    // Simulate a multiplication of an LWE by another LWE using a LUT
    pub fn lwe_mul(&self, lwe1: &LWE, lwe2: &LWE, ctx: &Context) -> LWE {
        let mut many_lwe = Vec::new();
        for i in 0..ctx.full_message_modulus() - 1 {
            let mut i_lwe1 = lwe1.clone();
            lwe_ciphertext_cleartext_mul_assign(&mut i_lwe1, Cleartext(i as u64));
            many_lwe.push(i_lwe1);
        }
        let lut = LUT::from_vec_of_lwe(&many_lwe, self, ctx);
        self.blind_array_access(lwe2, &lut, ctx)
    }

    pub fn glwe_absorption_monic_monomial(&self, glwe: &mut GLWE, monomial_degree: MonomialDegree) {
        let mut glwe_poly_list = glwe.as_mut_polynomial_list();
        for mut glwe_poly in glwe_poly_list.iter_mut() {
            polynomial_wrapping_monic_monomial_mul_assign(&mut glwe_poly, monomial_degree);
        }
    }

    pub fn glwe_absorption_polynomial(&self, glwe: &GLWE, poly: &Poly) -> GLWE {
        let mut res = GlweCiphertext::new(
            0_u64,
            glwe.glwe_size(),
            glwe.polynomial_size(),
            glwe.ciphertext_modulus(),
        );

        res.as_mut_polynomial_list()
            .iter_mut()
            .zip(glwe.as_polynomial_list().iter())
            .for_each(|(mut dst, lhs)| polynomial_karatsuba_wrapping_mul(&mut dst, &lhs, poly));

        return res;
    }

    pub fn glwe_absorption_polynomial_with_fft(&self, glwe: &GLWE, poly: &Poly) -> GLWE {
        let mut res = GlweCiphertext::new(
            0_u64,
            glwe.glwe_size(),
            glwe.polynomial_size(),
            glwe.ciphertext_modulus(),
        );

        let n = glwe.polynomial_size();

        let (fft, mut mem) = init_fft(n);
        let mut stack = PodStack::new(&mut mem);

        res.as_mut_polynomial_list()
            .iter_mut()
            .zip(glwe.as_polynomial_list().iter())
            .for_each(|(mut dst, lhs)| {
                polynomial_fft_wrapping_mul(&mut dst, &lhs, poly, fft.as_view(), &mut stack);
            });

        return res;
    }

    pub fn glwe_sum(&self, ct1: &GLWE, ct2: &GLWE) -> GLWE {
        let mut res = GlweCiphertext::new(
            0_u64,
            ct1.glwe_size(),
            ct1.polynomial_size(),
            ct1.ciphertext_modulus(),
        );

        res.as_mut()
            .iter_mut()
            .zip(ct1.as_ref().iter().zip(ct2.as_ref().iter()))
            .for_each(|(dst, (&lhs, &rhs))| *dst = lhs.wrapping_add(rhs));
        return res;
    }

    pub fn glwe_sum_assign(&self, ct1: &mut GLWE, ct2: &GLWE) {
        ct1.as_mut()
            .iter_mut()
            .zip(ct2.as_ref().iter())
            .for_each(|(dst, &rhs)| *dst += rhs);
    }

    pub fn glwe_sum_polynomial(&self, glwe: &GLWE, poly: &Poly, ctx: &Context) -> GLWE {
        let mut res = glwe.clone();

        // Scale the polynomial by delta
        let plain = PlaintextList::from_container(
            poly.as_ref()
                .to_vec()
                .iter()
                .map(|x| x * ctx.delta())
                .collect::<Vec<u64>>(),
        );
        glwe_ciphertext_plaintext_list_add_assign(&mut res, &plain);

        return res;
    }

    /// Add a scalar to an LWE
    pub fn lwe_ciphertext_plaintext_add(
        &self,
        lwe: &LWE,
        constant: u64,
        ctx: &Context,
    ) -> LweCiphertextOwned<u64> {
        let mut output = lwe.clone();
        lwe_ciphertext_plaintext_add_assign(&mut output, Plaintext(constant * ctx.delta()));
        output
    }

    /// Multiply an LWE by a scalar
    pub fn lwe_ciphertext_plaintext_mul(&self, lwe: &LWE, constant: u64) -> LWE {
        let mut output = lwe.clone();
        lwe_ciphertext_cleartext_mul_assign(&mut output, Cleartext(constant));
        output
    }

    /// Multiply a GLWE by a scalar
    pub fn glwe_ciphertext_plaintext_mul(&self, glwe: &GLWE, constant: u64) -> GLWE {
        let mut output = glwe.clone();
        glwe_ciphertext_cleartext_mul_assign(&mut output, Cleartext(constant));
        output
    }

    pub fn serialize_lwe_vector_to_file(&self, lwe_vector: &Vec<LWE>, file_path: &str) {
        let json = serde_json::to_string(lwe_vector).expect("Failed to serialize LWE vector");
        let mut file = fs::File::create(file_path).expect("Failed to create file");
        file.write_all(json.as_bytes())
            .expect("Failed to write to file");
    }

    pub fn deserialize_lwe_vector_from_file(&self, file_path: &str) -> Vec<LWE> {
        let mut file = fs::File::open(file_path).expect("Failed to open file");
        let mut json = String::new();
        file.read_to_string(&mut json).expect("Failed to read file");
        serde_json::from_str(&json).expect("Failed to deserialize LWE vector")
    }

    // revoLUT operations
    /// Proxy blind rotation. Switches the input LWE ciphertext from big to small key before BR
    pub fn blind_rotation(&self, big_lwe: &LWE, lut: &LUT, ctx: &Context) -> LUT {
        let mut output = lut.clone();
        self.blind_rotation_assign(big_lwe, &mut output, ctx);
        output
    }

    /// Assign variant of `blind_rotation`
    pub fn blind_rotation_assign(&self, big_lwe: &LWE, lut: &mut LUT, ctx: &Context) {
        let small_lwe = self.allocate_and_keyswitch_lwe_ciphertext(big_lwe, ctx);
        blind_rotate_assign(&small_lwe, &mut lut.0, &self.fourier_bsk);
    }

    /// Get an element of an `array` given its `index`
    /// it can also be used to perform a programable bootstrap
    pub fn blind_array_access(&self, big_input: &LWE, array: &LUT, ctx: &Context) -> LWE {
        let mut big_output = self.allocate_and_trivially_encrypt_lwe(0, ctx);
        let small_input = self.allocate_and_keyswitch_lwe_ciphertext(&big_input, ctx);
        programmable_bootstrap_lwe_ciphertext(
            &small_input,
            &mut big_output,
            &array.0,
            &self.fourier_bsk,
        );
        big_output
    }

    /// Get an element of a `matrix` given it `index_line` and it `index_column`
    pub fn blind_matrix_access(
        &self,
        matrix: &[LUT],
        line: &LWE,
        column: &LWE,
        ctx: &Context,
    ) -> LWE {
        // multi blind array access
        let vec_of_lwe: Vec<LWE> = matrix
            .into_par_iter()
            .map(|lut| self.blind_array_access(column, lut, ctx))
            .collect();

        // pack all the lwe
        let accumulator_final = LUT::from_vec_of_lwe(&vec_of_lwe, self, &ctx);

        // final blind array access
        self.blind_array_access(&line, &accumulator_final, ctx)
    }

    /// PIR-like construction to access a matrix element blindly, returns Enc(matrix[x][y])
    /// time: 2BR + pKS
    pub fn blind_matrix_access_clear(
        &self,
        matrix: &Vec<Vec<u64>>,
        x: &LWE,
        y: &LWE,
        ctx: &Context,
    ) -> LWE {
        let p = ctx.full_message_modulus;
        let mut lut = LUT::from_vec_trivially(&vec![1], ctx);
        self.blind_rotation_assign(&self.neg_lwe(&y, &ctx), &mut lut, ctx);
        let onehot = lut.to_many_lwe(&self, ctx);
        let zero = self.allocate_and_trivially_encrypt_lwe(0, ctx);
        let column = Vec::from_iter(matrix.iter().map(|line| {
            let mut output = zero.clone();
            for (lwe, elt) in onehot.iter().zip(line.iter()) {
                let mut encrypted_bool = lwe.clone();
                lwe_ciphertext_cleartext_mul_assign(&mut encrypted_bool, Cleartext(*elt));
                lwe_ciphertext_add_assign(&mut output, &encrypted_bool);
            }
            output
        }));
        let lut = LUT::from_vec_of_lwe(&column, &self, ctx);
        self.blind_array_access(&x, &lut, ctx)
    }

    pub fn blind_matrix_add(
        &self,
        matrix: &mut [LUT],
        line: &LWE,
        column: &LWE,
        value: &LWE,
        ctx: &Context,
    ) {
        let mut column_lut = LUT::from_lwe(&self.neg_lwe(value, ctx), &self, ctx);
        let mut n = self.allocate_and_trivially_encrypt_lwe(ctx.full_message_modulus as u64, ctx);
        lwe_ciphertext_sub_assign(&mut n, line);
        self.blind_rotation_assign(&n, &mut column_lut, ctx);
        for (i, lut) in matrix.iter_mut().enumerate() {
            let x = self.lut_extract(&column_lut, i, ctx);
            self.blind_array_increment(lut, &column, &x, ctx);
        }
    }

    pub fn blind_matrix_set(
        &self,
        matrix: &mut [LUT],
        line: &LWE,
        column: &LWE,
        value: &LWE,
        ctx: &Context,
    ) {
        let current = self.blind_matrix_access(matrix, line, column, ctx);
        let mut value = value.clone();
        lwe_ciphertext_sub_assign(&mut value, &current);

        self.blind_matrix_add(matrix, line, column, &value, ctx);
    }

    // Prototype not working as expected
    pub fn blind_matrix_access_mv(
        &self,
        matrix: &Vec<Vec<u64>>,
        lwe_line: &LWE,
        lwe_column: &LWE,
        ctx: &Context,
    ) -> LWE {
        /* Creation des deux polynômes lhs et rhs tels que lhs*rhs = 2.
        - rhs sera trivially encrypted and blind rotated
        - lhs sera multiplié par les différentes LUT lignes de la matrice*/

        // Créer un polynôme représentant (1 - x) pour le côté gauche
        let mut lhs = Polynomial::new(0, ctx.polynomial_size());
        lhs[0] = 1u64;
        lhs[1] = u64::MAX;

        // Créer un polynôme représentant (1 + ... + x^N) pour le côté droit
        let vec_rhs = vec![1_u64 * ctx.delta(); ctx.polynomial_size().0];
        let pt_rhs = PlaintextList::from_container(vec_rhs);

        // Encoder le plaintext et l'encrypter trivialement
        let glwe_rhs = self.allocate_and_trivially_encrypt_glwe(pt_rhs, ctx);

        //#cashing the matrix

        // Encoder les lignes de la matrice comme des polynômes
        let mut matrix_in_poly_form: Vec<Poly> = Vec::new();
        for l in matrix.iter() {
            let vec_l_with_redundancy: Vec<u64> = LUT::add_redundancy_many_u64(l, ctx);
            matrix_in_poly_form.push(Polynomial::from_container(vec_l_with_redundancy));
        }

        // Step 1 : Multiplier chaque ligne de la matrice par le polynôme lhs

        // Init fft material
        let (fft, mut mem) = init_fft(ctx.polynomial_size());
        let mut stack = PodStack::new(&mut mem);

        let mut new_matrix: Vec<Poly> = Vec::new();
        for p in matrix_in_poly_form.iter() {
            let mut res_mul = Polynomial::new(0_u64, ctx.polynomial_size());
            polynomial_fft_wrapping_mul(&mut res_mul, &lhs, &p, fft.as_view(), &mut stack);
            new_matrix.push(res_mul);
        }

        // Step 2 : Préparer la LUT pour la rotation aveugle
        let mut only_lut_to_rotate = LUT(glwe_rhs);
        // let start_bma_mv = Instant::now();
        self.blind_rotation_assign(&lwe_column, &mut only_lut_to_rotate, ctx);

        // Step 3 : Appliquer l'absorption GLWE pour chaque ligne de la nouvelle matrice
        let mut columns_lwe: Vec<LWE> = Vec::new();
        for line in new_matrix.iter() {
            let lut =
                LUT(self.glwe_absorption_polynomial_with_fft(&mut only_lut_to_rotate.0, line));
            let ct = self.lut_extract(&lut, 0, ctx);
            columns_lwe.push(ct);
        }

        let lut_col = LUT::from_vec_of_lwe(&columns_lwe, self, ctx);

        // Effectuer une rotation aveugle sur la LUT colonne
        let result = self.blind_array_access(&lwe_line, &lut_col, ctx);

        // FIXME: half result may behave weirdly
        // result.as_mut().iter_mut().for_each(|x| *x /= 2);
        return result;
    }

    // TODO : a corriger
    /// Insert an `element` in a `lut` at `index` and return the modified lut (très très sensible et pas très robuste...)
    pub fn blind_insertion(
        &self,
        lut: LUT,
        index: LWE,
        element: &LWE,
        ctx: &Context,
        private_key: &PrivateKey,
    ) -> LUT {
        // One LUT to many LUT
        let mut many_lut = lut.to_many_lut(&self, &ctx);
        let lut_insertion = LUT::from_lwe(&element, &self, &ctx);
        print!("----lut_insertion : -----");
        lut_insertion.print(private_key, ctx);

        //Updating the index
        println!("-----many_lut : -----");
        let mut new_index: Vec<LWE> = Vec::new();
        for original_index in 0..many_lut.len() {
            let mut ct_cp = self.leq_scalar(&index, original_index as u64, &ctx);
            lwe_ciphertext_plaintext_add_assign(
                &mut ct_cp,
                Plaintext((original_index as u64) * ctx.delta()),
            );
            new_index.push(ct_cp);

            many_lut[original_index].print(&private_key, &ctx);
        }
        new_index[ctx.full_message_modulus() - 1] = index;
        many_lut[ctx.full_message_modulus() - 1] = lut_insertion;

        println!("------ Multi Blind Rotate-------");
        // Multi Blind Rotate
        for (lut, index) in many_lut.iter_mut().zip(new_index.iter()) {
            let mut rotation =
                self.allocate_and_trivially_encrypt_lwe(ctx.full_message_modulus() as u64, &ctx);
            lwe_ciphertext_sub_assign(&mut rotation, &index); // rotation = 16 - index = - index
                                                              // let rotation = self.neg_lwe(&index, &ctx);
            blind_rotate_assign(&rotation, &mut lut.0, &self.fourier_bsk);
            lut.print(private_key, ctx);
        }

        // Sum all the rotated glwe to get the final glwe permuted
        let mut output = many_lut[0].0.clone();
        for i in 1..many_lut.len() {
            output = self.glwe_sum(&output, &many_lut[i].0);
        }

        LUT(output)
    }

    /// Swap the elements of a `lut` given a vector of `permutation` and return the lut permuted
    pub fn blind_permutation(&self, lut: &LUT, permutation: &Vec<LWE>, ctx: &Context) -> LUT {
        let mut many_lut = lut.to_many_lut(&self, &ctx);
        // Multi Blind Rotate
        many_lut
            .iter_mut()
            .zip(permutation)
            .par_bridge()
            .for_each(|(mut lut, p)| {
                let neg_p = self.neg_lwe(&p, &ctx);
                self.blind_rotation_assign(&neg_p, &mut lut, &ctx);
            });
        // Sum all the rotated lut to get the final lut permuted
        let mut result_glwe = many_lut[0].0.clone();
        for i in 1..many_lut.len() {
            result_glwe = self.glwe_sum(&result_glwe, &many_lut[i].0);
        }
        LUT(result_glwe)
    }

    pub fn blind_kmin_all_distinct(&self, lut: LUT, ctx: &Context, k: usize) -> LWE {
        let n = ctx.full_message_modulus() as u64;
        let id = LUT::from_vec_trivially(&Vec::from_iter(0..n), ctx); // should be cached
        let permutation = lut.to_many_lwe(&self, ctx);
        let indices = self.blind_permutation(&id, &permutation, ctx);
        self.lut_extract(&indices, k, ctx)
    }

    pub fn blind_private_kmin(&self, lut: LUT, ctx: &Context, k: LWE) -> LWE {
        let n = ctx.full_message_modulus() as u64;
        let id = LUT::from_vec_trivially(&Vec::from_iter(0..n), ctx); // should be cached
        let permutation = lut.to_many_lwe(&self, ctx);
        let indices = self.blind_permutation(&id, &permutation, ctx);
        self.blind_array_access(&k, &indices, ctx)
    }

    pub fn blind_argmin_all_distinct(&self, lut: LUT, ctx: &Context) -> LWE {
        self.blind_kmin_all_distinct(lut, ctx, 0)
    }

    pub fn blind_argmax_all_distinct(&self, lut: LUT, ctx: &Context) -> LWE {
        self.blind_kmin_all_distinct(lut, ctx, ctx.full_message_modulus() - 1)
    }

    pub fn blind_lt_bma_mv(&self, a: &LWE, b: &LWE, ctx: &Context) -> LWE {
        let n = ctx.full_message_modulus;
        let matrix = Vec::from_iter(
            (0..n).map(|lin| Vec::from_iter((0..n).map(|col| if lin < col { 1 } else { 0 }))),
        );
        // let twice_bit = self.blind_matrix_access_mv(&matrix, &a, &b, &ctx);
        // let lut = LUT::from_vec_trivially(&vec![0, 0, 1], ctx);
        // self.blind_array_access(&twice_bit, &lut, &ctx)
        self.blind_matrix_access_clear(&matrix, &a, &b, &ctx)
    }

    pub fn blind_gt_bma_mv(&self, a: &LWE, b: &LWE, ctx: &Context) -> LWE {
        let n = ctx.full_message_modulus;
        let matrix = Vec::from_iter(
            (0..n).map(|lin| Vec::from_iter((0..n).map(|col| if lin > col { 1 } else { 0 }))),
        );
        self.blind_matrix_access_clear(&matrix, &a, &b, &ctx)
    }

    pub fn blind_eq_bma_mv(&self, a: &LWE, b: &LWE, ctx: &Context) -> LWE {
        let n = ctx.full_message_modulus;
        let matrix = Vec::from_iter(
            (0..n).map(|lin| Vec::from_iter((0..n).map(|col| if lin == col { 1 } else { 0 }))),
        );
        self.blind_matrix_access_clear(&matrix, &a, &b, &ctx)
    }

    // TODO : a revoir
    // Retrieve an element from a `lut` given it `index` and return the retrieved element with the new lut
    pub fn blind_retrieve(&self, lut: &mut LUT, index_retrieve: LWE, ctx: &Context) -> (LWE, LUT) {
        let mut big_lwe = LweCiphertext::new(
            0_64,
            ctx.big_lwe_dimension().to_lwe_size(),
            ctx.ciphertext_modulus(),
        );
        let mut lwe_retrieve = LweCiphertext::new(
            0_64,
            ctx.small_lwe_dimension().to_lwe_size(),
            ctx.ciphertext_modulus(),
        );

        // Delete the retrieved element from the lut
        // get the element wanted
        blind_rotate_assign(&index_retrieve, &mut lut.0, &self.fourier_bsk);
        extract_lwe_sample_from_glwe_ciphertext(&lut.0, &mut big_lwe, MonomialDegree(0));
        keyswitch_lwe_ciphertext(&self.lwe_ksk, &big_lwe, &mut lwe_retrieve);

        let lut_retrieve = LUT::from_lwe(&lwe_retrieve, self, &*ctx);
        let mut lut_sum = LUT(self.glwe_sum(&lut.0, &lut_retrieve.0));
        // rerotate the lut
        let neg_index_retrieve = self.neg_lwe(&index_retrieve, &*ctx);
        blind_rotate_assign(&neg_index_retrieve, &mut lut_sum.0, &self.fourier_bsk);

        // One LUT to many LUT
        let mut many_lut = lut_sum.to_many_lut(self, &*ctx);

        // Updating the index
        let mut new_index: Vec<LWE> = Vec::new();
        for original_index in 0..many_lut.len() {
            let ct_cp = self.leq_scalar(&index_retrieve, original_index as u64, &*ctx);
            let ct_original_index =
                self.allocate_and_trivially_encrypt_lwe(original_index as u64, ctx);
            let mut ct_new_index = LweCiphertext::new(
                0_u64,
                ctx.small_lwe_dimension().to_lwe_size(),
                ctx.ciphertext_modulus(),
            );
            lwe_ciphertext_sub(&mut ct_new_index, &ct_original_index, &ct_cp); // new index = original_index - ct_cp
            new_index.push(ct_new_index);
        }

        // Multi Blind Rotate
        for (lut, index) in many_lut.iter_mut().zip(new_index.iter()) {
            let rotation = self.neg_lwe(&index, &ctx);
            blind_rotate_assign(&rotation, &mut lut.0, &self.fourier_bsk);
        }

        // Sum all the rotated glwe to get the final glwe retrieved

        let mut result = many_lut[0].0.clone();
        for i in 1..many_lut.len() {
            result = self.glwe_sum(&result, &many_lut[i].0);
        }

        let new_lut = LUT(result);

        (lwe_retrieve, new_lut)
    }

    // TODO : a revoir
    /// Pop and udpate the `lut_stack`
    pub fn blind_pop(&self, lut_stack: &mut LUTStack, ctx: &Context) -> LWE {
        // rotation = stack_len - 1
        let lwe_one = self.allocate_and_trivially_encrypt_lwe(1_u64, &ctx);
        let mut lwe_pop = LweCiphertext::new(
            0,
            ctx.small_lwe_dimension().to_lwe_size(),
            ctx.ciphertext_modulus(),
        );
        let mut lwe_pop_not_switched = LweCiphertext::new(
            0,
            ctx.big_lwe_dimension().to_lwe_size(),
            ctx.ciphertext_modulus(),
        );
        let mut rotation = LweCiphertext::new(
            0_64,
            ctx.small_lwe_dimension().to_lwe_size(),
            ctx.ciphertext_modulus(),
        );
        lwe_ciphertext_sub(&mut rotation, &lut_stack.number_of_elements, &lwe_one);

        // rotate and extract to delete
        blind_rotate_assign(&rotation, &mut lut_stack.lut.0, &self.fourier_bsk);
        extract_lwe_sample_from_glwe_ciphertext(
            &lut_stack.lut.0,
            &mut lwe_pop_not_switched,
            MonomialDegree(0),
        );
        keyswitch_lwe_ciphertext(&self.lwe_ksk, &lwe_pop_not_switched, &mut lwe_pop);

        // Delete from the stack and re-rotate
        let lut_used_to_delete = LUT::from_lwe(&lwe_pop, &self, &ctx);
        self.glwe_sum_assign(&mut lut_stack.lut.0, &lut_used_to_delete.0);
        self.wrapping_neg_lwe(&mut rotation);
        blind_rotate_assign(&rotation, &mut lut_stack.lut.0, &self.fourier_bsk);

        // udpating the number of element
        lwe_ciphertext_sub_assign(&mut lut_stack.number_of_elements, &lwe_one);

        lwe_pop
    }

    // TODO : a revoir
    pub fn blind_push(&self, lut_stack: &mut LUTStack, lwe_push: &LWE, ctx: &Context) {
        let mut to_push = LUT::from_lwe(&lwe_push, self, &ctx);

        let stack_len = &lut_stack.number_of_elements;
        let mut rotation =
            self.allocate_and_trivially_encrypt_lwe(ctx.full_message_modulus() as u64, &ctx);

        lwe_ciphertext_sub_assign(&mut rotation, &stack_len);
        // rotation = 16 - index_to_push = - index_to_push
        blind_rotate_assign(&rotation, &mut to_push.0, &self.fourier_bsk);

        // Sum all the rotated glwe to get the final glwe permuted
        self.glwe_sum_assign(&mut lut_stack.lut.0, &to_push.0);

        let lwe_one = self.allocate_and_trivially_encrypt_lwe(1_u64, &ctx);
        // let mut new_number_of_element = LweCiphertext::new(0_u64, ctx.small_lwe_dimension().to_lwe_size(), ctx.ciphertext_modulus());
        // lwe_ciphertext_add(&mut new_number_of_element, &stack_len, &lwe_one);

        lwe_ciphertext_add_assign(&mut lut_stack.number_of_elements, &lwe_one);
        // lut_stack.number_of_elements = new_number_of_element;
    }

    // TODO : a revoir (generalize matrix to d-dimension)
    /// Get an element of a `tensor` given its `index_line` and its `index_column` ( the tensor must be encoded with encode_tensor_into_matrix)
    pub fn blind_tensor_access(
        &self,
        ct_tensor: &Vec<LUT>,
        index_line: &LWE,
        index_column: &LWE,
        nb_of_channels: usize,
        ctx: &Context,
    ) -> Vec<LWE> {
        let pbs_results: Vec<LWE> = ct_tensor
            .into_par_iter()
            .map(|acc| self.blind_array_access(&index_column, &acc, ctx))
            .collect();

        let mut lut_column = LUT::from_vec_of_lwe(&pbs_results, self, &ctx);
        // [ (c10, c20, c30), (c11, c21, c31), (c12, c22, c32), (c13, c23, c33), ... ]

        let index_line_encoded =
            self.lwe_ciphertext_plaintext_mul(&index_line, nb_of_channels as u64); // line = line * nb_of_channel

        // TODO : voir si ce code est encore nécéssaire
        // let index_line_encoded = self.lwe_ciphertext_plaintext_add(
        //     &index_line_encoded,
        //     ctx.full_message_modulus() as u64,
        //     &ctx,
        // ); // line = msg_mod + line \in [16,32] for 4_0

        self.blind_rotation_assign(&index_line_encoded, &mut lut_column, &ctx);

        let outputs_channels: Vec<LWE> = (0..nb_of_channels)
            .map(|channel| self.lut_extract(&lut_column, channel, ctx))
            .collect();

        outputs_channels
    }

    pub fn allocate_and_keyswitch_lwe_ciphertext(&self, lwe: &LWE, ctx: &Context) -> LWE {
        let mut switched = LweCiphertext::new(
            0,
            ctx.small_lwe_dimension().to_lwe_size(),
            ctx.ciphertext_modulus,
        );
        keyswitch_lwe_ciphertext(&self.lwe_ksk, &lwe, &mut switched);

        switched
    }

    /// returns the ciphertext at index i from the given lut, accounting for redundancya
    pub fn lut_extract(&self, lut: &LUT, i: usize, ctx: &Context) -> LWE {
        self.glwe_extract(&lut.0, i * ctx.box_size, ctx)
    }

    // Sample extract in glwe without the redundancy
    pub fn glwe_extract(&self, glwe: &GLWE, i: usize, ctx: &Context) -> LWE {
        let mut lwe = self.allocate_and_trivially_encrypt_lwe(0, ctx);
        extract_lwe_sample_from_glwe_ciphertext(&glwe, &mut lwe, MonomialDegree(i));
        lwe
    }

    pub fn bootstrap_lwe(&self, ct_input: &mut LWE, ctx: &Context) {
        let identity = LUT::from_function(|x| x % ctx.full_message_modulus() as u64, ctx);
        let bootstrapped = self.blind_array_access(ct_input, &identity, ctx);
        *ct_input = bootstrapped;
    }

    /// blindly adds x to the i-th box of the given LUT
    /// this process is noisy and the LUT needs bootstrapping before being read
    /// ```ignore
    ///    [ a, .. a, b, ... b, c, ..., c, ... ]
    /// + ~[ 0, .. 0, 0, ... 0, x, ..., x, ... ]
    /// ```
    pub fn blind_array_increment(&self, lut: &mut LUT, i: &LWE, x: &LWE, ctx: &Context) {
        let mut other = LUT::from_lwe(&x, &self, ctx);
        let neg_i = self.neg_lwe(&i, ctx);
        self.blind_rotation_assign(&neg_i, &mut other, ctx);
        self.glwe_sum_assign(&mut lut.0, &other.0);
    }

    pub fn blind_array_set(&self, lut: &mut LUT, i: &LWE, x: &LWE, ctx: &Context) {
        let current = self.blind_array_access(i, lut, ctx);
        let mut x = x.clone();
        lwe_ciphertext_sub_assign(&mut x, &current);
        self.blind_array_increment(lut, i, &x, ctx);
    }

    pub fn blind_index(&self, lut: &LUT, x: &LWE, ctx: &Context) -> LWE {
        let n = ctx.full_message_modulus();
        let mut i = self.allocate_and_trivially_encrypt_lwe(0, ctx);
        let mut f = self.allocate_and_trivially_encrypt_lwe(0, ctx);
        let iszero = LUT::from_vec_trivially(&vec![1], ctx);
        for j in 0..n {
            // sample extract
            let e = self.lut_extract(&lut, j, ctx);

            // z = (x == e)
            let mut z = self.allocate_and_trivially_encrypt_lwe(0u64, ctx);
            lwe_ciphertext_sub(&mut z, &x, &e);
            z = self.blind_array_access(&z, &iszero, ctx);

            // z = 1 if x == e else 0

            // i = f ? j : i
            // i += (z and not f) * j
            // i += (1 - f + z) * j
            let mut acc = self.allocate_and_trivially_encrypt_lwe(1, ctx);
            lwe_ciphertext_sub_assign(&mut acc, &f);
            lwe_ciphertext_add_assign(&mut acc, &z);
            let jifzandnotf = LUT::from_vec_trivially(&vec![0, 0, j as u64], &ctx);
            let maybej = self.blind_array_access(&acc, &jifzandnotf, &ctx);
            lwe_ciphertext_add_assign(&mut i, &maybej);

            // f |= z
            lwe_ciphertext_add_assign(&mut z, &f);
            z = self.blind_array_access(&z, &iszero, ctx);
            f = self.allocate_and_trivially_encrypt_lwe(1u64, ctx);
            lwe_ciphertext_sub_assign(&mut f, &z);
        }

        i
    }

    // Blind select between two LWE (selector = 0 ? lwe1 : lwe2)
    pub fn cmux(&self, lwe1: LWE, lwe2: LWE, selector: &LWE, ctx: &Context) -> LWE {
        let vec_lwe = vec![lwe1, lwe2];
        let lut = LUT::from_vec_of_lwe(&vec_lwe, self, ctx);
        self.blind_array_access(&selector, &lut, ctx)
    }

    // Blind selection of a data from a list of private data, with a list of private selector ( a la OT)
    pub fn blind_selection(&self, vec_lwe: &[LWE], vec_selector: &[LWE], ctx: &Context) -> LWE {
        let mut acc = self.allocate_and_trivially_encrypt_lwe(0, ctx);
        vec_lwe
            .iter()
            .zip(vec_selector.iter())
            .for_each(|(lwe, selector)| {
                lwe_ciphertext_add_assign(
                    &mut acc,
                    &self.lwe_mul_encrypted_bit(&lwe, &selector, ctx),
                );
            });
        acc
    }

    // Private selection of a data from a list of public data, with a list of private selector ( a la PIR)
    pub fn private_selection(&self, data: &[u64], vec_selector: &[LWE], ctx: &Context) -> LWE {
        let mut acc = self.allocate_and_trivially_encrypt_lwe(0, ctx);
        data.iter()
            .zip(vec_selector.iter())
            .for_each(|(d, selector)| {
                let mut d_or_zero = selector.clone();
                lwe_ciphertext_cleartext_mul_assign(&mut d_or_zero, Cleartext(*d));
                lwe_ciphertext_add_assign(&mut acc, &d_or_zero);
            });
        acc
    }

    pub fn blind_argmin(&self, lwes: &[LWE], ctx: &Context) -> LWE {
        // initialize min to the first element, and argmin to its index
        let mut min = lwes[0].clone();
        let mut argmin = self.allocate_and_trivially_encrypt_lwe(0, ctx);

        // loop and search for min and armgin
        for i in 1..lwes.len() {
            let e = lwes[i].clone();
            // blind lt mv
            let b = self.blind_lt_bma_mv(&min, &e, ctx);

            let arg_e = self.allocate_and_trivially_encrypt_lwe(i as u64, &ctx);
            let lut_indices = LUT::from_vec_of_lwe(&[arg_e, argmin], self, &ctx);
            let lut_messages = LUT::from_vec_of_lwe(&[e, min], self, &ctx);

            argmin = self.blind_array_access(&b, &lut_indices, &ctx);
            min = self.blind_array_access(&b, &lut_messages, &ctx);
        }

        argmin
    }

    pub fn blind_argmax(&self, lwes: &[LWE], ctx: &Context) -> LWE {
        // initialize min to the first element, and argmin to its index
        let mut max = lwes[0].clone();
        let mut argmax = self.allocate_and_trivially_encrypt_lwe(0, ctx);

        // loop and search for min and armgin
        for i in 1..lwes.len() {
            let e = lwes[i].clone();
            // blind lt mv
            let b = self.blind_gt_bma_mv(&max, &e, ctx);

            let arg_e = self.allocate_and_trivially_encrypt_lwe(i as u64, &ctx);
            let lut_indices = LUT::from_vec_of_lwe(&[arg_e, argmax], self, &ctx);
            let lut_messages = LUT::from_vec_of_lwe(&[e, max], self, &ctx);

            argmax = self.blind_array_access(&b, &lut_indices, &ctx);
            max = self.blind_array_access(&b, &lut_messages, &ctx);
        }

        argmax
    }

    pub fn blind_count(&self, lwes: &[LWE], ctx: &Context) -> Vec<LWE> {
        let mut count = LUT::from_vec_trivially(&vec![0; ctx.full_message_modulus()], ctx);
        let one = self.allocate_and_trivially_encrypt_lwe(1, ctx);
        let lut = LUT::from_vec_of_lwe(lwes, self, ctx);
        for i in 0..lwes.len() {
            let j = self.lut_extract(&lut, i, ctx);
            self.blind_array_increment(&mut count, &j, &one, ctx);
        }
        count.to_many_lwe(self, ctx)
    }

    pub fn blind_majority(&self, lwes: &[LWE], ctx: &Context) -> LWE {
        let count = self.blind_count(lwes, ctx);
        let maj = self.blind_argmax(&count, ctx);
        maj
    }

    /// This function select one of the 3 luts based on the value of s1 then use the result to select one of the 3 lwe based on the value of s2
    /// s2 needs to encrypt 0, 1 or 2
    pub fn switch_case3(&self, s1: &LWE, s2: &LWE, luts: &[LUT], ctx: &Context) -> LWE {
        let a = self.blind_array_access(&s1, &luts[0], ctx);
        let b = self.blind_array_access(&s1, &luts[1], ctx);
        let c = self.blind_array_access(&s1, &luts[2], ctx);

        let acc = LUT::from_vec_of_lwe(&vec![a, b, c], self, ctx);
        let res = self.blind_array_access(s2, &acc, ctx);
        res
    }
}

#[derive(Clone)]
pub struct LUT(pub GLWE);

impl LUT {
    pub fn new(ctx: &Context) -> LUT {
        let new_lut = GlweCiphertext::new(
            0_64,
            ctx.glwe_dimension().to_glwe_size(),
            ctx.polynomial_size(),
            ctx.ciphertext_modulus(),
        );
        LUT(new_lut)
    }

    /* Fill the boxes and multiplying the content by delta (encoding in the MSB) */
    fn add_redundancy_and_encode_many_u64(vec: &Vec<u64>, ctx: &Context) -> Vec<u64> {
        // N/(p/2) = size of each block, to correct noise from the input we introduce the notion of
        // box, which manages redundancy to yield a denoised value for several noisy values around
        // a true input value.
        let box_size = ctx.box_size();

        // Create the output
        let mut accumulator_u64 = vec![0_u64; ctx.polynomial_size().0];

        // Fill each box with the encoded denoised value
        for i in 0..vec.len() {
            let index = i * box_size;
            for j in index..index + box_size {
                accumulator_u64[j] = vec[i] * ctx.delta() as u64;
            }
        }

        let half_box_size = box_size / 2;
        // Negate the first half_box_size coefficients to manage negacyclicity and rotate
        for a_i in accumulator_u64[0..half_box_size].iter_mut() {
            *a_i = (*a_i).wrapping_neg();
        }

        // Rotate the accumulator
        accumulator_u64.rotate_left(half_box_size);

        accumulator_u64
    }

    /* Fill the boxes without multiplying the content by delta */
    fn add_redundancy_many_u64(vec: &Vec<u64>, ctx: &Context) -> Vec<u64> {
        // N/(p/2) = size of each block, to correct noise from the input we introduce the notion of
        // box, which manages redundancy to yield a denoised value for several noisy values around
        // a true input value.
        let box_size = ctx.box_size();

        // Create the output
        let mut accumulator_u64 = vec![0_u64; ctx.polynomial_size().0];

        // Fill each box with the encoded denoised value
        for i in 0..vec.len() {
            let index = i * box_size;
            for j in index..index + box_size {
                accumulator_u64[j] = vec[i];
            }
        }

        let half_box_size = box_size / 2;
        // Negate the first half_box_size coefficients to manage negacyclicity and rotate
        for a_i in accumulator_u64[0..half_box_size].iter_mut() {
            *a_i = ((*a_i).wrapping_neg()) % ctx.full_message_modulus() as u64;
        }
        // Rotate the accumulator
        accumulator_u64.rotate_left(half_box_size);

        accumulator_u64
    }

    pub fn from_function<F>(f: F, ctx: &Context) -> LUT
    where
        F: Fn(u64) -> u64,
    {
        let box_size = ctx.box_size();
        // Create the accumulator
        let mut accumulator_u64 = vec![0_u64; ctx.polynomial_size().0];

        // Fill each box with the encoded denoised value
        for i in 0..ctx.full_message_modulus() {
            let index = i * box_size;
            accumulator_u64[index..index + box_size]
                .iter_mut()
                .for_each(|a| *a = f(i as u64) * ctx.delta());
        }

        let half_box_size = box_size / 2;

        // Negate the first half_box_size coefficients to manage negacyclicity and rotate
        for a_i in accumulator_u64[0..half_box_size].iter_mut() {
            *a_i = (*a_i).wrapping_neg();
        }

        // Rotate the accumulator
        accumulator_u64.rotate_left(half_box_size);

        let accumulator_plaintext = PlaintextList::from_container(accumulator_u64);

        let accumulator = allocate_and_trivially_encrypt_new_glwe_ciphertext(
            ctx.glwe_dimension().to_glwe_size(),
            &accumulator_plaintext,
            ctx.ciphertext_modulus(),
        );

        LUT(accumulator)
    }

    pub fn from_function_and_delta<F>(f: F, delta: u64, ctx: &Context) -> LUT
    where
        F: Fn(u64) -> u64,
    {
        let box_size = ctx.box_size();
        // Create the accumulator
        let mut accumulator_u64 = vec![0_u64; ctx.polynomial_size().0];

        // Fill each box with the encoded denoised value
        for i in 0..ctx.full_message_modulus() {
            let index = i * box_size;
            accumulator_u64[index..index + box_size]
                .iter_mut()
                .for_each(|a| *a = f(i as u64) * delta);
        }

        let half_box_size = box_size / 2;

        // Negate the first half_box_size coefficients to manage negacyclicity and rotate
        for a_i in accumulator_u64[0..half_box_size].iter_mut() {
            *a_i = (*a_i).wrapping_neg();
        }

        // Rotate the accumulator
        accumulator_u64.rotate_left(half_box_size);

        let accumulator_plaintext = PlaintextList::from_container(accumulator_u64);

        let accumulator = allocate_and_trivially_encrypt_new_glwe_ciphertext(
            ctx.glwe_dimension().to_glwe_size(),
            &accumulator_plaintext,
            ctx.ciphertext_modulus(),
        );

        LUT(accumulator)
    }

    pub fn from_vec(vec: &Vec<u64>, private_key: &PrivateKey, ctx: &mut Context) -> LUT {
        let mut lut_as_glwe = GlweCiphertext::new(
            0_u64,
            ctx.glwe_dimension().to_glwe_size(),
            ctx.polynomial_size(),
            ctx.ciphertext_modulus(),
        );
        let redundant_lut = Self::add_redundancy_and_encode_many_u64(vec, ctx);
        let accumulator_plaintext = PlaintextList::from_container(redundant_lut);
        private_key.encrypt_glwe(&mut lut_as_glwe, accumulator_plaintext, ctx);
        LUT(lut_as_glwe)
    }

    pub fn from_vec_trivially(data: &Vec<u64>, ctx: &Context) -> LUT {
        let redundant_lut = Self::add_redundancy_and_encode_many_u64(data, ctx);
        LUT(allocate_and_trivially_encrypt_new_glwe_ciphertext(
            ctx.glwe_dimension().to_glwe_size(),
            &PlaintextList::from_container(redundant_lut),
            ctx.ciphertext_modulus(),
        ))
    }

    pub fn from_vec_of_lwe(many_lwe: &[LWE], public_key: &PublicKey, ctx: &Context) -> LUT {
        if many_lwe.len() > ctx.full_message_modulus() as usize {
            panic!(
                "Number of LWE samples are more than the full message modulus, it cannot be packed into one LUT"
            );
        }
        let pt_list = PlaintextList::new(0, PlaintextCount(ctx.polynomial_size().0));
        let mut acc = public_key.allocate_and_trivially_encrypt_glwe(pt_list, ctx);
        for (i, lwe) in many_lwe.iter().enumerate() {
            let mut lut = LUT::from_lwe(&lwe, &public_key, &ctx);
            lut.public_rotate_right(i * ctx.box_size(), public_key);
            public_key.glwe_sum_assign(&mut acc, &lut.0);
        }
        LUT(acc)
    }

    // /// creates a LUT whose first box is filled with copies of the given lwe
    // pub fn from_lwe(lwe: &LWE, public_key: &PublicKey, ctx: &Context) -> LUT {
    //     let mut output = GlweCiphertext::new(
    //         0,
    //         ctx.glwe_dimension().to_glwe_size(),
    //         ctx.polynomial_size(),
    //         ctx.ciphertext_modulus(),
    //     );
    //     // par_private_functional_keyswitch_lwe_ciphertext_into_glwe_ciphertext(
    //     //     &public_key.pfpksk,
    //     //     &mut output,
    //     //     &lwe,
    //     // );

    //     private_functional_keyswitch_lwe_ciphertext_into_glwe_ciphertext(
    //         &public_key.pfpksk,
    //         &mut output,
    //         &lwe,
    //     );

    //     // fill the first box in log(box_size) glwe sums
    //     for i in 0..ctx.box_size().ilog2() {
    //         let mut other = output.clone();
    //         public_key.glwe_absorption_monic_monomial(&mut other, MonomialDegree(2usize.pow(i)));
    //         public_key.glwe_sum_assign(&mut output, &other);
    //     }

    //     // center the box
    //     let poly_monomial_degree = MonomialDegree(2 * ctx.polynomial_size().0 - ctx.box_size() / 2);
    //     public_key.glwe_absorption_monic_monomial(&mut output, poly_monomial_degree);

    //     LUT(output)
    // }

    /// creates a LUT whose first box is filled with copies of the given lwe
    pub fn from_lwe(lwe: &LWE, public_key: &PublicKey, ctx: &Context) -> LUT {
        let mut output = GlweCiphertext::new(
            0,
            ctx.glwe_dimension().to_glwe_size(),
            ctx.polynomial_size(),
            ctx.ciphertext_modulus(),
        );

        keyswitch_lwe_ciphertext_into_glwe_ciphertext(&public_key.packing_ksk, &lwe, &mut output);

        // fill the first box in log(box_size) glwe sums
        for i in 0..ctx.box_size().ilog2() {
            let mut other = output.clone();
            public_key.glwe_absorption_monic_monomial(&mut other, MonomialDegree(2usize.pow(i)));
            public_key.glwe_sum_assign(&mut output, &other);
        }

        // center the box
        let poly_monomial_degree = MonomialDegree(2 * ctx.polynomial_size().0 - ctx.box_size() / 2);
        public_key.glwe_absorption_monic_monomial(&mut output, poly_monomial_degree);

        LUT(output)
    }

    /// Extract each element from the LUT into a LWE
    pub fn to_many_lwe(&self, public_key: &PublicKey, ctx: &Context) -> Vec<LWE> {
        (0..ctx.full_message_modulus())
            .map(|i| public_key.lut_extract(&self, i, ctx))
            .collect()
    }

    /// Make a LUT starting with each element from this LUT
    pub fn to_many_lut(&self, public_key: &PublicKey, ctx: &Context) -> Vec<LUT> {
        self.to_many_lwe(public_key, ctx)
            .iter()
            .map(|lwe| LUT::from_lwe(&lwe, public_key, ctx))
            .collect()
    }

    pub fn add_lut(&self, lut_r: &LUT) -> LUT {
        let ciphertext_modulus = CiphertextModulus::new_native();
        let mut res = GlweCiphertext::new(
            0_u64,
            self.0.glwe_size(),
            self.0.polynomial_size(),
            ciphertext_modulus,
        );

        res.as_mut()
            .iter_mut()
            .zip(self.0.as_ref().iter().zip(lut_r.0.as_ref().iter()))
            .for_each(|(dst, (&lhs, &rhs))| *dst = lhs + rhs);
        return LUT(res);
    }

    pub fn print(&self, private_key: &PrivateKey, ctx: &Context) {
        let output_vec = (0..ctx.message_modulus().0)
            .map(|i| {
                let ct_big = private_key.public_key.lut_extract(&self, i, ctx);
                private_key.decrypt_lwe(&ct_big, &ctx)
            })
            .collect::<Vec<u64>>();
        println!("{:?}", output_vec);
    }

    pub fn to_array(&self, private_key: &PrivateKey, ctx: &Context) -> Vec<u64> {
        self.to_many_lwe(&private_key.public_key, ctx)
            .iter()
            .map(|lwe| private_key.decrypt_lwe(&lwe, &ctx))
            .collect()
    }

    // Rotate the LUT to the right by the given number of boxes
    pub fn public_rotate_right(&mut self, rotation: usize, public_key: &PublicKey) {
        public_key.glwe_absorption_monic_monomial(&mut self.0, MonomialDegree(rotation));
    }

    /// Rotate the LUT to the left by the given number of boxes (emulate a blind rotation with a trivial lwe)
    pub fn public_rotate_left(&mut self, rotation: usize, public_key: &PublicKey) {
        let poly_size = self.0.polynomial_size().0;
        public_key
            .glwe_absorption_monic_monomial(&mut self.0, MonomialDegree(2 * poly_size - rotation));
    }

    /// re-packs a fresh LUT from its sample extracts
    pub fn bootstrap_lut(&self, public_key: &PublicKey, ctx: &Context) -> LUT {
        let mut many_lwe = self.to_many_lwe(public_key, ctx);
        for mut lwe in many_lwe.iter_mut() {
            public_key.bootstrap_lwe(&mut lwe, ctx);
        }
        LUT::from_vec_of_lwe(&many_lwe, public_key, ctx)
    }
}

pub struct LUTStack {
    pub lut: LUT,
    // sentinelle vers la prochaine case vide de la LUT
    pub number_of_elements: LWE,
}

impl LUTStack {
    pub fn new(ctx: &Context) -> LUTStack {
        let lut = LUT(GlweCiphertext::new(
            0_64,
            ctx.glwe_dimension().to_glwe_size(),
            ctx.polynomial_size(),
            ctx.ciphertext_modulus(),
        ));

        let number_of_elements = LweCiphertext::new(
            0_u64,
            ctx.big_lwe_dimension().to_lwe_size(),
            ctx.ciphertext_modulus(),
        );
        LUTStack {
            lut,
            number_of_elements,
        }
    }

    fn add_redundancy_many_u64(vec: &Vec<u64>, ctx: &Context) -> Vec<u64> {
        // N/(p/2) = size of each block, to correct noise from the input we introduce the notion of
        // box, which manages redundancy to yield a denoised value for several noisy values around
        // a true input value.
        let box_size = ctx.box_size();

        // Create the output
        let mut accumulator_u64 = vec![0_u64; ctx.polynomial_size().0];

        // Fill each box with the encoded denoised value
        for i in 0..vec.len() {
            let index = i * box_size;
            for j in index..index + box_size {
                accumulator_u64[j] = vec[i] * ctx.delta() as u64;
            }
        }

        let half_box_size = box_size / 2;
        // Negate the first half_box_size coefficients to manage negacyclicity and rotate
        for a_i in accumulator_u64[0..half_box_size].iter_mut() {
            *a_i = (*a_i).wrapping_neg();
        }

        // Rotate the accumulator
        accumulator_u64.rotate_left(half_box_size);

        accumulator_u64
    }

    pub fn from_vec(vec: &Vec<u64>, private_key: &PrivateKey, ctx: &mut Context) -> LUTStack {
        let stack_len = private_key.allocate_and_trivially_encrypt_lwe((vec.len()) as u64, ctx);
        let mut lut_as_glwe = GlweCiphertext::new(
            0_u64,
            ctx.glwe_dimension().to_glwe_size(),
            ctx.polynomial_size(),
            ctx.ciphertext_modulus(),
        );
        let redundant_lut = Self::add_redundancy_many_u64(vec, ctx);
        let accumulator_plaintext = PlaintextList::from_container(redundant_lut);
        private_key.encrypt_glwe(&mut lut_as_glwe, accumulator_plaintext, ctx);

        LUTStack {
            lut: LUT(lut_as_glwe),
            number_of_elements: stack_len,
        }
    }

    pub fn from_lut(lut: LUT, public_key: &PublicKey, ctx: &Context) -> LUTStack {
        let mut number_of_elements =
            public_key.allocate_and_trivially_encrypt_lwe(ctx.full_message_modulus() as u64, ctx);

        for i in (0..ctx.full_message_modulus()).rev() {
            let lwe = public_key.lut_extract(&lut, i, ctx);
            let cp = public_key.eq_scalar(&lwe, 0, &ctx);
            lwe_ciphertext_sub_assign(&mut number_of_elements, &cp);
        }

        LUTStack {
            lut,
            number_of_elements,
        }
    }

    pub fn print(&self, private_key: &PrivateKey, ctx: &Context) {
        let box_size = ctx.polynomial_size().0 / ctx.message_modulus().0;

        // Create the accumulator
        let mut input_vec = Vec::new();
        let mut ct_big = LweCiphertext::new(
            0_64,
            ctx.big_lwe_dimension().to_lwe_size(),
            ctx.ciphertext_modulus(),
        );

        for i in 0..ctx.message_modulus().0 {
            //many_lwe.len()
            let index = i * box_size;
            extract_lwe_sample_from_glwe_ciphertext(
                &self.lut.0,
                &mut ct_big,
                MonomialDegree(index),
            );
            input_vec.push(private_key.decrypt_lwe(&ct_big, &ctx));
        }

        println!("LUT Stack : {:?}", input_vec);
        println!(
            "LUT Stack size : {:?}",
            private_key.decrypt_lwe(&self.number_of_elements, ctx)
        );
    }
}

#[cfg(test)]
mod test {
    use std::array;
    use std::cmp;
    use std::time::Instant;

    use super::*;
    use itertools::Itertools;
    use quickcheck::TestResult;
    use rand::seq::SliceRandom;
    use tfhe::shortint::parameters::*;

    #[test]
    fn test_lwe_add() {
        let mut ctx = Context::from(PARAM_MESSAGE_4_CARRY_0);
        let private_key = key(PARAM_MESSAGE_4_CARRY_0);
        let input1: u64 = 19;
        let input2: u64 = 1;
        let mut lwe1 = private_key.allocate_and_encrypt_lwe(input1, &mut ctx);
        let lwe2 = private_key.allocate_and_encrypt_lwe(input2, &mut ctx);
        lwe_ciphertext_add_assign(&mut lwe1, &lwe2);
        let clear = private_key.decrypt_lwe_without_reduction(&lwe1, &mut ctx);
        println!("clear: {}", clear);
        // assert_eq!(input1 + input2, clear);
    }

    #[test]
    fn test_lwe_add_tfhe_rs() {
        use tfhe::core_crypto::prelude::*;

        // DISCLAIMER: these toy example parameters are not guaranteed to be secure or yield correct
        // computations
        // Define parameters for LweCiphertext creation
        let lwe_dimension = LweDimension(742);
        let lwe_noise_distribution =
            Gaussian::from_dispersion_parameter(StandardDev(0.000007069849454709433), 0.0);
        let message_modulus = MessageModulus(16);
        let ciphertext_modulus = CiphertextModulus::new_native();

        // Create the PRNG
        let mut seeder = new_seeder();
        let seeder = seeder.as_mut();
        let mut encryption_generator =
            EncryptionRandomGenerator::<ActivatedRandomGenerator>::new(seeder.seed(), seeder);
        let mut secret_generator =
            SecretRandomGenerator::<ActivatedRandomGenerator>::new(seeder.seed());

        // Create the LweSecretKey
        let lwe_secret_key =
            allocate_and_generate_new_binary_lwe_secret_key(lwe_dimension, &mut secret_generator);

        // Create the plaintext
        let delta = (1u64 << 63) / (message_modulus.0 as u64);
        let msg1 = 15;
        let msg2 = 15;
        let plaintext1 = Plaintext(msg1 * delta);
        let plaintext2 = Plaintext(msg2 * delta);

        // Create a new LweCiphertext
        let lwe1 = allocate_and_encrypt_new_lwe_ciphertext(
            &lwe_secret_key,
            plaintext1,
            lwe_noise_distribution,
            ciphertext_modulus,
            &mut encryption_generator,
        );
        let lwe2 = allocate_and_encrypt_new_lwe_ciphertext(
            &lwe_secret_key,
            plaintext2,
            lwe_noise_distribution,
            ciphertext_modulus,
            &mut encryption_generator,
        );
        let mut lwe_sum = lwe1.clone();
        lwe_ciphertext_add_assign(&mut lwe_sum, &lwe2);
        lwe_ciphertext_plaintext_add_assign(&mut lwe_sum, Plaintext(4 * delta));

        let decrypted_plaintext = decrypt_lwe_ciphertext(&lwe_secret_key, &lwe_sum);

        // Round and remove encoding
        // First create a decomposer working on the high 4 bits corresponding to our encoding.
        let decomposer = SignedDecomposer::new(DecompositionBaseLog(4), DecompositionLevelCount(1));
        let rounded = decomposer.closest_representable(decrypted_plaintext.0);
        // Remove the encoding
        let cleartext = rounded / delta;

        println!("cleartext: {}", cleartext);
    }
    #[test]
    fn test_lwe_enc() {
        let mut ctx = Context::from(PARAM_MESSAGE_4_CARRY_0);
        let private_key = key(PARAM_MESSAGE_4_CARRY_0);
        let input: u64 = 1;
        let lwe = private_key.allocate_and_encrypt_lwe(input, &mut ctx);
        let clear = private_key.decrypt_lwe(&lwe, &mut ctx); // decryption with reduction
        println!("Test encryption-decryption");
        println!("input: {}", input);
        println!("decrypted: {}", clear);
        assert_eq!(input, clear);
    }

    #[test]
    fn test_add_lwe() {
        let mut ctx = Context::from(PARAM_MESSAGE_4_CARRY_0);
        let private_key = key(PARAM_MESSAGE_4_CARRY_0);
        let public_key = &private_key.public_key;
        let input1: u64 = 16;
        let input2: u64 = 1;
        let mut lwe1 = private_key.allocate_and_encrypt_lwe(input1, &mut ctx);
        let lwe2 = private_key.allocate_and_encrypt_lwe(input2, &mut ctx);
        lwe_ciphertext_add_assign(&mut lwe1, &lwe2);

        let identity = LUT::from_function(|x| ctx.full_message_modulus() as u64 - x, &ctx);
        let lwe_identity = public_key.blind_array_access(&mut lwe1, &identity, &ctx);

        lwe_ciphertext_add_assign(&mut lwe1, &lwe_identity);
        let plaintext = decrypt_lwe_ciphertext(&private_key.get_big_lwe_sk(), &lwe1);
        let decrypted = plaintext.0 / ctx.delta();
        println!("decrypted: {}", decrypted);
    }

    #[test]
    fn test_lut_enc() {
        let mut ctx = Context::from(PARAM_MESSAGE_4_CARRY_0);
        let private_key = key(PARAM_MESSAGE_4_CARRY_0);
        let array = vec![0, 1, 2, 3, 4];
        let _lut = LUT::from_vec(&array, &private_key, &mut ctx);
    }

    #[test]
    fn test_neg_lwe() {
        let mut ctx = Context::from(PARAM_MESSAGE_4_CARRY_0);
        let private_key = key(PARAM_MESSAGE_4_CARRY_0);
        let public_key = &private_key.public_key;
        let input: u64 = 3;
        let mut lwe = private_key.allocate_and_encrypt_lwe(input, &mut ctx);
        public_key.wrapping_neg_lwe(&mut lwe);
        let clear = private_key.decrypt_lwe(&lwe, &mut ctx);
        println!("Test encryption-decryption");
        println!("neg_lwe = {}", clear);
        // assert_eq!(input,16-clear);
    }

    #[test]
    fn test_neg_lwe_assign() {
        let mut ctx = Context::from(PARAM_MESSAGE_4_CARRY_0);
        let private_key = key(PARAM_MESSAGE_4_CARRY_0);
        let public_key = &private_key.public_key;
        let input: u64 = 3;
        let mut lwe = private_key.allocate_and_encrypt_lwe(input, &mut ctx);
        let neg_lwe = public_key.neg_lwe(&mut lwe, &ctx);
        let clear = private_key.decrypt_lwe(&neg_lwe, &mut ctx);
        println!("Test encryption-decryption");
        println!("neg_lwe = {}", clear);
        // assert_eq!(input,16-clear);
    }

    #[test]
    fn test_lut_from_many_lwe() {
        let mut ctx = Context::from(PARAM_MESSAGE_2_CARRY_0);
        let private_key = PrivateKey::new(&mut ctx);
        let public_key = &private_key.public_key;
        let our_input: Vec<u64> = vec![0, 1, 2, 3];
        let mut many_lwe: Vec<LWE> = vec![];
        for input in our_input {
            let lwe = private_key.allocate_and_encrypt_lwe(input, &mut ctx);
            many_lwe.push(lwe);
        }
        let lut = LUT::from_vec_of_lwe(&many_lwe, public_key, &ctx);
        let output_pt = private_key.decrypt_and_decode_glwe(&lut.0, &ctx);
        println!("Test many LWE to one GLWE");
        println!("{:?}", output_pt);
    }

    #[test]
    fn test_lut_from_lwe() {
        let mut ctx = Context::from(PARAM_MESSAGE_4_CARRY_0);
        let private_key = key(ctx.parameters);
        let public_key = &private_key.public_key;

        for i in 0u64..16u64 {
            let lwe = private_key.allocate_and_encrypt_lwe(i, &mut ctx);
            let start = Instant::now();
            let lut = LUT::from_lwe(&lwe, public_key, &ctx);
            let elapsed = Instant::now() - start;
            lut.print(&private_key, &ctx);
            println!("Time taken to create LUT: {:?}", elapsed);
            for j in 0..16u64 {
                let output = public_key.lut_extract(&lut, j as usize, &ctx);
                let actual = private_key.decrypt_lwe(&output, &ctx);
                assert_eq!(actual, if j == 0 { i } else { 0 });
            }
        }
    }

    #[test]
    fn test_eq_scalar() {
        let mut ctx = Context::from(PARAM_MESSAGE_4_CARRY_0);
        let private_key = key(PARAM_MESSAGE_4_CARRY_0);
        let public_key = &private_key.get_public_key();
        let our_input = 0u64;
        let lwe = private_key.allocate_and_encrypt_lwe(our_input, &mut ctx);

        for i in 0..16 {
            let cp = public_key.eq_scalar(&lwe, i, &ctx);
            let res = private_key.decrypt_lwe(&cp, &ctx);
            println!("{} == {} : {}", our_input, i, res);
        }
    }

    #[test]
    fn test_lut_stack_from_lut() {
        let mut ctx = Context::from(PARAM_MESSAGE_4_CARRY_0);
        let private_key = key(PARAM_MESSAGE_4_CARRY_0);
        let public_key = &private_key.public_key;
        let array = vec![2, 1, 2, 3, 4];
        let lut = LUT::from_vec(&array, &private_key, &mut ctx);

        let lut_stack = LUTStack::from_lut(lut, public_key, &ctx);

        lut_stack.print(&private_key, &ctx);
    }

    #[test]
    fn test_lut_sum() {
        let mut ctx = Context::from(PARAM_MESSAGE_2_CARRY_0);
        let private_key = key(PARAM_MESSAGE_2_CARRY_0);
        let array1 = vec![1, 1, 0, 0];
        let array2 = vec![0, 0, 1, 1];
        let lut1 = LUT::from_vec(&array1, &private_key, &mut ctx);
        let lut2 = LUT::from_vec(&array2, &private_key, &mut ctx);
        lut1.print(&private_key, &ctx);
        println!("+");
        lut2.print(&private_key, &ctx);
        println!("=");
        let lut_sum = lut1.add_lut(&lut2);
        lut_sum.print(&private_key, &ctx);
    }

    #[test]
    fn test_lwe_sub_wrap() {
        let mut ctx = Context::from(PARAM_MESSAGE_4_CARRY_0);
        let private_key = key(PARAM_MESSAGE_4_CARRY_0);
        let public_key = &private_key.public_key;
        let a = private_key.allocate_and_encrypt_lwe(0, &mut ctx);
        let b = public_key.allocate_and_trivially_encrypt_lwe(1, &ctx);
        let mut c = a.clone();
        lwe_ciphertext_sub(&mut c, &a, &b);
        let d = private_key.decrypt_lwe(&c, &ctx);
        assert_eq!(d, 15);
    }

    #[quickcheck]
    fn test_lut_extract(mut array: Vec<u64>, i: usize) -> TestResult {
        let mut ctx = Context::from(PARAM_MESSAGE_4_CARRY_0);
        let private_key = key(PARAM_MESSAGE_4_CARRY_0);
        let public_key = &private_key.public_key;

        array.truncate(16);
        array.iter_mut().for_each(|x| *x %= 16);
        if !(i < array.len()) {
            return TestResult::discard();
        }

        let expected = array[i];
        let lut = LUT::from_vec(&array, &private_key, &mut ctx);
        let lwe = public_key.lut_extract(&lut, i, &ctx);
        let actual = private_key.decrypt_lwe(&lwe, &ctx);

        TestResult::from_bool(actual == expected)
    }

    #[test]
    fn test_blind_permutation_time() {
        let mut ctx = Context::from(PARAM_MESSAGE_5_CARRY_0);
        let private_key = key(PARAM_MESSAGE_5_CARRY_0);
        let public_key = &private_key.public_key;
        // let array = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
        let array = Vec::from_iter(0..32);
        let lut = LUT::from_vec(&array, &private_key, &mut ctx);
        let permutation = Vec::from_iter(
            array
                .iter()
                .map(|&x| private_key.allocate_and_encrypt_lwe(x, &mut ctx)),
        );

        let begin = Instant::now();
        let permuted = public_key.blind_permutation(&lut, &permutation, &ctx);
        let elapsed = Instant::now() - begin;

        print!("sorted ({:?}): ", elapsed);
        permuted.print(&private_key, &ctx);
    }

    #[test]
    fn test_blind_rotation_time() {
        let mut ctx = Context::from(PARAM_MESSAGE_4_CARRY_0);
        let private_key = key(PARAM_MESSAGE_4_CARRY_0);
        let public_key = &private_key.public_key;
        let array = Vec::from_iter(0..16);
        let mut lut = LUT::from_vec(&array, &private_key, &mut ctx);
        let rotation_amount = 1;
        let mut lwe_rotation_amount =
            private_key.allocate_and_encrypt_lwe_big_key(rotation_amount, &mut ctx);

        // print the noise of the lwe_rotation_amount
        println!(
            "noise of lwe_rotation_amount: {}",
            private_key.lwe_noise(&lwe_rotation_amount, rotation_amount, &ctx)
        );

        // keyswitch (small sk)
        let mut switched = LWE::new(
            0,
            ctx.small_lwe_dimension().to_lwe_size(),
            ctx.ciphertext_modulus(),
        );
        keyswitch_lwe_ciphertext(&public_key.lwe_ksk, &mut lwe_rotation_amount, &mut switched);

        // print the noise of the switched
        println!(
            "noise of switched: {}",
            private_key.lwe_noise_small_sk(&switched, rotation_amount, &ctx)
        );

        // blind rotation
        lut.print(&private_key, &ctx);
        let begin = Instant::now();
        blind_rotate_assign(&lwe_rotation_amount, &mut lut.0, &public_key.fourier_bsk);
        let elapsed = Instant::now() - begin;
        println!("rotated ({:?}): ", elapsed);
        lut.print(&private_key, &ctx);

        // extract the sample from the glwe (under big key)
        let mut extracted_lwe = LWE::new(
            0u64,
            ctx.big_lwe_dimension().to_lwe_size(),
            ctx.ciphertext_modulus(),
        );
        extract_lwe_sample_from_glwe_ciphertext(&lut.0, &mut extracted_lwe, MonomialDegree(0));

        let noise = private_key.lwe_noise(&extracted_lwe, rotation_amount, &ctx);
        println!("noise after sample extract: {:.2}", noise);

        let actual = private_key.decrypt_lwe(&extracted_lwe, &ctx);
        let expected = array[rotation_amount as usize];
        println!(" actual: {}, expected: {}", actual, expected);
        // assert_eq!(actual, expected);
    }

    #[test]
    fn test_blind_permutation_sort_itself() {
        let mut ctx = Context::from(PARAM_MESSAGE_2_CARRY_0);
        let private_key = key(PARAM_MESSAGE_2_CARRY_0);
        let public_key = &private_key.public_key;

        for array in (0..4u64).permutations(4) {
            let lut = LUT::from_vec(&array, &private_key, &mut ctx);
            print!("lut: ");
            lut.print(&private_key, &ctx);

            // Define the permutation indices
            let permutation = Vec::from_iter(
                array
                    .iter()
                    .map(|&x| private_key.allocate_and_encrypt_lwe(x, &mut ctx)),
            );

            // Make the permutation
            let begin = Instant::now();
            let permuted = public_key.blind_permutation(&lut, &permutation, &ctx);
            let elapsed = Instant::now() - begin;
            print!("sorted ({:?}): ", elapsed);
            permuted.print(&private_key, &ctx);

            for i in 0..4u64 {
                let lwe = public_key.lut_extract(&permuted, i as usize, &ctx);
                let actual = private_key.decrypt_lwe(&lwe, &ctx);
                assert_eq!(actual, i);
            }
        }
    }

    #[test]
    fn test_blind_argmin_all_distinct() {
        let mut ctx = Context::from(PARAM_MESSAGE_2_CARRY_0);
        let private_key = key(PARAM_MESSAGE_2_CARRY_0);
        let public_key = &private_key.public_key;

        for array in (0..4u64).permutations(4) {
            let lut = LUT::from_vec(&array, &private_key, &mut ctx);
            print!("lut: ");
            lut.print(&private_key, &ctx);

            let begin = Instant::now();
            let actual = public_key.blind_argmin_all_distinct(lut, &ctx);
            let elapsed = Instant::now() - begin;
            let decrypted = private_key.decrypt_lwe(&actual, &ctx);
            println!("actual: {} ({:?}): ", decrypted, elapsed);
            let pos = array
                .iter()
                .enumerate()
                .min_by(|x, y| x.1.cmp(y.1))
                .unwrap()
                .0 as u64;
            assert_eq!(decrypted, pos);
        }
    }

    fn blind_array_add_prop(mut array: Vec<u64>, i: u64, x: u64) -> bool {
        let param = PARAM_MESSAGE_2_CARRY_0;
        let size = param.message_modulus.0;
        let mut ctx = Context::from(param);
        let private_key = key(param);
        let public_key = &private_key.public_key;

        let lwe_i = private_key.allocate_and_encrypt_lwe(i, &mut ctx);
        let lwe_x = private_key.allocate_and_encrypt_lwe(x, &mut ctx);
        let mut lut = LUT::from_vec(&array, &private_key, &mut ctx);

        lut.print(&private_key, &ctx);
        public_key.blind_array_increment(&mut lut, &lwe_i, &lwe_x, &ctx);
        lut.print(&private_key, &ctx);
        array[i as usize] = (array[i as usize] + x) % size as u64;

        (0..array.len()).all(|idx| {
            let lwe = public_key.lut_extract(&lut, idx, &ctx);
            let actual = private_key.decrypt_lwe(&lwe, &ctx);
            println!("{}: {} == {}", idx, actual, array[idx]);
            actual == array[idx]
        })
    }

    #[quickcheck]
    fn test_blind_array_add_quickcheck(mut array: Vec<u64>, i: u64, x: u64) -> TestResult {
        let param = PARAM_MESSAGE_2_CARRY_0;
        let size = param.message_modulus.0;
        if array.len() == 0 {
            return TestResult::discard();
        }
        array.truncate(size);
        array.iter_mut().for_each(|v| *v %= size as u64);
        let i = i % array.len() as u64;
        let x = x % size as u64;
        println!("{} {} {:?}", i, x, array);
        TestResult::from_bool(blind_array_add_prop(array, i, x))
    }

    #[test]
    fn test_lut_from_vec_of_lwe() {
        let mut ctx = Context::from(PARAM_MESSAGE_4_CARRY_0);
        let n = ctx.full_message_modulus();
        let private_key = key(ctx.parameters);
        let public_key = &private_key.public_key;

        let suite = [
            Vec::from_iter(0..n),
            vec![0, 1, 2, 3],
            vec![2, 0, 1, 3, 0, 0, 5],
        ];
        for array in suite {
            let data = Vec::from_iter(
                array
                    .iter()
                    .map(|&i| private_key.allocate_and_encrypt_lwe(i as u64, &mut ctx)),
            );

            let lut = LUT::from_vec_of_lwe(&data, public_key, &ctx);
            // println!("LUT::from_vec_of_lwe({array:?})");
            // lut.print(private_key, &ctx);

            for (i, &expected) in array.iter().enumerate() {
                let actual = private_key.decrypt_lwe(&public_key.lut_extract(&lut, i, &ctx), &ctx);
                assert_eq!(actual, expected as u64);
            }
        }
    }

    #[test]
    fn test_bootstrap_lut() {
        let ctx = Context::from(PARAM_MESSAGE_2_CARRY_0);
        let private_key = key(ctx.parameters);
        let public_key = &private_key.public_key;

        let lut = LUT::from_vec_trivially(&vec![2, 0, 1, 3], &ctx);

        let other = lut.bootstrap_lut(public_key, &ctx);

        for i in 0..ctx.full_message_modulus() {
            let expected = private_key.decrypt_lwe(&public_key.lut_extract(&lut, i, &ctx), &ctx);
            let actual = private_key.decrypt_lwe(&public_key.lut_extract(&other, i, &ctx), &ctx);

            println!("idx: {}, actual: {}, expected: {}", i, actual, expected);
            assert_eq!(actual, expected);
        }
    }

    #[test]
    fn test_glwe_ciphertext_plaintext_mul() {
        let mut ctx = Context::from(PARAM_MESSAGE_2_CARRY_0);
        let private_key = key(ctx.parameters);
        let public_key = &private_key.public_key;
        let plaintext_list =
            PlaintextList::from_container(vec![1_u64 * ctx.delta(); ctx.polynomial_size().0]);
        let glwe = private_key.allocate_and_encrypt_glwe(plaintext_list, &mut ctx);
        private_key.debug_glwe("glwe = ", &glwe, &ctx);
        let constant = 2_u64;
        let res = public_key.glwe_ciphertext_plaintext_mul(&glwe, constant);
        private_key.debug_glwe("res = ", &res, &ctx);
    }
    #[test]
    fn test_glwe_sum_polynomial() {
        let mut ctx = Context::from(PARAM_MESSAGE_2_CARRY_0);
        let private_key = key(ctx.parameters);
        let public_key = &private_key.public_key;

        let glwe = private_key
            .allocate_and_encrypt_glwe_from_vec(&vec![1_u64; ctx.polynomial_size().0], &mut ctx);

        let poly = Polynomial::from_container(vec![2_u64; ctx.polynomial_size().0]);

        println!("poly = {:?}", poly.as_ref().to_vec());

        let result = public_key.glwe_sum_polynomial(&glwe, &poly, &ctx);

        let actual = private_key.decrypt_and_decode_glwe(&result, &ctx);
        let expected = vec![3_u64; ctx.polynomial_size().0];
        assert_eq!(actual, expected);
    }
    #[test]
    fn test_absorption_glwe() {
        let mut ctx = Context::from(PARAM_MESSAGE_2_CARRY_0);
        let private_key = key(ctx.parameters);
        let public_key = &private_key.public_key;

        /* Initialization */
        let vec: Vec<u64> = vec![
            rand::random::<u64>() % ctx.full_message_modulus() as u64;
            ctx.polynomial_size().0
        ];
        let mut glwe = private_key.allocate_and_encrypt_glwe_from_vec(&vec, &mut ctx);

        /* Create a random polynomial */
        let container: Vec<u64> = vec![
            rand::random::<u64>() % ctx.full_message_modulus() as u64;
            ctx.polynomial_size().0
        ];
        let poly = Polynomial::from_container(container);

        /* Absorption */
        let begin = Instant::now();
        let res = public_key.glwe_absorption_polynomial(&mut glwe, &poly);
        let elapsed = Instant::now() - begin;
        println!("absorption ({:?}): ", elapsed);

        /* Decryption */
        let decrypted_res = private_key.decrypt_and_decode_glwe(&res, &ctx);

        /* Verification */
        let poly_in_glwe = Polynomial::from_container(vec);
        let mut expected = Polynomial::new(0_u64, ctx.polynomial_size());
        polynomial_karatsuba_wrapping_mul(&mut expected, &poly_in_glwe, &poly);

        // reduce the result to the message space as in the decryption process
        expected
            .as_mut()
            .iter_mut()
            .for_each(|x| *x %= ctx.full_message_modulus() as u64);

        assert_eq!(expected.as_ref().to_vec(), decrypted_res);
    }

    #[test]
    fn test_absorption_glwe_with_fft() {
        let mut ctx = Context::from(PARAM_MESSAGE_2_CARRY_0);
        let private_key = key(ctx.parameters);
        let public_key = &private_key.public_key;

        /* Initialization */
        let vec: Vec<u64> = vec![
            rand::random::<u64>() % ctx.full_message_modulus() as u64;
            ctx.polynomial_size().0
        ];
        let mut glwe = private_key.allocate_and_encrypt_glwe_from_vec(&vec, &mut ctx);

        /* Create a random polynomial */
        let container: Vec<u64> = vec![
            rand::random::<u64>() % ctx.full_message_modulus() as u64;
            ctx.polynomial_size().0
        ];
        let poly = Polynomial::from_container(container);

        /* Absorption */
        let begin = Instant::now();
        let res = public_key.glwe_absorption_polynomial_with_fft(&mut glwe, &poly);
        let elapsed = Instant::now() - begin;
        println!("absorption ({:?}): ", elapsed);

        /* Decryption */
        let decrypted_res = private_key.decrypt_and_decode_glwe(&res, &ctx);

        /* Verification */
        let poly_in_glwe = Polynomial::from_container(vec);
        let mut expected = Polynomial::new(0_u64, ctx.polynomial_size());
        polynomial_karatsuba_wrapping_mul(&mut expected, &poly_in_glwe, &poly);

        // reduce the result to the message space as in the decryption process
        expected
            .as_mut()
            .iter_mut()
            .for_each(|x| *x %= ctx.full_message_modulus() as u64);

        assert_eq!(expected.as_ref().to_vec(), decrypted_res);
    }

    #[test]
    fn test_bma() {
        let mut ctx = Context::from(PARAM_MESSAGE_4_CARRY_0);
        let private_key = PrivateKey::new(&mut ctx);
        let public_key = &private_key.public_key;

        // // Matrice de test pour la vérification
        // let matrix: Vec<LUT> = vec![
        //     LUT::from_vec(&vec![0, 1, 2, 3], &private_key, &mut ctx),
        //     LUT::from_vec(&vec![1, 2, 3, 0], &private_key, &mut ctx),
        //     LUT::from_vec(&vec![2, 3, 0, 1], &private_key, &mut ctx),
        //     LUT::from_vec(&vec![3, 0, 1, 2], &private_key, &mut ctx),
        // ];

        let n = ctx.full_message_modulus() as u64;
        let mut matrix = Vec::with_capacity(ctx.full_message_modulus());
        for _i in 0..ctx.full_message_modulus() {
            matrix.push(LUT::from_vec(&(0..n).collect(), &private_key, &mut ctx));
        }

        // Ligne et colonne à utiliser pour la vérification
        let line = 0;
        let column = 4;

        // Chiffrer les indices de la colonne et de la ligne
        let lwe_column = private_key.allocate_and_encrypt_lwe(column, &mut ctx);
        let lwe_line = private_key.allocate_and_encrypt_lwe(line, &mut ctx);

        // Appeler la fonction bma
        let start_bma = Instant::now();
        let result = public_key.blind_matrix_access(&matrix, &lwe_line, &lwe_column, &mut ctx);
        let elapsed = Instant::now() - start_bma;
        print!("bma ({:?}): ", elapsed);

        let result_decrypted = private_key.decrypt_lwe(&result, &ctx);
        println!("result_decrypted {}", result_decrypted);
    }

    // FIXME: this test is not working
    #[test]
    fn test_mv() {
        let mut ctx = Context::from(PARAM_MESSAGE_4_CARRY_0);
        let private_key = key(ctx.parameters);
        let public_key = &private_key.public_key;

        let n = ctx.full_message_modulus();
        let matrix = vec![Vec::from_iter(0..n as u64); n];
        for line in &matrix {
            println!("{:?}", line);
        }

        // Appeler la fonction bma_mv
        for lin in 0..n {
            for col in 0..n {
                let lwe_line = private_key.allocate_and_encrypt_lwe(lin as u64, &mut ctx);
                let lwe_column = private_key.allocate_and_encrypt_lwe(col as u64, &mut ctx);
                let start = Instant::now();
                let result =
                    public_key.blind_matrix_access_mv(&matrix, &lwe_line, &lwe_column, &ctx);
                let elapsed = Instant::now() - start;
                let result_decrypted = private_key.decrypt_lwe(&result, &ctx);
                println!(
                    "{}, {}, expected {}, got {} ({:?})",
                    lin,
                    col,
                    matrix[lin][col] % n as u64,
                    result_decrypted,
                    elapsed
                );
                // assert_eq!(result_decrypted, matrix[lin][col] % n as u64);
            }
        }
    }

    #[test]
    fn test_blind_index() {
        let ctx = Context::from(PARAM_MESSAGE_5_CARRY_0);
        let private_key = key(ctx.parameters);
        let public_key = &private_key.public_key;
        let n = ctx.full_message_modulus();

        // let mut total = Duration::default();
        // let mut runs = 0;
        // for array in (0..4u64).permutations(4) {
        let array = Vec::from_iter(0u64..n as u64);
        let lut = LUT::from_vec_trivially(&array, &ctx);
        for needle in 0..4 {
            let x = public_key.allocate_and_trivially_encrypt_lwe(needle, &ctx);

            let begin = Instant::now();
            let i = public_key.blind_index(&lut, &x, &ctx);
            let elapsed = Instant::now() - begin;
            // total += elapsed;
            // runs += 1;

            let expected = array
                .iter()
                .enumerate()
                .find(|&(_, x)| x == &needle)
                .unwrap()
                .0 as u64;
            let actual = private_key.decrypt_lwe(&i, &ctx);

            println!(
                "array: {:?}, needle: {}, actual: {}, expected: {} ({:?})",
                array, needle, actual, expected, elapsed
            );
            assert_eq!(actual, expected);
        }
    }
    // println!("avg time: {:?}", total / runs);
    // }
    #[test]
    fn test_mul_polynomial_with_fft() {
        let ctx = Context::from(PARAM_MESSAGE_4_CARRY_0);

        let fft = Fft::new(ctx.polynomial_size());
        let fft = fft.as_view();

        let n = ctx.polynomial_size().0;

        let mut mem = GlobalPodBuffer::new(
            fft.forward_scratch()
                .unwrap()
                .and(fft.backward_scratch().unwrap()),
        );

        let mut stack = PodStack::new(&mut mem);

        let input1 = Polynomial::from_container({
            (0..n)
                .map(|_| rand::random::<u16>() as u64)
                .collect::<Vec<_>>()
        });
        let input2 = Polynomial::from_container({
            (0..n)
                .map(|_| rand::random::<u16>() as u64)
                .collect::<Vec<_>>()
        });

        let mut actual = Polynomial::new(0u64, PolynomialSize(n));
        //time here
        let start = Instant::now();
        polynomial_fft_wrapping_mul(&mut actual, &input1, &input2, fft, &mut stack);
        let end = Instant::now();
        println!("Time taken fft: {:?}", end.duration_since(start));

        let mut expected = Polynomial::new(0u64, PolynomialSize(n));
        let start = Instant::now();
        polynomial_karatsuba_wrapping_mul(&mut expected, &input1, &input2);
        let end = Instant::now();
        println!("Time taken karatsuba: {:?}", end.duration_since(start));

        assert_eq!(actual, expected);
    }

    #[test]
    fn test_compare_blind_and_public_rotation() {
        let mut ctx = Context::from(PARAM_MESSAGE_6_CARRY_0);
        let private_key = key(ctx.parameters);
        let public_key = &private_key.public_key;

        let mut lut_1 = LUT::from_vec(&vec![0, 1, 2, 3], &private_key, &mut ctx);
        let index_lwe = private_key.allocate_and_encrypt_lwe(3, &mut ctx);
        let start = Instant::now();
        blind_rotate_assign(&index_lwe, &mut lut_1.0, &public_key.fourier_bsk);
        let end = Instant::now();
        println!(
            "Time taken for blind rotation with encrypted index: {:?}",
            end.duration_since(start)
        );
        private_key.debug_glwe("lut after blind rotation = ", &lut_1.0, &ctx);

        let mut lut_2 = LUT::from_vec(&vec![0, 1, 2, 3], &private_key, &mut ctx);
        let index = 3 * ctx.box_size();
        let start = Instant::now();
        lut_2.public_rotate_left(index, public_key);
        let end = Instant::now();
        println!(
            "Time taken for public rotation with trivial index: {:?}",
            end.duration_since(start)
        );
        private_key.debug_glwe("lut after public rotation = ", &lut_2.0, &ctx);

        // conclusion : public rotation is ~200 times faster than blind rotations
    }

    #[test]
    fn test_compare_poly_mul_fft_and_monomial() {
        let ctx = Context::from(PARAM_MESSAGE_2_CARRY_0);

        let n = ctx.polynomial_size().0 as u64;
        let poly1 = Polynomial::from_container((0..n).collect::<Vec<u64>>());
        let index = 1;
        let monomial = Polynomial::from_container(
            (0..n)
                .map(|x| if x == index { 1 } else { 0 })
                .collect::<Vec<u64>>(),
        );

        let (fft, mut mem) = init_fft(ctx.polynomial_size());
        let fft = fft.as_view();
        let mut stack = PodStack::new(&mut mem);

        let mut actual_fft = Polynomial::new(0u64, ctx.polynomial_size());
        let start = Instant::now();
        polynomial_fft_wrapping_mul(&mut actual_fft, &poly1, &monomial, fft, &mut stack);
        let end = Instant::now();
        println!("Time taken fft: {:?}", end.duration_since(start));

        let mut actual_monomial = Polynomial::new(0u64, ctx.polynomial_size());
        let start = Instant::now();
        polynomial_wrapping_monic_monomial_mul(
            &mut actual_monomial,
            &poly1,
            MonomialDegree(index as usize),
        );
        let end = Instant::now();
        println!("Time taken monomial: {:?}", end.duration_since(start));

        // conclusion : monomial is ~two times faster than fft
        assert_eq!(actual_fft, actual_monomial);
    }

    #[test]
    fn test_lwe_noise() {
        let mut ctx = Context::from(PARAM_MESSAGE_4_CARRY_0);
        let private_key = key(ctx.parameters);
        let public_key = &private_key.public_key;
        // let n = ctx.full_message_modulus();

        for _ in 0..8 {
            let mut output = private_key.allocate_and_encrypt_lwe(0, &mut ctx);
            println!("initial noise {}", private_key.lwe_noise(&output, 0, &ctx));

            let zero = private_key.allocate_and_encrypt_lwe(0, &mut ctx);
            for _ in 1..128 {
                lwe_ciphertext_add_assign(&mut output, &zero);
                let decrypted = private_key.decrypt_lwe(&output, &ctx);
                assert_eq!(decrypted, 0);
            }
            let noise = private_key.lwe_noise(&output, 0, &ctx);
            println!("noise after 128 addition {} ({})", noise, 0);

            let identity = LUT::from_function(|x| x, &ctx);
            let bootstrapped = public_key.blind_array_access(&output, &identity, &ctx);
            println!(
                "after bootstrapping noise {}",
                private_key.lwe_noise(&bootstrapped, 0, &ctx)
            );

            println!("=======");
        }
    }
    #[test]
    fn test_pbs_duration() {
        let mut ctx = Context::from(PARAM_MESSAGE_4_CARRY_0);
        let private_key = PrivateKey::new(&mut ctx);
        let public_key = &private_key.public_key;

        let lwe = private_key.allocate_and_encrypt_lwe(1, &mut ctx);
        let lut = LUT::from_vec(
            &Vec::from_iter(0..ctx.message_modulus().0 as u64),
            &private_key,
            &mut ctx,
        );

        let mut total_dur = 0u64;
        let num_trials = 100;

        for _ in 0..num_trials {
            let start = Instant::now();
            public_key.blind_array_access(&lwe, &lut, &ctx);
            let dur = start.elapsed().as_millis() as u64;
            total_dur += dur;
        }

        let avg_dur = total_dur as f64 / num_trials as f64;
        println!("Average time taken for a pbs: {:.2}ms", avg_dur);
    }

    #[test]
    fn test_lut_from_lwe_avg_dur() {
        let mut ctx = Context::from(PARAM_MESSAGE_4_CARRY_0);
        let private_key = key(ctx.parameters);
        let public_key = &private_key.public_key;

        let mut total_dur = 0u64;
        let num_trials = 100;

        for _ in 0..num_trials {
            let lwe = private_key.allocate_and_encrypt_lwe(1, &mut ctx);
            let start = Instant::now();
            let _ = LUT::from_lwe(&lwe, public_key, &ctx);
            let dur = start.elapsed().as_millis() as u64;
            total_dur += dur;
        }

        let avg_dur = total_dur as f64 / num_trials as f64;
        println!("[DEBUG] avg_lut_from_lwe={:.2}ms", avg_dur);
    }

    #[test]
    fn test_lut_from_vec_lwe_avg_dur() {
        let mut ctx = Context::from(PARAM_MESSAGE_4_CARRY_0);
        // let private_key = PrivateKey::new(&mut ctx);
        let private_key = key(ctx.parameters);
        let public_key = &private_key.public_key;

        let mut total_dur = 0u64;
        let num_trials = 100;

        for _ in 0..num_trials {
            let start = Instant::now();
            let lut = LUT::from_vec_of_lwe(
                &Vec::from_iter(0..ctx.message_modulus().0 as u64)
                    .into_iter()
                    .map(|x| private_key.allocate_and_encrypt_lwe(x, &mut ctx))
                    .collect::<Vec<_>>(),
                &public_key,
                &mut ctx,
            );
            let dur = start.elapsed().as_millis() as u64;
            lut.print(private_key, &ctx);
            total_dur += dur;
        }

        let avg_dur = total_dur as f64 / num_trials as f64;
        println!("[DEBUG] avg_lut_from_lwe={:.2}ms", avg_dur);
    }

    #[test]
    fn test_lwe_mul() {
        let mut ctx = Context::from(PARAM_MESSAGE_4_CARRY_0);
        let private_key = key(ctx.parameters);
        let public_key = &private_key.public_key;

        // Test multiplication of two encrypted values
        for i in 0..ctx.full_message_modulus() - 1 {
            for j in 0..ctx.full_message_modulus() - 1 {
                let val1 = i as u64;
                let val2 = j as u64;
                let expected = val1 * val2;

                let lwe1 = private_key.allocate_and_encrypt_lwe(val1, &mut ctx);
                let lwe2 = private_key.allocate_and_encrypt_lwe(val2, &mut ctx);

                let start = Instant::now();
                let result = public_key.lwe_mul(&lwe1, &lwe2, &ctx);
                let end = Instant::now();
                let decrypted = private_key.decrypt_lwe(&result, &ctx);
                println!(
                    "{val1} x {val2} = {decrypted} (Time taken for lwe_mul: {:?})",
                    end.duration_since(start)
                );

                // Decrypt and verify result
                assert_eq!(decrypted, expected % ctx.message_modulus().0 as u64);
            }
        }
    }

    #[test]
    fn test_blind_selection() {
        let mut ctx = Context::from(PARAM_MESSAGE_4_CARRY_0);
        let private_key = key(ctx.parameters);
        let public_key = &private_key.public_key;

        let mut vec_to_select = (0..ctx.message_modulus().0 as u64).collect::<Vec<_>>();
        vec_to_select.shuffle(&mut rand::thread_rng());

        let vec_lwe = vec_to_select
            .iter()
            .map(|x| private_key.allocate_and_encrypt_lwe(*x, &mut ctx))
            .collect::<Vec<_>>();

        for index_to_select in 0..ctx.message_modulus().0 as u64 {
            let mut vec_selector = vec![0u64; ctx.message_modulus().0 as usize];
            vec_selector[index_to_select as usize] = 1;
            let encrypted_selector = vec_selector
                .iter()
                .map(|x| private_key.allocate_and_encrypt_lwe(*x, &mut ctx))
                .collect::<Vec<_>>();

            let selected = public_key.blind_selection(&vec_lwe, &encrypted_selector, &ctx);

            let expected = vec_to_select[index_to_select as usize];

            let actual = private_key.decrypt_lwe(&selected, &ctx);
            println!("expected: {}, actual: {}", expected, actual);
            assert_eq!(actual, expected);
        }
    }

    #[test]
    fn test_private_selection() {
        let mut ctx = Context::from(PARAM_MESSAGE_4_CARRY_0);
        let private_key = key(ctx.parameters);
        let public_key = &private_key.public_key;

        let mut data = (0..ctx.message_modulus().0 as u64).collect::<Vec<_>>();
        data.shuffle(&mut rand::thread_rng());

        for index_to_select in 0..ctx.message_modulus().0 as u64 {
            let mut vec_selector = vec![0u64; ctx.message_modulus().0 as usize];
            vec_selector[index_to_select as usize] = 1;
            let encrypted_selector = vec_selector
                .iter()
                .map(|x| private_key.allocate_and_encrypt_lwe(*x, &mut ctx))
                .collect::<Vec<_>>();

            let selected = public_key.private_selection(&data, &encrypted_selector, &ctx);

            let expected = data[index_to_select as usize];

            let actual = private_key.decrypt_lwe(&selected, &ctx);
            println!("expected: {}, actual: {}", expected, actual);
            assert_eq!(actual, expected);
        }
    }

    #[test]
    fn test_blind_lt_bma_mv() {
        let mut ctx = Context::from(PARAM_MESSAGE_4_CARRY_0);
        let private_key = key(ctx.parameters);
        let public_key = &private_key.public_key;

        for a in 0..ctx.full_message_modulus() - 1 {
            for b in 0..ctx.full_message_modulus() - 1 {
                let lwe_a = private_key.allocate_and_encrypt_lwe(a as u64, &mut ctx);
                let lwe_b = private_key.allocate_and_encrypt_lwe(b as u64, &mut ctx);

                let lwe_bit = public_key.blind_lt_bma_mv(&lwe_a, &lwe_b, &ctx);
                let actual = private_key.decrypt_lwe(&lwe_bit, &ctx);
                println!("a={}, b={}, actual={}", a, b, actual);
                assert_eq!(actual, (a < b) as u64);
            }
        }
    }

    #[test]
    fn test_blind_matrix_add() {
        let mut ctx = Context::from(PARAM_MESSAGE_4_CARRY_0);
        let private_key = key(ctx.parameters);
        let public_key = &private_key.public_key;

        let mut matrix =
            Vec::from_iter((0..16).map(|_| LUT::from_vec(&vec![0; 16], &private_key, &mut ctx)));
        let line = private_key.allocate_and_encrypt_lwe(1, &mut ctx);
        let column = private_key.allocate_and_encrypt_lwe(2, &mut ctx);
        let value = private_key.allocate_and_encrypt_lwe(1, &mut ctx);

        public_key.blind_matrix_add(&mut matrix, &line, &column, &value, &ctx);

        let ciphertext = public_key.blind_matrix_access(&matrix, &line, &column, &ctx);
        let actual = private_key.decrypt_lwe(&ciphertext, &ctx);

        assert_eq!(actual, 1);

        let mut matrix =
            Vec::from_iter((0..16).map(|_| LUT::from_vec(&vec![0; 16], &private_key, &mut ctx)));
        let line = private_key.allocate_and_encrypt_lwe(15, &mut ctx);
        let column = private_key.allocate_and_encrypt_lwe(15, &mut ctx);
        let value = private_key.allocate_and_encrypt_lwe(15, &mut ctx);

        public_key.blind_matrix_add(&mut matrix, &line, &column, &value, &ctx);

        let ciphertext = public_key.blind_matrix_access(&matrix, &line, &column, &ctx);
        let actual = private_key.decrypt_lwe(&ciphertext, &ctx);

        assert_eq!(actual, 15);
    }

    #[test]
    fn test_blind_argmin() {
        let mut ctx = Context::from(PARAM_MESSAGE_4_CARRY_0);
        let private_key = key(ctx.parameters);
        let public_key = &private_key.public_key;

        let vec = vec![3, 2, 3];

        let lwes = vec
            .iter()
            .map(|x| private_key.allocate_and_encrypt_lwe(*x, &mut ctx))
            .collect::<Vec<_>>();

        let argmin = public_key.blind_argmin(&lwes, &ctx);

        let actual = private_key.decrypt_lwe(&argmin, &ctx);
        assert_eq!(actual, 1);

        println!("argmin: {}", actual);
        println!(
            "expected: {}",
            vec.iter()
                .enumerate()
                .min_by_key(|&(_, item)| item)
                .unwrap()
                .0
        );
    }

    #[test]
    fn test_blind_argmax() {
        let mut ctx = Context::from(PARAM_MESSAGE_4_CARRY_0);
        let private_key = key(ctx.parameters);
        let public_key = &private_key.public_key;

        let vec = vec![1, 10, 2];

        let lwes = vec
            .iter()
            .map(|x| private_key.allocate_and_encrypt_lwe(*x, &mut ctx))
            .collect::<Vec<_>>();

        let start = Instant::now();
        let argmax = public_key.blind_argmax(&lwes, &ctx);
        let end = Instant::now();
        println!("time taken: {:?}", end.duration_since(start));
        let actual = private_key.decrypt_lwe(&argmax, &ctx);
        assert_eq!(actual, 1);

        println!("argmax: {}", actual);
        println!(
            "expected: {}",
            vec.iter()
                .enumerate()
                .max_by_key(|&(_, item)| item)
                .unwrap()
                .0
        );
    }

    #[test]
    fn test_blind_count_operation() {
        let mut ctx = Context::from(PARAM_MESSAGE_4_CARRY_0);
        let private_key = key(ctx.parameters);
        let public_key = &private_key.public_key;

        let vec = vec![1, 2, 3, 1, 5];

        let lwes = vec
            .iter()
            .map(|x| private_key.allocate_and_encrypt_lwe(*x, &mut ctx))
            .collect::<Vec<_>>();

        let count = public_key.blind_count(&lwes, &ctx);
        let actual = private_key.decrypt_lwe_vector(&count, &ctx);

        println!("actual: {:?}", actual);

        let mut expected = vec![0; ctx.full_message_modulus()];
        for &val in &vec {
            expected[val as usize] += 1;
        }
        println!("expected: {:?}", expected);
        assert_eq!(actual, expected);
    }

    #[test]
    fn test_blind_majority() {
        let mut ctx = Context::from(PARAM_MESSAGE_4_CARRY_0);
        let private_key = key(ctx.parameters);
        let public_key = &private_key.public_key;
        let vec = vec![1, 3, 2, 2, 1, 3, 1, 2, 3, 2];

        let lwes = vec
            .iter()
            .map(|x| private_key.allocate_and_encrypt_lwe(*x, &mut ctx))
            .collect::<Vec<_>>();

        let start = Instant::now();
        let maj = public_key.blind_majority(&lwes, &ctx);
        let end = Instant::now();
        println!("time taken: {:?}", end.duration_since(start));
        let actual = private_key.decrypt_lwe(&maj, &ctx);
        println!("actual: {}", actual);
        assert_eq!(actual, 2);
    }

    #[test]
    fn test_switch_case3() {
        let mut ctx = Context::from(PARAM_MESSAGE_4_CARRY_0);
        let private_key = key(ctx.parameters);
        let public_key = &private_key.public_key;
        let p = ctx.full_message_modulus() as u64;

        // Identity luts
        let lut1 = LUT::from_vec(&(0..p).collect::<Vec<_>>(), &private_key, &mut ctx);
        // Increment lut
        let lut2 = LUT::from_vec(
            &(0..p).map(|x| (x + 1) % p).collect::<Vec<_>>(),
            &private_key,
            &mut ctx,
        );
        // Decrement lut
        let lut3 = LUT::from_vec(
            &(0..p).map(|x| (x - 1) % p).collect::<Vec<_>>(),
            &private_key,
            &mut ctx,
        );

        // Selectors
        let s1 = private_key.allocate_and_encrypt_lwe(p - 1, &mut ctx);
        let s2 = private_key.allocate_and_encrypt_lwe(1, &mut ctx);

        let res = public_key.switch_case3(&s1, &s2, &vec![lut1, lut2, lut3], &ctx);
        let actual = private_key.decrypt_lwe(&res, &ctx);
        println!("actual: {}", actual);
        // assert_eq!(actual, 2);
    }
}
