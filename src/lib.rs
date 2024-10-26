#[cfg(test)]
extern crate quickcheck;
#[cfg(test)]
#[macro_use(quickcheck)]
extern crate quickcheck_macros;

use aligned_vec::ABox;
use num_complex::Complex;
use rayon::iter::{IntoParallelIterator, ParallelBridge, ParallelExtend, ParallelIterator};
use rayon::ThreadPoolBuilder;
use serde::{Deserialize, Serialize};
use std::fs;
// use std::process::Output;
use std::sync::{Mutex, OnceLock};
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

type LWE = LweCiphertext<Vec<u64>>;

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
            PrivateKey::from_file(&format!("PrivateKey{}", bitsize))
                .unwrap_or(PrivateKey::to_file(&mut Context::from(param)))
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
    signed_decomposer: SignedDecomposer<u64>,
    encryption_generator: EncryptionRandomGenerator<ActivatedRandomGenerator>,
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
    small_lwe_sk: LweSecretKey<Vec<u64>>,
    big_lwe_sk: LweSecretKey<Vec<u64>>,
    glwe_sk: GlweSecretKey<Vec<u64>>,
    pub public_key: PublicKey,
}

impl PrivateKey {
    /// Generate a PrivateKey which contain also the PublicKey
    pub fn new(ctx: &mut Context) -> PrivateKey {
        // Generate an LweSecretKey with binary coefficients
        let small_lwe_sk =
            LweSecretKey::generate_new_binary(ctx.small_lwe_dimension(), &mut ctx.secret_generator);

        // Generate a GlweSecretKey with binary coefficients
        let glwe_sk = GlweSecretKey::generate_new_binary(
            ctx.glwe_dimension(),
            ctx.polynomial_size(),
            &mut ctx.secret_generator,
        );

        // Create a copy of the GlweSecretKey re-interpreted as an LweSecretKey
        let big_lwe_sk = glwe_sk.clone().into_lwe_secret_key();

        // Generate the bootstrapping key, we use the parallel variant for performance reason
        let std_bootstrapping_key = par_allocate_and_generate_new_lwe_bootstrap_key(
            &small_lwe_sk,
            &glwe_sk,
            ctx.pbs_base_log(),
            ctx.pbs_level(),
            ctx.parameters.glwe_noise_distribution,
            ctx.ciphertext_modulus(),
            &mut ctx.encryption_generator,
        );

        // Create the empty bootstrapping key in the Fourier domain
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
        // We don't need the standard bootstrapping key anymore
        drop(std_bootstrapping_key);

        let mut lwe_ksk = LweKeyswitchKey::new(
            0u64,
            ctx.ks_base_log(),
            ctx.ks_level(),
            ctx.big_lwe_dimension(),
            ctx.small_lwe_dimension(),
            ctx.ciphertext_modulus(),
        );

        generate_lwe_keyswitch_key(
            &big_lwe_sk,
            &small_lwe_sk,
            &mut lwe_ksk,
            ctx.parameters.lwe_noise_distribution,
            &mut ctx.encryption_generator,
        );

        // Create Packing Key Switch

        let mut pfpksk = LwePrivateFunctionalPackingKeyswitchKey::new(
            0,
            ctx.pfks_base_log(),
            ctx.pfks_level(),
            ctx.small_lwe_dimension(),
            ctx.glwe_dimension().to_glwe_size(),
            ctx.polynomial_size(),
            ctx.ciphertext_modulus(),
        );

        // Here there is some freedom for the choice of the last polynomial from algorithm 2
        // By convention from the paper the polynomial we use here is the constant -1
        let mut last_polynomial = Polynomial::new(0, ctx.polynomial_size());
        // Set the constant term to u64::MAX == -1i64
        // last_polynomial[0] = u64::MAX;
        last_polynomial[0] = 1_u64;
        // Generate the LWE private functional packing keyswitch key
        par_generate_lwe_private_functional_packing_keyswitch_key(
            &small_lwe_sk,
            &glwe_sk,
            &mut pfpksk,
            ctx.parameters.glwe_noise_distribution,
            &mut ctx.encryption_generator,
            |x| x,
            &last_polynomial,
        );

        let cbs_pfpksk = par_allocate_and_generate_new_circuit_bootstrap_lwe_pfpksk_list(
            &big_lwe_sk,
            &glwe_sk,
            ctx.pfks_base_log(),
            ctx.pfks_level(),
            ctx.parameters.glwe_noise_distribution,
            ctx.ciphertext_modulus(),
            &mut ctx.encryption_generator,
        );

        let public_key = PublicKey {
            lwe_ksk,
            fourier_bsk,
            pfpksk,
            cbs_pfpksk,
        };

        PrivateKey {
            small_lwe_sk,
            big_lwe_sk,
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
    pub fn get_big_lwe_sk(&self) -> &LweSecretKey<Vec<u64>> {
        &self.big_lwe_sk
    }
    pub fn get_glwe_sk(&self) -> &GlweSecretKey<Vec<u64>> {
        &self.glwe_sk
    }
    pub fn get_public_key(&self) -> &PublicKey {
        &self.public_key
    }

    pub fn allocate_and_encrypt_lwe(
        &self,
        input: u64,
        ctx: &mut Context,
    ) -> LweCiphertext<Vec<u64>> {
        let plaintext = Plaintext(ctx.delta().wrapping_mul(input));

        // Allocate a new LweCiphertext and encrypt our plaintext
        let lwe_ciphertext: LweCiphertextOwned<u64> = allocate_and_encrypt_new_lwe_ciphertext(
            &self.small_lwe_sk,
            plaintext,
            ctx.parameters.lwe_noise_distribution,
            ctx.ciphertext_modulus(),
            &mut ctx.encryption_generator,
        );
        lwe_ciphertext
    }

    pub fn allocate_and_encrypt_lwe_big_key(
        &self,
        input: u64,
        ctx: &mut Context,
    ) -> LweCiphertext<Vec<u64>> {
        let plaintext = Plaintext(ctx.delta().wrapping_mul(input));

        // Allocate a new LweCiphertext and encrypt our plaintext
        let lwe_ciphertext: LweCiphertextOwned<u64> = allocate_and_encrypt_new_lwe_ciphertext(
            &self.big_lwe_sk,
            plaintext,
            ctx.parameters.lwe_noise_distribution,
            ctx.ciphertext_modulus(),
            &mut ctx.encryption_generator,
        );
        lwe_ciphertext
    }

    pub fn allocate_and_trivially_encrypt_lwe(
        &self,
        input: u64,
        ctx: &Context,
    ) -> LweCiphertext<Vec<u64>> {
        let plaintext = Plaintext(ctx.delta().wrapping_mul(input));
        // Allocate a new LweCiphertext and encrypt trivially our plaintext
        let lwe_ciphertext: LweCiphertextOwned<u64> =
            allocate_and_trivially_encrypt_new_lwe_ciphertext(
                ctx.small_lwe_dimension().to_lwe_size(),
                plaintext,
                ctx.ciphertext_modulus(),
            );
        lwe_ciphertext
    }

    pub fn decrypt_lwe(&self, ciphertext: &LweCiphertext<Vec<u64>>, ctx: &Context) -> u64 {
        // Decrypt the PBS multiplication result
        let plaintext: Plaintext<u64> = decrypt_lwe_ciphertext(&self.small_lwe_sk, &ciphertext);
        let result: u64 = ctx.signed_decomposer.closest_representable(plaintext.0) / ctx.delta()
            % ctx.full_message_modulus() as u64;
        result
    }

    pub fn decrypt_lwe_big_key(&self, ciphertext: &LweCiphertext<Vec<u64>>, ctx: &Context) -> u64 {
        // Decrypt the PBS multiplication result
        let plaintext: Plaintext<u64> = decrypt_lwe_ciphertext(&self.big_lwe_sk, &ciphertext);
        let result: u64 = ctx.signed_decomposer.closest_representable(plaintext.0) / ctx.delta()
            % ctx.full_message_modulus() as u64;
        result
    }

    pub fn allocate_and_encrypt_glwe(
        &self,
        pt_list: PlaintextList<Vec<u64>>,
        ctx: &mut Context,
    ) -> GlweCiphertext<Vec<u64>> {
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
    ) -> GlweCiphertext<Vec<u64>> {
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
        output_glwe: &mut GlweCiphertext<Vec<u64>>,
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

    pub fn allocate_and_encrypt_glwe_from_vec(
        &self,
        vec: &Vec<u64>,
        ctx: &mut Context,
    ) -> GlweCiphertext<Vec<u64>> {
        let mut encoded_vec: Vec<u64> = vec.iter().map(|x| x * ctx.delta()).collect();
        if encoded_vec.len() < ctx.polynomial_size().0 {
            encoded_vec.resize(ctx.polynomial_size().0, 0_u64);
        }
        let output_glwe =
            self.allocate_and_encrypt_glwe(PlaintextList::from_container(encoded_vec), ctx);
        output_glwe
    }

    pub fn decrypt_and_decode_glwe_as_neg(
        &self,
        input_glwe: &GlweCiphertext<Vec<u64>>,
        ctx: &Context,
    ) -> Vec<u64> {
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

    pub fn decrypt_and_decode_glwe(
        &self,
        input_glwe: &GlweCiphertext<Vec<u64>>,
        ctx: &Context,
    ) -> Vec<u64> {
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

    pub fn debug_lwe(&self, string: &str, ciphertext: &LweCiphertext<Vec<u64>>, ctx: &Context) {
        // Decrypt the PBS multiplication result
        let plaintext: Plaintext<u64> =
            decrypt_lwe_ciphertext(&self.get_small_lwe_sk(), &ciphertext);
        let result: u64 = ctx.signed_decomposer.closest_representable(plaintext.0) / ctx.delta();
        println!("{} {}", string, result);
    }
    pub fn debug_big_lwe(&self, string: &str, ciphertext: &LweCiphertext<Vec<u64>>, ctx: &Context) {
        // Decrypt the PBS multiplication result
        let plaintext: Plaintext<u64> = decrypt_lwe_ciphertext(&self.get_big_lwe_sk(), &ciphertext);
        let result: u64 = ctx.signed_decomposer.closest_representable(plaintext.0) / ctx.delta();
        println!("{} {}", string, result);
    }

    pub fn debug_glwe(&self, string: &str, input_glwe: &GlweCiphertext<Vec<u64>>, ctx: &Context) {
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

    pub fn lwe_noise(
        &self,
        ct: &LweCiphertext<Vec<u64>>,
        expected_plaintext: u64,
        ctx: &Context,
    ) -> f64 {
        // plaintext = b - a*s = Delta*m + e
        let mut plaintext = decrypt_lwe_ciphertext(&self.small_lwe_sk, &ct);

        // plaintext = plaintext - Delta*m = e
        plaintext.0 = plaintext.0.wrapping_sub(ctx.delta() * expected_plaintext);

        ((plaintext.0 as i64).abs() as f64).log2()
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
    pub cbs_pfpksk: LwePrivateFunctionalPackingKeyswitchKeyListOwned<u64>,
}

impl PublicKey {
    pub fn wrapping_neg_lwe(&self, lwe: &mut LweCiphertext<Vec<u64>>) {
        for ai in lwe.as_mut() {
            *ai = (*ai).wrapping_neg();
        }
    }

    pub fn neg_lwe(&self, lwe: &LweCiphertext<Vec<u64>>, ctx: &Context) -> LweCiphertext<Vec<u64>> {
        let mut neg_lwe = LweCiphertext::new(
            0_u64,
            ctx.small_lwe_dimension().to_lwe_size(),
            ctx.ciphertext_modulus(),
        );
        neg_lwe
            .as_mut()
            .iter_mut()
            .zip(lwe.as_ref().iter())
            .for_each(|(dst, &lhs)| *dst = lhs.wrapping_neg());
        return neg_lwe;
    }

    pub fn allocate_and_trivially_encrypt_lwe(
        &self,
        input: u64,
        ctx: &Context,
    ) -> LweCiphertext<Vec<u64>> {
        let plaintext = Plaintext(ctx.delta().wrapping_mul(input));
        // Allocate a new LweCiphertext and encrypt trivially our plaintext
        let lwe_ciphertext: LweCiphertextOwned<u64> =
            allocate_and_trivially_encrypt_new_lwe_ciphertext(
                ctx.small_lwe_dimension().to_lwe_size(),
                plaintext,
                ctx.ciphertext_modulus(),
            );
        lwe_ciphertext
    }

    pub fn allocate_and_trivially_encrypt_glwe(
        &self,
        pt_list: PlaintextList<Vec<u64>>,
        ctx: &Context,
    ) -> GlweCiphertext<Vec<u64>> {
        let mut output_glwe = GlweCiphertext::new(
            0,
            ctx.glwe_dimension().to_glwe_size(),
            ctx.polynomial_size(),
            ctx.ciphertext_modulus(),
        );
        trivially_encrypt_glwe_ciphertext(&mut output_glwe, &pt_list);
        output_glwe
    }

    pub fn leq_scalar(
        &self,
        ct_input: &LweCiphertext<Vec<u64>>,
        scalar: u64,
        ctx: &Context,
    ) -> LweCiphertext<Vec<u64>> {
        let cmp_scalar_accumulator = LUT::from_function(|x| (x <= scalar as u64) as u64, ctx);
        let mut res_cmp = LweCiphertext::new(
            0u64,
            ctx.big_lwe_dimension().to_lwe_size(),
            ctx.ciphertext_modulus(),
        );
        programmable_bootstrap_lwe_ciphertext(
            &ct_input,
            &mut res_cmp,
            &cmp_scalar_accumulator.0,
            &self.fourier_bsk,
        );
        let mut switched = LweCiphertext::new(
            0,
            ctx.small_lwe_dimension().to_lwe_size(),
            ctx.ciphertext_modulus(),
        );
        keyswitch_lwe_ciphertext(&self.lwe_ksk, &mut res_cmp, &mut switched);

        switched
    }

    pub fn geq_scalar(
        &self,
        ct_input: &LweCiphertext<Vec<u64>>,
        scalar: u64,
        ctx: &Context,
    ) -> LweCiphertext<Vec<u64>> {
        let cmp_scalar_accumulator = LUT::from_function(|x| (x >= scalar) as u64, ctx);
        let mut res_cmp = LweCiphertext::new(
            0u64,
            ctx.big_lwe_dimension().to_lwe_size(),
            ctx.ciphertext_modulus(),
        );
        programmable_bootstrap_lwe_ciphertext(
            &ct_input,
            &mut res_cmp,
            &cmp_scalar_accumulator.0,
            &self.fourier_bsk,
        );
        let mut switched = LweCiphertext::new(
            0,
            ctx.small_lwe_dimension().to_lwe_size(),
            ctx.ciphertext_modulus(),
        );
        keyswitch_lwe_ciphertext(&self.lwe_ksk, &mut res_cmp, &mut switched);

        switched
    }

    pub fn eq_scalar(
        &self,
        ct_input: &LweCiphertext<Vec<u64>>,
        scalar: u64,
        ctx: &Context,
    ) -> LweCiphertext<Vec<u64>> {
        let eq_scalar_accumulator = LUT::from_function(|x| (x == scalar as u64) as u64, ctx);
        let mut res_eq = LweCiphertext::new(
            0u64,
            ctx.big_lwe_dimension().to_lwe_size(),
            ctx.ciphertext_modulus(),
        );
        programmable_bootstrap_lwe_ciphertext(
            &ct_input,
            &mut res_eq,
            &eq_scalar_accumulator.0,
            &self.fourier_bsk,
        );
        let mut switched = LweCiphertext::new(
            0,
            ctx.small_lwe_dimension().to_lwe_size(),
            ctx.ciphertext_modulus(),
        );
        keyswitch_lwe_ciphertext(&self.lwe_ksk, &mut res_eq, &mut switched);

        switched
    }

    pub fn one_lwe_to_lwe_ciphertext_list(
        &self,
        input_lwe: &LweCiphertext<Vec<u64>>,
        ctx: &Context,
    ) -> LweCiphertextList<Vec<u64>> {
        let neg_lwe = self.neg_lwe(input_lwe, ctx);
        let redundant_lwe = vec![neg_lwe.into_container(); ctx.box_size()].concat();
        let lwe_ciphertext_list = LweCiphertextList::from_container(
            redundant_lwe,
            ctx.small_lwe_dimension().to_lwe_size(),
            ctx.ciphertext_modulus,
        );

        lwe_ciphertext_list
    }
    pub fn glwe_absorption_monic_monomial(
        &self,
        glwe: &mut GlweCiphertext<Vec<u64>>,
        monomial_degree: MonomialDegree,
    ) {
        let mut glwe_poly_list = glwe.as_mut_polynomial_list();
        for mut glwe_poly in glwe_poly_list.iter_mut() {
            // let glwe_poly_read_only = Polynomial::from_container(glwe_poly.as_ref().to_vec());
            polynomial_wrapping_monic_monomial_mul_assign(&mut glwe_poly, monomial_degree);
        }
    }

    pub fn glwe_absorption_polynomial(
        &self,
        glwe: &GlweCiphertext<Vec<u64>>,
        poly: &Polynomial<Vec<u64>>,
    ) -> GlweCiphertext<Vec<u64>> {
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

    pub fn glwe_absorption_polynomial_with_fft(
        &self,
        glwe: &GlweCiphertext<Vec<u64>>,
        poly: &Polynomial<Vec<u64>>,
    ) -> GlweCiphertext<Vec<u64>> {
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

    pub fn glwe_sum(
        &self,
        ct1: &GlweCiphertext<Vec<u64>>,
        ct2: &GlweCiphertext<Vec<u64>>,
    ) -> GlweCiphertext<Vec<u64>> {
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

    pub fn glwe_sum_assign(
        &self,
        ct1: &mut GlweCiphertext<Vec<u64>>,
        ct2: &GlweCiphertext<Vec<u64>>,
    ) {
        ct1.as_mut()
            .iter_mut()
            .zip(ct2.as_ref().iter())
            .for_each(|(dst, &rhs)| *dst += rhs);
    }

    pub fn glwe_sum_polynomial(
        &self,
        glwe: &GlweCiphertext<Vec<u64>>,
        poly: &Polynomial<Vec<u64>>,
        ctx: &Context,
    ) -> GlweCiphertext<Vec<u64>> {
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

    // TODO : nom a changer : plaintext -> cleartext puisque Plaintext = Plaintext(cleartext)
    pub fn lwe_ciphertext_plaintext_add(
        &self,
        lwe: &LweCiphertext<Vec<u64>>,
        constant: u64,
        ctx: &Context,
    ) -> LweCiphertextOwned<u64> {
        let constant_plain = Plaintext(constant * ctx.delta());

        let constant_lwe = allocate_and_trivially_encrypt_new_lwe_ciphertext(
            ctx.small_lwe_dimension().to_lwe_size(),
            constant_plain,
            ctx.ciphertext_modulus(),
        );
        let mut res = LweCiphertext::new(
            0,
            ctx.small_lwe_dimension().to_lwe_size(),
            ctx.ciphertext_modulus(),
        );

        lwe_ciphertext_add(&mut res, &constant_lwe, lwe);
        return res;
    }

    // TODO : nom a changer : plaintext -> cleartext puisque Plaintext = Plaintext(cleartext)
    pub fn lwe_ciphertext_plaintext_mul(
        &self,
        lwe: &LweCiphertext<Vec<u64>>,
        constant: u64,
        ctx: &Context,
    ) -> LweCiphertext<Vec<u64>> {
        // let constant_plain = Plaintext(constant*ctx.delta());

        // let constant_lwe = allocate_and_trivially_encrypt_new_lwe_ciphertext(ctx.small_lwe_dimension().to_lwe_size(),constant_plain,ctx.ciphertext_modulus());
        let mut res = LweCiphertext::new(
            0,
            ctx.small_lwe_dimension().to_lwe_size(),
            ctx.ciphertext_modulus(),
        );

        lwe_ciphertext_cleartext_mul(&mut res, &lwe, Cleartext(constant));

        return res;
    }

    pub fn glwe_ciphertext_plaintext_mul(
        &self,
        glwe: &GlweCiphertext<Vec<u64>>,
        constant: u64,
    ) -> GlweCiphertext<Vec<u64>> {
        let mut res = GlweCiphertext::new(
            0_u64,
            glwe.glwe_size(),
            glwe.polynomial_size(),
            glwe.ciphertext_modulus(),
        );

        glwe_ciphertext_cleartext_mul(&mut res, &glwe, Cleartext(constant));
        return res;
    }

    // revoLUT operations

    /// Get an element of an `array` given it `index`
    pub fn blind_array_access(
        &self,
        index: &LweCiphertext<Vec<u64>>,
        array: &LUT,
        ctx: &Context,
    ) -> LweCiphertext<Vec<u64>> {
        let mut output = LweCiphertext::new(
            0u64,
            ctx.big_lwe_dimension().to_lwe_size(),
            ctx.ciphertext_modulus(),
        );
        programmable_bootstrap_lwe_ciphertext(&index, &mut output, &array.0, &self.fourier_bsk);
        let mut switched = LweCiphertext::new(
            0_64,
            ctx.small_lwe_dimension().to_lwe_size(),
            ctx.ciphertext_modulus(),
        );
        keyswitch_lwe_ciphertext(&self.lwe_ksk, &output, &mut switched);
        return switched;
    }

    /// Get an element of a `matrix` given it `index_line` and it `index_column`
    pub fn blind_matrix_access(
        &self,
        matrix: &Vec<LUT>,
        line: &LweCiphertext<Vec<u64>>,
        column: &LweCiphertext<Vec<u64>>,
        ctx: &Context,
    ) -> LweCiphertext<Vec<u64>> {
        // multi blind array access
        let vec_of_lwe: Vec<LweCiphertext<Vec<u64>>> = matrix
            .into_par_iter()
            .map(|lut| self.blind_array_access(column, lut, ctx))
            .collect();

        // pack all the lwe
        let accumulator_final = LUT::from_vec_of_lwe(&vec_of_lwe, self, &ctx);

        // final blind array access
        self.blind_array_access(&line, &accumulator_final, ctx)
    }

    // Prototype not working as expected (the result is 2 times the expected result)
    pub fn blind_matrix_access_multi_values_opt(
        &self,
        matrix: &Vec<Vec<u64>>,
        lwe_line: LweCiphertext<Vec<u64>>,
        lwe_column: LweCiphertext<Vec<u64>>,
        ctx: &mut Context,
    ) -> LweCiphertext<Vec<u64>> {
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
        let mut matrix_in_poly_form: Vec<Polynomial<Vec<u64>>> = Vec::new();
        for l in matrix.iter() {
            let vec_l_with_redundancy: Vec<u64> = LUT::add_redundancy_many_u64(l, ctx);
            matrix_in_poly_form.push(Polynomial::from_container(vec_l_with_redundancy));
        }

        // Multiplier chaque ligne de la matrice par le polynôme lhs
        let mut new_matrix: Vec<Polynomial<Vec<u64>>> = Vec::new();
        for p in matrix_in_poly_form.iter() {
            let mut res_mul = Polynomial::new(0_u64, ctx.polynomial_size());
            polynomial_karatsuba_wrapping_mul(&mut res_mul, &lhs, &p);
            new_matrix.push(res_mul);
        }

        // Préparer la LUT pour la rotation aveugle
        let mut only_lut_to_rotate = LUT(glwe_rhs);
        let start_bma_mv = Instant::now();
        blind_rotate_assign(&lwe_column, &mut only_lut_to_rotate.0, &self.fourier_bsk);

        // Appliquer l'absorption GLWE pour chaque ligne de la nouvelle matrice
        let mut columns_lwe: Vec<LweCiphertext<Vec<u64>>> = Vec::new();
        for line in new_matrix.iter() {
            let lut = LUT(self.glwe_absorption_polynomial(&mut only_lut_to_rotate.0, line));
            let ct = self.sample_extract(&lut, 0, ctx);
            columns_lwe.push(ct);
        }

        // Packer les LUTs
        let lut_col = LUT::from_vec_of_lwe(&columns_lwe, self, ctx);

        // Effectuer une rotation aveugle sur la LUT colonne
        let result = self.blind_array_access(&lwe_line, &lut_col, ctx);
        let elapsed = Instant::now() - start_bma_mv;
        print!("bma_mv ({:?}): ", elapsed);

        return result;
    }

    /// Insert an `element` in a `lut` at `index` and return the modified lut (très très sensible et pas très robuste...)
    pub fn blind_insertion(
        &self,
        lut: LUT,
        index: LweCiphertext<Vec<u64>>,
        element: &LweCiphertext<Vec<u64>>,
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
        let mut new_index: Vec<LweCiphertext<Vec<u64>>> = Vec::new();
        for original_index in 0..many_lut.len() {
            let mut ct_cp = self.leq_scalar(&index, original_index as u64, &ctx);
            lwe_ciphertext_plaintext_add_assign(
                &mut ct_cp,
                Plaintext((original_index as u64) * ctx.delta()),
            );
            private_key.debug_lwe("ct_cp", &ct_cp, &ctx);
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
    pub fn blind_permutation(
        &self,
        lut: LUT,
        permutation: Vec<LweCiphertext<Vec<u64>>>,
        ctx: &Context,
    ) -> LUT {
        let mut many_lut = lut.to_many_lut(&self, &ctx);
        // Multi Blind Rotate
        for (lut, p) in many_lut.iter_mut().zip(permutation.iter()) {
            let neg_p = self.neg_lwe(&p, &ctx);
            blind_rotate_assign(&neg_p, &mut lut.0, &self.fourier_bsk);
        }
        // Sum all the rotated lut to get the final lut permuted
        let mut result_glwe = many_lut[0].0.clone();
        for i in 1..many_lut.len() {
            result_glwe = self.glwe_sum(&result_glwe, &many_lut[i].0);
        }

        LUT(result_glwe)
    }

    pub fn blind_kmin(&self, lut: LUT, ctx: &Context, k: usize) -> LweCiphertext<Vec<u64>> {
        let n = ctx.full_message_modulus() as u64;
        let id = LUT::from_vec_trivially(&Vec::from_iter(0..n), ctx); // should be cached
        let permutation = lut.to_many_lwe(&self, ctx);
        let indices = self.blind_permutation(id, permutation, ctx);
        self.sample_extract(&indices, k, ctx)
    }

    pub fn blind_private_kmin(
        &self,
        lut: LUT,
        ctx: &Context,
        k: LweCiphertext<Vec<u64>>,
    ) -> LweCiphertext<Vec<u64>> {
        let n = ctx.full_message_modulus() as u64;
        let id = LUT::from_vec_trivially(&Vec::from_iter(0..n), ctx); // should be cached
        let permutation = lut.to_many_lwe(&self, ctx);
        let indices = self.blind_permutation(id, permutation, ctx);
        self.blind_array_access(&k, &indices, ctx)
    }

    pub fn blind_argmin(&self, lut: LUT, ctx: &Context) -> LweCiphertext<Vec<u64>> {
        self.blind_kmin(lut, ctx, 0)
    }

    pub fn blind_argmax(&self, lut: LUT, ctx: &Context) -> LweCiphertext<Vec<u64>> {
        self.blind_kmin(lut, ctx, ctx.full_message_modulus() - 1)
    }

    // Retrieve an element from a `lut` given it `index` and return the retrieved element with the new lut
    pub fn blind_retrieve(
        &self,
        lut: &mut LUT,
        index_retrieve: LweCiphertext<Vec<u64>>,
        ctx: &Context,
    ) -> (LweCiphertext<Vec<u64>>, LUT) {
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
        let mut new_index: Vec<LweCiphertext<Vec<u64>>> = Vec::new();
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

    /// Pop and udpate the `lut_stack`
    pub fn blind_pop(&self, lut_stack: &mut LUTStack, ctx: &Context) -> LweCiphertext<Vec<u64>> {
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

    pub fn blind_push(
        &self,
        lut_stack: &mut LUTStack,
        lwe_push: &LweCiphertext<Vec<u64>>,
        ctx: &Context,
    ) {
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

    /// Get an element of a `tensor` given its `index_line` and its `index_column` ( the tensor must be encoded with encode_tensor_into_matrix)
    pub fn blind_tensor_access(
        &self,
        ct_tensor: &Vec<LUT>,
        index_line: &LweCiphertext<Vec<u64>>,
        index_column: &LweCiphertext<Vec<u64>>,
        nb_of_channels: usize,
        ctx: &Context,
    ) -> Vec<LweCiphertext<Vec<u64>>> {
        let mut pbs_results: Vec<LweCiphertext<Vec<u64>>> = Vec::new();
        pbs_results.par_extend(ct_tensor.into_par_iter().map(|acc| {
            let mut pbs_ct = LweCiphertext::new(
                0u64,
                ctx.big_lwe_dimension().to_lwe_size(),
                ctx.ciphertext_modulus(),
            );
            programmable_bootstrap_lwe_ciphertext(
                &index_column,
                &mut pbs_ct,
                &acc.0,
                &self.fourier_bsk,
            );
            let mut switched = LweCiphertext::new(
                0,
                ctx.small_lwe_dimension().to_lwe_size(),
                ctx.ciphertext_modulus(),
            );
            keyswitch_lwe_ciphertext(&self.lwe_ksk, &mut pbs_ct, &mut switched);
            switched
        }));

        let mut lut_column = LUT::from_vec_of_lwe(&pbs_results, self, &ctx);

        let index_line_encoded =
            self.lwe_ciphertext_plaintext_mul(&index_line, nb_of_channels as u64, &ctx); // line = line * nb_of_channel
        let index_line_encoded = self.lwe_ciphertext_plaintext_add(
            &index_line_encoded,
            ctx.full_message_modulus() as u64,
            &ctx,
        ); // line = msg_mod + line \in [16,32] for 4_0

        blind_rotate_assign(&index_line_encoded, &mut lut_column.0, &self.fourier_bsk);

        let mut outputs_channels: Vec<LweCiphertext<Vec<u64>>> = Vec::new();
        for channel in 0..nb_of_channels {
            let mut ct_res = LweCiphertext::new(
                0u64,
                ctx.big_lwe_dimension().to_lwe_size(),
                ctx.ciphertext_modulus(),
            );
            extract_lwe_sample_from_glwe_ciphertext(
                &lut_column.0,
                &mut ct_res,
                MonomialDegree(0 + channel * ctx.box_size() as usize),
            );
            let mut switched = LweCiphertext::new(
                0,
                ctx.small_lwe_dimension().to_lwe_size(),
                ctx.ciphertext_modulus(),
            );
            keyswitch_lwe_ciphertext(&self.lwe_ksk, &mut ct_res, &mut switched);
            outputs_channels.push(switched);
        }

        outputs_channels
    }

    fn allocate_and_keyswitch_lwe_ciphertext(
        &self,
        mut lwe: LweCiphertext<Vec<u64>>,
        ctx: &Context,
    ) -> LweCiphertext<Vec<u64>> {
        let mut switched = LweCiphertext::new(
            0,
            ctx.parameters.lwe_dimension.to_lwe_size(),
            ctx.ciphertext_modulus,
        );
        keyswitch_lwe_ciphertext(&self.lwe_ksk, &mut lwe, &mut switched);

        switched
    }

    /// returns the ciphertext at index i from the given lut, accounting for redundancy
    pub fn sample_extract(&self, lut: &LUT, i: usize, ctx: &Context) -> LweCiphertext<Vec<u64>> {
        let mut lwe = LweCiphertext::new(
            0u64,
            ctx.big_lwe_dimension.to_lwe_size(),
            ctx.ciphertext_modulus,
        );
        extract_lwe_sample_from_glwe_ciphertext(&lut.0, &mut lwe, MonomialDegree(i * ctx.box_size));
        self.allocate_and_keyswitch_lwe_ciphertext(lwe, ctx)
    }

    /* Sample extract in glwe without the redundancy */
    pub fn sample_extract_in_glwe(
        &self,
        glwe: &GlweCiphertext<Vec<u64>>,
        i: usize,
        ctx: &Context,
    ) -> LweCiphertext<Vec<u64>> {
        let mut lwe = LweCiphertext::new(
            0u64,
            ctx.big_lwe_dimension.to_lwe_size(),
            ctx.ciphertext_modulus,
        );
        extract_lwe_sample_from_glwe_ciphertext(&glwe, &mut lwe, MonomialDegree(i));

        self.allocate_and_keyswitch_lwe_ciphertext(lwe, ctx)
    }

    /// run f(ct_input), assuming lut was constructed with LUT::from_function(f)
    pub fn run_lut(
        &self,
        ct_input: &LweCiphertext<Vec<u64>>,
        lut: &LUT,
        ctx: &Context,
    ) -> LweCiphertext<Vec<u64>> {
        let mut lwe = LweCiphertext::new(
            0u64,
            ctx.big_lwe_dimension.to_lwe_size(),
            ctx.ciphertext_modulus,
        );
        programmable_bootstrap_lwe_ciphertext(&ct_input, &mut lwe, &lut.0, &self.fourier_bsk);
        self.allocate_and_keyswitch_lwe_ciphertext(lwe, ctx)
    }

    /// blindly adds x to the i-th box of the given LUT
    /// this process is noisy and the LUT needs bootstrapping before being read
    pub fn blind_array_inject(
        &self,
        lut: &mut LUT,
        i: &LweCiphertext<Vec<u64>>,
        x: &LweCiphertext<Vec<u64>>,
        ctx: &Context,
    ) {
        let mut other = LUT::from_lwe(&x, &self, ctx);
        let neg_i = self.neg_lwe(i, ctx);
        blind_rotate_assign(&neg_i, &mut other.0, &self.fourier_bsk);
        self.glwe_sum_assign(&mut lut.0, &other.0);
    }

    pub fn blind_array_inject_clear_index(
        &self,
        lut: &mut LUT,
        i: usize,
        x: &LweCiphertext<Vec<u64>>,
        ctx: &Context,
    ) {
        let mut other = LUT::from_lwe(&x, &self, ctx);
        let index = i * ctx.box_size();
        other.public_rotate_right(index, &self);
        self.glwe_sum_assign(&mut lut.0, &other.0);
    }

    pub fn blind_array_inject_trivial_lut(
        &self,
        lut: &mut LUT,
        i: &LweCiphertext<Vec<u64>>,
        x: u64,
        ctx: &Context,
    ) {
        let mut other = LUT::from_vec_trivially(&vec![x], ctx);
        let neg_i = self.neg_lwe(i, ctx);
        blind_rotate_assign(&neg_i, &mut other.0, &self.fourier_bsk);
        self.glwe_sum_assign(&mut lut.0, &other.0);
    }

    // retrieves the encrypted index of the first occurence of x in the given lut
    pub fn blind_index(
        &self,
        lut: &LUT,
        x: &LweCiphertext<Vec<u64>>,
        ctx: &Context,
    ) -> LweCiphertext<Vec<u64>> {
        let n = ctx.full_message_modulus();
        let mut i = self.allocate_and_trivially_encrypt_lwe(0, ctx);
        let mut f = self.allocate_and_trivially_encrypt_lwe(0, ctx);
        let iszero = LUT::from_vec_trivially(&vec![1], ctx);
        for j in 0..n {
            // sample extract
            let e = self.sample_extract(&lut, j, ctx);

            // z = (x == e)
            let mut z = self.allocate_and_trivially_encrypt_lwe(0u64, ctx);
            lwe_ciphertext_sub(&mut z, &x, &e);
            z = self.run_lut(&z, &iszero, ctx);

            // z = 1 if x == e else 0

            // i = f ? j : i
            // i += (z and not f) * j
            // i += (1 - f + z) * j
            let mut acc = self.allocate_and_trivially_encrypt_lwe(1, ctx);
            lwe_ciphertext_sub_assign(&mut acc, &f);
            lwe_ciphertext_add_assign(&mut acc, &z);
            let jifzandnotf = LUT::from_vec_trivially(&vec![0, 0, j as u64], &ctx);
            let maybej = self.run_lut(&acc, &jifzandnotf, &ctx);
            lwe_ciphertext_add_assign(&mut i, &maybej);

            // f |= z
            lwe_ciphertext_add_assign(&mut z, &f);
            z = self.run_lut(&z, &iszero, ctx);
            f = self.allocate_and_trivially_encrypt_lwe(1u64, ctx);
            lwe_ciphertext_sub_assign(&mut f, &z);
        }

        i
    }

    pub fn blind_topk(&self, lwes: &[LWE], k: usize, ctx: &Context) -> Vec<LWE> {
        println!("new round of top{k} with {} elements", lwes.len());
        if lwes.len() <= k {
            return lwes.to_vec();
        }
        let n = ctx.full_message_modulus();
        assert!(k < n);
        let chunk_number = lwes.len().div_ceil(n);
        let mut result = vec![];
        for (i, chunk) in lwes.chunks(n).enumerate() {
            print!(
                "top{k} of chunk ({}/{}) of len {}: ",
                i + 1,
                chunk_number,
                chunk.len()
            );
            assert!(chunk.len() <= n);
            let lut = LUT::from_vec_of_lwe(chunk, self, ctx);
            let start = Instant::now();
            let sorted_lut = self.blind_counting_sort_k(&lut, ctx, chunk.len());
            println!("{:?}", Instant::now() - start);
            result
                .extend((0..k.min(chunk.len())).map(|i| self.sample_extract(&sorted_lut, i, ctx)));
        }
        assert!(result.len() < lwes.len());
        // tournament style
        self.blind_topk(&result, k, ctx)
    }

    // TODO : a generalisé pour m vecteurs de lwe (pour l'instant m=2)
    pub fn blind_topk_many_lut(
        &self,
        many_lwes: &Vec<Vec<LWE>>, // slice of slices
        k: usize,
        ctx: &Context,
    ) -> Vec<Vec<LWE>> {
        println!("new round of top{k} with {} elements", many_lwes[0].len());
        if many_lwes[0].len() <= k {
            return many_lwes.to_vec();
        }
        let n = ctx.full_message_modulus();
        assert!(k < n);
        // let chunk_number = many_lwes[0].len().div_ceil(n);
        let mut result1 = vec![];
        let mut result2 = vec![];
        let mut result = vec![];
        for (i, (chunk1, chunk2)) in many_lwes[0]
            .chunks(n)
            .zip(many_lwes[1].chunks(n))
            .enumerate()
        {
            // print!(
            //     "top{k} of chunk ({}/{}) of len {}: ",
            //     i + 1,
            //     chunk_number,
            //     chunk1.len()
            // );
            assert!(chunk1.len() <= n);
            let lut_to_sort = LUT::from_vec_of_lwe(chunk1, self, ctx);
            let lut_other = LUT::from_vec_of_lwe(chunk2, self, ctx);
            let luts = vec![&lut_to_sort, &lut_other];
            // let start = Instant::now();
            let sorted_luts = self.many_blind_counting_sort_k(&luts, ctx, chunk1.len());
            // println!("{:?}", Instant::now() - start);
            result1.extend(
                (0..k.min(chunk1.len())).map(|i| self.sample_extract(&sorted_luts[0], i, ctx)),
            );
            result2.extend(
                (0..k.min(chunk2.len())).map(|i| self.sample_extract(&sorted_luts[1], i, ctx)),
            );
        }
        result.push(result1);
        result.push(result2);
        assert!(result.len() < many_lwes[0].len());
        // tournament style
        self.blind_topk_many_lut(&result, k, ctx)
    }

    pub fn blind_topk_many_lut_par(
        &self,
        many_lwes: &Vec<Vec<LWE>>, // slice of slices
        k: usize,
        ctx: &Context,
    ) -> Vec<Vec<LWE>> {
        // Créez un pool de threads avec 4 threads
        let pool = ThreadPoolBuilder::new().num_threads(4).build().unwrap();

        // println!("new round of top{k} with {} elements", many_lwes[0].len());
        if many_lwes[0].len() <= k {
            return many_lwes.to_vec();
        }
        let n = ctx.full_message_modulus();
        assert!(k < n);

        // Utilisez Mutex pour permettre un accès concurrent sécurisé aux résultats
        let result1 = Mutex::new(vec![]);
        let result2 = Mutex::new(vec![]);

        // Utilisez le pool de threads pour paralléliser l'itération
        pool.scope(|s| {
            s.spawn(|_| {
                many_lwes[0]
                    .chunks(n)
                    .zip(many_lwes[1].chunks(n))
                    .enumerate()
                    .par_bridge()
                    .for_each(|(_, (chunk1, chunk2))| {
                        assert!(chunk1.len() <= n);
                        let lut_to_sort = LUT::from_vec_of_lwe(chunk1, self, ctx);
                        let lut_other = LUT::from_vec_of_lwe(chunk2, self, ctx);
                        let luts = vec![&lut_to_sort, &lut_other];
                        // let start = Instant::now();
                        let sorted_luts = self.many_blind_counting_sort_k(
                            &luts,
                            ctx,
                            chunk1.len().min(chunk2.len()),
                        );
                        // println!("{:?}", Instant::now() - start);

                        // Ajoutez les résultats dans les vecteurs protégés
                        let mut res1 = result1.lock().unwrap();
                        res1.extend(
                            (0..k.min(chunk1.len()))
                                .map(|i| self.sample_extract(&sorted_luts[0], i, ctx)),
                        );

                        let mut res2 = result2.lock().unwrap();
                        res2.extend(
                            (0..k.min(chunk2.len()))
                                .map(|i| self.sample_extract(&sorted_luts[1], i, ctx)),
                        );
                    });
            });
        });

        let result = vec![result1.into_inner().unwrap(), result2.into_inner().unwrap()];
        assert!(result.len() < many_lwes[0].len());

        // Appel récursif en style tournoi
        self.blind_topk_many_lut(&result, k, ctx)
    }
}

pub struct LUT(pub GlweCiphertext<Vec<u64>>);

impl Clone for LUT {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

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

    pub fn clone(&self) -> LUT {
        LUT(self.0.clone())
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

    fn add_redundancy_many_lwe(many_lwe: &[LWE], ctx: &Context) -> Vec<LWE> {
        let box_size = ctx.box_size();
        // Create the vector of redundancy
        many_lwe
            .iter()
            .flat_map(|lwe| std::iter::repeat(lwe.clone()).take(box_size))
            .collect()
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
        let number_of_lwe_samples = many_lwe.len();
        if number_of_lwe_samples > ctx.full_message_modulus() as usize {
            panic!(
                "Number of LWE samples are more than the full message modulus, it cannot be packed into one LUT"
            );
        }
        let redundant_many_lwe = Self::add_redundancy_many_lwe(many_lwe, &ctx);
        let mut lwe_container: Vec<u64> = Vec::new();
        for ct in redundant_many_lwe {
            let mut lwe = ct.into_container();
            lwe_container.append(&mut lwe);
        }

        let lwe_ciphertext_list = LweCiphertextList::from_container(
            lwe_container,
            ctx.small_lwe_dimension().to_lwe_size(),
            ctx.ciphertext_modulus(),
        );

        // Prepare our output GLWE in which we pack our LWEs
        let mut glwe = GlweCiphertext::new(
            0,
            ctx.glwe_dimension().to_glwe_size(),
            ctx.polynomial_size(),
            ctx.ciphertext_modulus(),
        );

        // Keyswitch and pack
        par_private_functional_keyswitch_lwe_ciphertext_list_and_pack_in_glwe_ciphertext(
            &public_key.pfpksk,
            &mut glwe,
            &lwe_ciphertext_list,
        );

        let poly_monomial_degree = MonomialDegree(2 * ctx.polynomial_size().0 - ctx.box_size() / 2);
        public_key.glwe_absorption_monic_monomial(&mut glwe, poly_monomial_degree);

        LUT(glwe)
    }

    fn add_redundancy_many_lwe_with_padding(
        many_lwe: Vec<LweCiphertext<Vec<u64>>>,
        public_key: &PublicKey,
        ctx: &Context,
    ) -> Vec<LweCiphertext<Vec<u64>>> {
        let box_size = ctx.polynomial_size().0 / ctx.full_message_modulus();
        // Create the vector which will contain the redundant lwe
        let mut redundant_many_lwe: Vec<LweCiphertext<Vec<u64>>> = Vec::new();
        let ct_0 = LweCiphertext::new(
            0_64,
            ctx.small_lwe_dimension().to_lwe_size(),
            ctx.ciphertext_modulus(),
        );

        let size_many_lwe = many_lwe.len();
        // Fill each box with the encoded denoised value
        for i in 0..size_many_lwe {
            let index = i * box_size;
            for _j in index..index + box_size {
                redundant_many_lwe.push(many_lwe[i].clone());
            }
        }

        let half_box_size = box_size / 2;

        // Negate the first half_box_size coefficients to manage negacyclicity and rotate
        for a_i in redundant_many_lwe[0..half_box_size].iter_mut() {
            public_key.wrapping_neg_lwe(a_i);
        }
        redundant_many_lwe.resize(ctx.full_message_modulus() * box_size, ct_0);
        redundant_many_lwe.rotate_left(half_box_size);
        redundant_many_lwe
    }

    pub fn from_vec_of_lwe_with_padding(
        many_lwe: Vec<LweCiphertext<Vec<u64>>>,
        public_key: &PublicKey,
        ctx: &Context,
    ) -> LUT {
        let many_lwe_as_accumulator =
            Self::add_redundancy_many_lwe_with_padding(many_lwe, public_key, ctx);
        let mut lwe_container: Vec<u64> = Vec::new();
        for ct in many_lwe_as_accumulator {
            let mut lwe = ct.into_container();
            lwe_container.append(&mut lwe);
        }
        let lwe_ciphertext_list = LweCiphertextList::from_container(
            lwe_container,
            ctx.small_lwe_dimension().to_lwe_size(),
            ctx.ciphertext_modulus(),
        );

        // Prepare our output GLWE in which we pack our LWEs
        let mut glwe = GlweCiphertext::new(
            0,
            ctx.glwe_dimension().to_glwe_size(),
            ctx.polynomial_size(),
            ctx.ciphertext_modulus(),
        );

        // Keyswitch and pack
        par_private_functional_keyswitch_lwe_ciphertext_list_and_pack_in_glwe_ciphertext(
            &public_key.pfpksk,
            &mut glwe,
            &lwe_ciphertext_list,
        );
        LUT(glwe)
    }

    /// creates a LUT whose first box is filled with copies of the given lwe
    pub fn from_lwe(lwe: &LweCiphertext<Vec<u64>>, public_key: &PublicKey, ctx: &Context) -> LUT {
        let mut output = GlweCiphertext::new(
            0,
            ctx.glwe_dimension().to_glwe_size(),
            ctx.polynomial_size(),
            ctx.ciphertext_modulus(),
        );
        par_private_functional_keyswitch_lwe_ciphertext_into_glwe_ciphertext(
            &public_key.pfpksk,
            &mut output,
            &lwe,
        );

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
    pub fn to_many_lwe(
        &self,
        public_key: &PublicKey,
        ctx: &Context,
    ) -> Vec<LweCiphertext<Vec<u64>>> {
        (0..ctx.full_message_modulus())
            .map(|i| public_key.sample_extract(&self, i, ctx))
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
        let box_size = ctx.polynomial_size().0 / ctx.message_modulus().0;

        // let half_box_size = box_size / 2;

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
            extract_lwe_sample_from_glwe_ciphertext(&self.0, &mut ct_big, MonomialDegree(index));
            input_vec.push(private_key.decrypt_lwe_big_key(&ct_big, &ctx));
        }
        println!("{:?}", input_vec);
    }

    // TODO : check if this is correct
    pub fn to_array(&self, private_key: &PrivateKey, ctx: &Context) -> Vec<u64> {
        let mut result_insert: Vec<LweCiphertext<Vec<u64>>> = Vec::new();
        result_insert.par_extend((0..ctx.full_message_modulus()).into_par_iter().map(|i| {
            let mut lwe_sample = LweCiphertext::new(
                0_64,
                ctx.big_lwe_dimension().to_lwe_size(),
                ctx.ciphertext_modulus(),
            );
            extract_lwe_sample_from_glwe_ciphertext(
                &self.0,
                &mut lwe_sample,
                MonomialDegree((i * ctx.box_size()) as usize),
            );
            let mut switched = LweCiphertext::new(
                0,
                ctx.small_lwe_dimension().to_lwe_size(),
                ctx.ciphertext_modulus(),
            );
            keyswitch_lwe_ciphertext(
                &private_key.public_key.lwe_ksk,
                &mut lwe_sample,
                &mut switched,
            );
            switched
        }));

        let mut result_retrieve_u64: Vec<u64> = Vec::new();
        for lwe in result_insert {
            let pt = private_key.decrypt_lwe(&lwe, &ctx);
            result_retrieve_u64.push(pt);
        }

        result_retrieve_u64
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
    pub fn bootstrap(&self, public_key: &PublicKey, ctx: &Context) -> LUT {
        let many_lwe = self.to_many_lwe(public_key, ctx);
        LUT::from_vec_of_lwe(&many_lwe, public_key, ctx)
    }
}

pub struct LUTStack {
    pub lut: LUT,
    pub number_of_elements: LweCiphertext<Vec<u64>>,
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
            ctx.small_lwe_dimension().to_lwe_size(),
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
            let mut lwe_sample = LweCiphertext::new(
                0_64,
                ctx.big_lwe_dimension().to_lwe_size(),
                ctx.ciphertext_modulus(),
            );
            extract_lwe_sample_from_glwe_ciphertext(
                &lut.0,
                &mut lwe_sample,
                MonomialDegree(i * ctx.box_size() as usize),
            );
            let mut switched = LweCiphertext::new(
                0,
                ctx.small_lwe_dimension().to_lwe_size(),
                ctx.ciphertext_modulus(),
            );
            keyswitch_lwe_ciphertext(&public_key.lwe_ksk, &mut lwe_sample, &mut switched);

            let cp = public_key.eq_scalar(&switched, 0, &ctx);

            lwe_ciphertext_sub_assign(&mut number_of_elements, &cp);
        }

        LUTStack {
            lut: lut,
            number_of_elements: number_of_elements,
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
            input_vec.push(private_key.decrypt_lwe_big_key(&ct_big, &ctx));
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
    use std::time::Instant;

    use itertools::Itertools;
    use quickcheck::TestResult;
    use tfhe::shortint::parameters::*;

    use super::*;

    #[test]
    fn test_lwe_enc() {
        let mut ctx = Context::from(PARAM_MESSAGE_4_CARRY_0);
        let private_key = key(PARAM_MESSAGE_4_CARRY_0);
        let input: u64 = 1;
        let lwe = private_key.allocate_and_encrypt_lwe(input, &mut ctx);
        let clear = private_key.decrypt_lwe(&lwe, &mut ctx);
        println!("Test encryption-decryption");
        assert_eq!(input, clear);
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
    fn test_many_lwe_to_glwe() {
        let mut ctx = Context::from(PARAM_MESSAGE_2_CARRY_0);
        let private_key = PrivateKey::new(&mut ctx);
        let public_key = &private_key.public_key;
        let our_input: Vec<u64> = vec![0, 1, 2, 3];
        let mut many_lwe: Vec<LweCiphertext<Vec<u64>>> = vec![];
        for input in our_input {
            let lwe = private_key.allocate_and_encrypt_lwe(input, &mut ctx);
            many_lwe.push(lwe);
        }
        // for lwe in many_lwe.clone() {
        //     private_key.debug_lwe("ct", &lwe, &ctx);
        // }
        let lut = LUT::from_vec_of_lwe(&many_lwe, public_key, &ctx);
        let output_pt = private_key.decrypt_and_decode_glwe(&lut.0, &ctx);
        println!("Test many LWE to one GLWE");
        println!("{:?}", output_pt);
    }

    #[test]
    fn test_pack_many_lwe() {
        let mut ctx = Context::from(PARAM_MESSAGE_2_CARRY_0);
        let private_key = PrivateKey::new(&mut ctx);
        let public_key = &private_key.public_key;
        let our_input: Vec<u64> = vec![0, 1, 2, 3];
        let mut many_lwe: Vec<LweCiphertext<Vec<u64>>> = vec![];
        for input in our_input {
            let lwe = private_key.allocate_and_encrypt_lwe(input, &mut ctx);
            many_lwe.push(lwe);
        }
        let mut glwe = GlweCiphertext::new(
            0,
            ctx.glwe_dimension().to_glwe_size(),
            ctx.polynomial_size(),
            ctx.ciphertext_modulus(),
        );

        let mut lwe_list = LweCiphertextList::new(
            0_u64,
            ctx.small_lwe_dimension().to_lwe_size(),
            LweCiphertextCount(many_lwe.len()),
            ctx.ciphertext_modulus(),
        );
        for (mut dst, src) in lwe_list.iter_mut().zip(many_lwe.iter()) {
            dst.as_mut().copy_from_slice(src.as_ref());
        }

        par_private_functional_keyswitch_lwe_ciphertext_list_and_pack_in_glwe_ciphertext(
            &public_key.pfpksk,
            &mut glwe,
            &lwe_list,
        );
        let output_pt = private_key.decrypt_and_decode_glwe(&glwe, &ctx);
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
            println!("Time taken to create LUT: {:?}", elapsed);
            for j in 0..16u64 {
                let output = public_key.sample_extract(&lut, j as usize, &ctx);
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
    fn test_at(mut array: Vec<u64>, i: usize) -> TestResult {
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
        let lwe = public_key.sample_extract(&lut, i, &ctx);
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
        let permuted = public_key.blind_permutation(lut, permutation, &ctx);
        let elapsed = Instant::now() - begin;

        print!("sorted ({:?}): ", elapsed);
        permuted.print(&private_key, &ctx);
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
            let permuted = public_key.blind_permutation(lut, permutation, &ctx);
            let elapsed = Instant::now() - begin;
            print!("sorted ({:?}): ", elapsed);
            permuted.print(&private_key, &ctx);

            for i in 0..4u64 {
                let lwe = public_key.sample_extract(&permuted, i as usize, &ctx);
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
            let actual = public_key.blind_argmin(lut, &ctx);
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
        public_key.blind_array_inject(&mut lut, &lwe_i, &lwe_x, &ctx);
        lut.print(&private_key, &ctx);
        array[i as usize] = (array[i as usize] + x) % size as u64;

        (0..array.len()).all(|idx| {
            let lwe = public_key.sample_extract(&lut, idx, &ctx);
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
        let mut ctx = Context::from(PARAM_MESSAGE_2_CARRY_0);
        let private_key = key(ctx.parameters);
        let public_key = &private_key.public_key;

        let expected = 1;
        let data = vec![private_key.allocate_and_encrypt_lwe(expected, &mut ctx)];
        // Vec::from_iter((0..4).map(|i| private_key.allocate_and_encrypt_lwe(i, &mut ctx)));

        let lut = LUT::from_vec_of_lwe(&data, public_key, &ctx);
        private_key.debug_glwe("lut", &lut.0, &ctx);
        let lwe = public_key.sample_extract(&lut, 0, &ctx);
        let actual = private_key.decrypt_lwe(&lwe, &ctx);
        assert_eq!(actual, expected);

        // for i in 0..4 {
        //     let actual = private_key.decrypt_lwe(&public_key.sample_extract(&lut, i, &ctx), &ctx);
        //     println!("{}", i);
        //     assert_eq!(actual, i as u64);
        // }
    }

    #[test]
    fn test_bootstrap() {
        let ctx = Context::from(PARAM_MESSAGE_2_CARRY_0);
        let private_key = key(ctx.parameters);
        let public_key = &private_key.public_key;

        let lut = LUT::from_vec_trivially(&vec![2, 0, 1, 3], &ctx);

        let other = lut.bootstrap(public_key, &ctx);

        for i in 0..ctx.full_message_modulus() {
            let expected = private_key.decrypt_lwe(&public_key.sample_extract(&lut, i, &ctx), &ctx);
            let actual = private_key.decrypt_lwe(&public_key.sample_extract(&other, i, &ctx), &ctx);

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

    #[test]
    fn test_mv() {
        let mut ctx = Context::from(PARAM_MESSAGE_4_CARRY_0);
        let private_key = PrivateKey::new(&mut ctx);
        let public_key = &private_key.public_key;

        let p = ctx.full_message_modulus() as u64;

        // Matrice de test pour la vérification
        // let matrix: Vec<Vec<u64>> = vec![
        //     vec![0, 1, 2, 3],
        //     vec![1, 2, 3, 0],
        //     vec![2, 3, 0, 1],
        //     vec![3, 0, 1, 2],
        // ];

        let n = ctx.full_message_modulus() as u64;
        let mut matrix: Vec<Vec<u64>> = Vec::with_capacity(ctx.full_message_modulus());
        for _i in 0..ctx.full_message_modulus() {
            matrix.push((0..n).collect());
        }

        // Ligne et colonne à utiliser pour la vérification
        let line = 0;
        let column = 0;

        // Chiffrer les indices de la colonne et de la ligne
        let lwe_column = private_key.allocate_and_encrypt_lwe(column, &mut ctx);
        let lwe_line = private_key.allocate_and_encrypt_lwe(line, &mut ctx);

        // Appeler la fonction bma_mv
        let result = public_key
            .blind_matrix_access_multi_values_opt(&matrix, lwe_line, lwe_column, &mut ctx);

        let result_decrypted = private_key.decrypt_lwe(&result, &ctx);
        println!(
            "expected : {}, got : {}, ",
            2 * (matrix[line as usize][column as usize]) % p,
            result_decrypted
        );
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
    fn test_blind_array_inject_polynomial() {
        let mut ctx = Context::from(PARAM_MESSAGE_2_CARRY_0);
        let private_key = key(PARAM_MESSAGE_2_CARRY_0);
        let public_key = &private_key.public_key;

        // Initialiser une LUT avec des valeurs connues
        let initial_values = vec![0, 0, 0, 0];
        let mut lut = LUT::from_vec(&initial_values, &private_key, &mut ctx);

        // Chiffrer une valeur à injecter
        let value_to_inject = 1;
        let lwe_value = private_key.allocate_and_encrypt_lwe(value_to_inject, &mut ctx);

        // Indice où injecter la valeur
        let index_to_inject = 3;

        // Appeler la fonction à tester
        public_key.blind_array_inject_clear_index(&mut lut, index_to_inject, &lwe_value, &ctx);

        // Déchiffrer la LUT pour vérifier l'injection
        let decrypted_values: Vec<u64> = (0..ctx.full_message_modulus())
            .map(|i| {
                let lwe = public_key.sample_extract(&lut, i, &ctx);
                private_key.decrypt_lwe(&lwe, &ctx)
            })
            .collect();

        // Vérifier que la valeur a été correctement injectée
        assert_eq!(decrypted_values[index_to_inject as usize], value_to_inject);
        // Vérifier que les autres valeurs n'ont pas été modifiées
        for (i, &value) in decrypted_values.iter().enumerate() {
            if i != index_to_inject as usize {
                assert_eq!(value, initial_values[i]);
            }
        }
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
        // TODO : check if this is correct
        assert_eq!(actual_fft, actual_monomial);
    }

    #[test]
    pub fn test_blind_topk() {
        let param = PARAM_MESSAGE_4_CARRY_0;
        let mut ctx = Context::from(param);
        let private_key = key(ctx.parameters);
        let public_key = &private_key.public_key;

        let mut array = vec![10u64; 269];
        array[1] = 1;
        array[100] = 2;
        array[150] = 3;
        array[200] = 4;

        println!("{:?}", array);

        let lwes: Vec<LWE> = array
            .iter()
            .map(|i| private_key.allocate_and_encrypt_lwe(*i, &mut ctx))
            .collect();

        let start = Instant::now();
        let res = public_key.blind_topk(&lwes, 3, &ctx);
        println!("total time: {:?}", Instant::now() - start);

        for lwe in res {
            println!("{}", private_key.decrypt_lwe(&lwe, &ctx));
        }
    }

    #[test]
    pub fn test_blind_topk_many_lut() {
        let param = PARAM_MESSAGE_4_CARRY_0;
        let mut ctx = Context::from(param);
        let private_key = key(ctx.parameters);
        let public_key = &private_key.public_key;

        let mut array = vec![10u64; 269];
        array[1] = 1;
        array[10] = 2;
        array[15] = 3;
        array[20] = 4;

        let lwes1: Vec<LWE> = array
            .iter()
            .map(|i| private_key.allocate_and_encrypt_lwe(*i, &mut ctx))
            .collect();

        let lwes2: Vec<LWE> = (0..array.len() - 1)
            .map(|i| private_key.allocate_and_encrypt_lwe(i as u64, &mut ctx))
            .collect();

        let many_lwes = vec![lwes1, lwes2];

        let start = Instant::now();
        let res = public_key.blind_topk_many_lut_par(&many_lwes, 3, &ctx);
        println!("total time: {:?}", Instant::now() - start);

        for vec_lwe in res {
            println!("vec_lwe");
            for lwe in vec_lwe {
                println!("{}", private_key.decrypt_lwe(&lwe, &ctx));
            }
        }
    }
}
