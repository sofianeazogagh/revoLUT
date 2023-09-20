use std::time::Instant;

use aligned_vec::ABox;
use num_complex::Complex;
use rayon::prelude::*;
use tfhe::{core_crypto::prelude::*, core_crypto::prelude::polynomial_algorithms::*};
// use tfhe::core_crypto::prelude::polynomial_algorithms::polynomial_wrapping_monic_monomial_mul_assign;
use tfhe::shortint::{prelude::*, prelude::CiphertextModulus};
use tfhe::shortint::parameters::ClassicPBSParameters;

pub struct Context{
    parameters : ClassicPBSParameters,
    big_lwe_dimension : LweDimension,
    delta : u64,
    full_message_modulus : usize,
    signed_decomposer : SignedDecomposer<u64>,
    encryption_generator : EncryptionRandomGenerator<ActivatedRandomGenerator>,
    secret_generator : SecretRandomGenerator<ActivatedRandomGenerator>,
    box_size : usize,
    ciphertext_modulus:CiphertextModulus,
}

impl Context {
        pub fn from(parameters: ClassicPBSParameters) -> Context {
            let big_lwe_dimension = LweDimension(parameters.polynomial_size.0 * parameters.glwe_dimension.0);
            let full_message_modulus = parameters.message_modulus.0 * parameters.carry_modulus.0;
            let delta = (1u64 << 63) / (full_message_modulus) as u64;

            let signed_decomposer = SignedDecomposer::new(DecompositionBaseLog(full_message_modulus.ilog2() as usize + 1), DecompositionLevelCount(1)); // a changer peut-être pour les autres params

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
                ciphertext_modulus
            }
        }

        // getters for each (private) parameters
        pub fn small_lwe_dimension(&self) -> LweDimension { self.parameters.lwe_dimension }
        pub fn big_lwe_dimension(&self) -> LweDimension { self.big_lwe_dimension }
        pub fn glwe_dimension(&self) -> GlweDimension { self.parameters.glwe_dimension }
        pub fn polynomial_size(&self) -> PolynomialSize { self.parameters.polynomial_size }
        pub fn lwe_modular_std_dev(&self) -> StandardDev { self.parameters.lwe_modular_std_dev }
        pub fn glwe_modular_std_dev(&self) -> StandardDev { self.parameters.glwe_modular_std_dev }
        pub fn pbs_base_log(&self) -> DecompositionBaseLog { self.parameters.pbs_base_log }
        pub fn pbs_level(&self) -> DecompositionLevelCount { self.parameters.pbs_level }
        pub fn ks_level(&self) -> DecompositionLevelCount { self.parameters.ks_level }
        pub fn ks_base_log(&self) -> DecompositionBaseLog { self.parameters.ks_base_log }
        pub fn pfks_level(&self) -> DecompositionLevelCount { self.parameters.pbs_level }
        pub fn pfks_base_log(&self) -> DecompositionBaseLog { self.parameters.pbs_base_log }
        pub fn pfks_modular_std_dev(&self) -> StandardDev { self.parameters.glwe_modular_std_dev }
        pub fn message_modulus(&self) -> MessageModulus { self.parameters.message_modulus }
        pub fn carry_modulus(&self) -> CarryModulus { self.parameters.carry_modulus }
        pub fn delta(&self) -> u64 { self.delta }
        pub fn full_message_modulus(&self) -> usize { self.full_message_modulus }
        pub fn box_size(&self) -> usize { self.box_size }
        pub fn ciphertext_modulus(&self) -> CiphertextModulus { self.ciphertext_modulus }
        pub fn cbs_level(&self) -> DecompositionLevelCount { self.parameters.ks_level }
        pub fn cbs_base_log(&self) -> DecompositionBaseLog { self.parameters.ks_base_log }
        // pub fn signed_decomposer(&self) -> SignedDecomposer<u64> {self.signed_decomposer}
    }

    pub struct PrivateKey {
        small_lwe_sk: LweSecretKey<Vec<u64>>,
        big_lwe_sk: LweSecretKey<Vec<u64>>,
        glwe_sk: GlweSecretKey<Vec<u64>>,
        pub public_key: PublicKey,
    }

    impl PrivateKey {
        /// Generate a PrivateKey which contain also the PublicKey
        ///
        /// # Example
        ///
        /// ```rust
        /// // Generate the keys and get them in different variables:
        /// let mut ctx = Context::new(PARAM_MESSAGE_2_CARRY_2)
        /// let private_key = PrivateKey::new(&ctx);
        /// ```
        ///
        pub fn new(ctx: &mut Context) -> PrivateKey {


            // Generate an LweSecretKey with binary coefficients
            let small_lwe_sk =
                LweSecretKey::generate_new_binary(ctx.small_lwe_dimension(), &mut ctx.secret_generator);

            // Generate a GlweSecretKey with binary coefficients
            let glwe_sk =
                GlweSecretKey::generate_new_binary(ctx.glwe_dimension(), ctx.polynomial_size(), &mut ctx.secret_generator);

            // Create a copy of the GlweSecretKey re-interpreted as an LweSecretKey
            let big_lwe_sk = glwe_sk.clone().into_lwe_secret_key();

            // Generate the bootstrapping key, we use the parallel variant for performance reason
            let std_bootstrapping_key = par_allocate_and_generate_new_lwe_bootstrap_key(
                &small_lwe_sk,
                &glwe_sk,
                ctx.pbs_base_log(),
                ctx.pbs_level(),
                ctx.glwe_modular_std_dev(),
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
                ctx.ciphertext_modulus()
            );

            generate_lwe_keyswitch_key(
                &big_lwe_sk,
                &small_lwe_sk,
                &mut lwe_ksk,
                ctx.lwe_modular_std_dev(),
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
                ctx.ciphertext_modulus()
            );

            // Here there is some freedom for the choice of the last polynomial from algorithm 2
            // By convention from the paper the polynomial we use here is the constant -1
            let mut last_polynomial = Polynomial::new(0, ctx.polynomial_size());
            // Set the constant term to u64::MAX == -1i64
            last_polynomial[0] = u64::MAX;
            // Generate the LWE private functional packing keyswitch key
            par_generate_lwe_private_functional_packing_keyswitch_key(
                &small_lwe_sk,
                &glwe_sk,
                &mut pfpksk,
                ctx.pfks_modular_std_dev(),
                &mut ctx.encryption_generator,
                |x| x,
                &last_polynomial,
            );

            let cbs_pfpksk = par_allocate_and_generate_new_circuit_bootstrap_lwe_pfpksk_list(
                &big_lwe_sk,
                &glwe_sk,
                ctx.pfks_base_log(),
                ctx.pfks_level(),
                ctx.pfks_modular_std_dev(),
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
                public_key
            }
        }

        // getters for each attribute
        pub fn get_small_lwe_sk(&self) -> &LweSecretKey<Vec<u64>> { &self.small_lwe_sk }
        pub fn get_big_lwe_sk(&self) -> &LweSecretKey<Vec<u64>> { &self.big_lwe_sk }
        pub fn get_glwe_sk(&self) -> &GlweSecretKey<Vec<u64>> { &self.glwe_sk }
        pub fn get_public_key(&self) -> &PublicKey { &self.public_key }


        pub fn allocate_and_encrypt_lwe(&self, input: u64, ctx: &mut Context) -> LweCiphertext<Vec<u64>> {
            let plaintext = Plaintext(ctx.delta().wrapping_mul(input));

            // Allocate a new LweCiphertext and encrypt our plaintext
            let lwe_ciphertext: LweCiphertextOwned<u64> = allocate_and_encrypt_new_lwe_ciphertext(
                &self.small_lwe_sk,
                plaintext,
                ctx.lwe_modular_std_dev(),
                ctx.ciphertext_modulus(),
                &mut ctx.encryption_generator,
            );
            lwe_ciphertext
        }

        pub fn allocate_and_encrypt_lwe_big_key(&self, input: u64, ctx: &mut Context) -> LweCiphertext<Vec<u64>> {
            let plaintext = Plaintext(ctx.delta().wrapping_mul(input));

            // Allocate a new LweCiphertext and encrypt our plaintext
            let lwe_ciphertext: LweCiphertextOwned<u64> = allocate_and_encrypt_new_lwe_ciphertext(
                &self.big_lwe_sk,
                plaintext,
                ctx.lwe_modular_std_dev(),
                ctx.ciphertext_modulus(),
                &mut ctx.encryption_generator,
            );
            lwe_ciphertext
        }

        pub fn allocate_and_trivially_encrypt_lwe(&self, input: u64, ctx: &Context) -> LweCiphertext<Vec<u64>> {
            let plaintext = Plaintext(ctx.delta().wrapping_mul(input));
            // Allocate a new LweCiphertext and encrypt trivially our plaintext
            let lwe_ciphertext: LweCiphertextOwned<u64> = allocate_and_trivially_encrypt_new_lwe_ciphertext(
                ctx.small_lwe_dimension().to_lwe_size(),
                plaintext,
                ctx.ciphertext_modulus()
            );
            lwe_ciphertext
        }

        pub fn decrypt_lwe(&self, ciphertext: &LweCiphertext<Vec<u64>>, ctx: &Context) -> u64 {
            // Decrypt the PBS multiplication result
            let plaintext: Plaintext<u64> =
                decrypt_lwe_ciphertext(&self.small_lwe_sk, &ciphertext);
            let result: u64 =
                ctx.signed_decomposer.closest_representable(plaintext.0) / ctx.delta() % ctx.full_message_modulus() as u64;
            result
        }

        pub fn decrypt_lwe_big_key(&self, ciphertext: &LweCiphertext<Vec<u64>>, ctx: &Context) -> u64 {
            // Decrypt the PBS multiplication result
            let plaintext: Plaintext<u64> =
                decrypt_lwe_ciphertext(&self.big_lwe_sk, &ciphertext);
            let result: u64 =
                ctx.signed_decomposer.closest_representable(plaintext.0) / ctx.delta() % ctx.full_message_modulus() as u64;
            result
        }

        pub fn allocate_and_encrypt_glwe(&self, pt_list: PlaintextList<Vec<u64>>, ctx: &mut Context) -> GlweCiphertext<Vec<u64>> {
            let mut output_glwe = GlweCiphertext::new(0, ctx.glwe_dimension().to_glwe_size(), ctx.polynomial_size(), ctx.ciphertext_modulus()
            );
            encrypt_glwe_ciphertext(
                self.get_glwe_sk(),
                &mut output_glwe,
                &pt_list,
                ctx.glwe_modular_std_dev(),
                &mut ctx.encryption_generator,
            );
            output_glwe
        }

        pub fn encrypt_glwe(&self, output_glwe: &mut GlweCiphertext<Vec<u64>>, pt: PlaintextList<Vec<u64>>, ctx: &mut Context) {
            encrypt_glwe_ciphertext(
                self.get_glwe_sk(),
                output_glwe,
                &pt,
                ctx.glwe_modular_std_dev(),
                &mut ctx.encryption_generator,
            );
        }

        pub fn decrypt_and_decode_glwe_as_neg(&self, input_glwe: &GlweCiphertext<Vec<u64>>, ctx: &Context) -> Vec<u64> {
            let mut plaintext_res = PlaintextList::new(0, PlaintextCount(ctx.polynomial_size().0));
            decrypt_glwe_ciphertext(&self.get_glwe_sk(), &input_glwe, &mut plaintext_res);

            // To round our 4 bits of message
            // In the paper we return the complicated sum times -1, so here we invert that -1, otherwise we
            // could apply the wrapping_neg on our function and remove it here
            let decoded: Vec<_> = plaintext_res
                .iter()
                .map(|x| (ctx.signed_decomposer.closest_representable(*x.0) / ctx.delta()).wrapping_neg() % ctx.full_message_modulus() as u64)
                .collect();

            decoded
        }

        pub fn decrypt_and_decode_glwe(&self, input_glwe: &GlweCiphertext<Vec<u64>>, ctx: &Context) -> Vec<u64> {
            let mut plaintext_res = PlaintextList::new(0, PlaintextCount(ctx.polynomial_size().0));
            decrypt_glwe_ciphertext(&self.get_glwe_sk(), &input_glwe, &mut plaintext_res);

            // To round our 4 bits of message
            // In the paper we return the complicated sum times -1, so here we invert that -1, otherwise we
            // could apply the wrapping_neg on our function and remove it here
            let decoded: Vec<_> = plaintext_res
                .iter()
                .map(|x| (ctx.signed_decomposer.closest_representable(*x.0) / ctx.delta()) % ctx.full_message_modulus() as u64)
                .collect();

            decoded
        }

        pub fn decrypt_ggsw(&self, input_ggsw: &GgswCiphertext<Vec<u64>>, private_key: &PrivateKey) -> u64 {
            let plain = decrypt_constant_ggsw_ciphertext(&private_key.get_glwe_sk(), &input_ggsw);
            plain.0
        }

        pub fn debug_lwe(&self, string: &str, ciphertext: &LweCiphertext<Vec<u64>>, ctx: &Context) {
            // Decrypt the PBS multiplication result
            let plaintext: Plaintext<u64> =
                decrypt_lwe_ciphertext(&self.get_small_lwe_sk(), &ciphertext);
            let result: u64 =
                ctx.signed_decomposer.closest_representable(plaintext.0) / ctx.delta();
            println!("{} {}", string, result);
        }


        pub fn debug_glwe(&self, string: &str, input_glwe: &GlweCiphertext<Vec<u64>>, ctx: &Context) {
            let mut plaintext_res = PlaintextList::new(0, PlaintextCount(ctx.polynomial_size().0));
            decrypt_glwe_ciphertext(&self.get_glwe_sk(), &input_glwe, &mut plaintext_res);

            // To round our 4 bits of message
            // In the paper we return the complicated sum times -1, so here we invert that -1, otherwise we
            // could apply the wrapping_neg on our function and remove it here
            let decoded: Vec<_> = plaintext_res
                .iter()
                .map(|x| (ctx.signed_decomposer.closest_representable(*x.0) / ctx.delta()).wrapping_neg() % ctx.full_message_modulus() as u64)
                .collect();

            println!("{} {:?}", string, decoded);
        }
    }

    pub struct PublicKey { // utilKey ou ServerKey ou CloudKey
    pub lwe_ksk: LweKeyswitchKey<Vec<u64>>,
        pub fourier_bsk: FourierLweBootstrapKey<ABox<[Complex<f64>]>>,
        pub pfpksk: LwePrivateFunctionalPackingKeyswitchKey<Vec<u64>>,
        pub cbs_pfpksk:LwePrivateFunctionalPackingKeyswitchKeyListOwned<u64>,
    }



    impl PublicKey{

        pub fn wrapping_neg_lwe(&self, 
                                lwe : &mut LweCiphertext<Vec<u64>>,)
        {
            for ai in lwe.as_mut(){
                *ai = (*ai).wrapping_neg();
            }
        }

        pub fn neg_lwe(&self, 
                    lwe : &LweCiphertext<Vec<u64>>, 
                    ctx : &Context
        ) -> LweCiphertext<Vec<u64>>
        {
            let mut neg_lwe = LweCiphertext::new(0_u64 , ctx.small_lwe_dimension().to_lwe_size(),ctx.ciphertext_modulus());
            neg_lwe.as_mut().iter_mut()
                .zip(
                    lwe.as_ref().iter()
                ).for_each(|(dst, &lhs)| *dst = lhs.wrapping_neg());
            return neg_lwe;
        }

        pub fn allocate_and_trivially_encrypt_lwe(&self, input : u64, ctx: &Context) -> LweCiphertext<Vec<u64>>{
            let plaintext = Plaintext(ctx.delta().wrapping_mul(input));
            // Allocate a new LweCiphertext and encrypt trivially our plaintext
            let lwe_ciphertext: LweCiphertextOwned<u64> = allocate_and_trivially_encrypt_new_lwe_ciphertext(
                ctx.small_lwe_dimension().to_lwe_size(),
                plaintext,
                ctx.ciphertext_modulus()
            );
            lwe_ciphertext
        }

        pub fn leq_scalar(&self,
                          ct_input: &LweCiphertext<Vec<u64>>,
                          scalar : u64,
                          ctx : &Context
        ) -> LweCiphertext<Vec<u64>>
        {

            let cmp_scalar_accumulator = LUT::from_function(|x| (x <= scalar as u64) as u64, ctx);
            let mut res_cmp = LweCiphertext::new(0u64, ctx.big_lwe_dimension().to_lwe_size(),ctx.ciphertext_modulus());
            programmable_bootstrap_lwe_ciphertext(
                &ct_input,
                &mut res_cmp,
                &cmp_scalar_accumulator.0,
                &self.fourier_bsk,
            );
            let mut switched = LweCiphertext::new(0, ctx.small_lwe_dimension().to_lwe_size(),ctx.ciphertext_modulus()
            );
            keyswitch_lwe_ciphertext(&self.lwe_ksk, &mut res_cmp, &mut switched);

            switched
        }

        pub fn eq_scalar(&self,
                         ct_input: &LweCiphertext<Vec<u64>>,
                         scalar : u64,
                         ctx : &Context
        )-> LweCiphertext<Vec<u64>>
        {

            let eq_scalar_accumulator = LUT::from_function(|x| ( x == scalar as u64) as u64, ctx);
            let mut res_eq = LweCiphertext::new(0u64, ctx.big_lwe_dimension().to_lwe_size(),ctx.ciphertext_modulus());
            programmable_bootstrap_lwe_ciphertext(
                &ct_input,
                &mut res_eq,
                &eq_scalar_accumulator.0,
                &self.fourier_bsk,
            );
            let mut switched = LweCiphertext::new(0, ctx.small_lwe_dimension().to_lwe_size(),ctx.ciphertext_modulus());
            keyswitch_lwe_ciphertext(&self.lwe_ksk, &mut res_eq, &mut switched);

            switched
        }



        pub fn one_lwe_to_lwe_ciphertext_list(&self,
                                              input_lwe: LweCiphertext<Vec<u64>>,
                                              ctx : &Context
        )-> LweCiphertextList<Vec<u64>>
        {

            let redundant_lwe = vec![input_lwe.into_container();ctx.box_size()].concat();
            let lwe_ciphertext_list =  LweCiphertextList::from_container(redundant_lwe, ctx.small_lwe_dimension().to_lwe_size(), ctx.ciphertext_modulus);


            lwe_ciphertext_list
        }
        pub fn glwe_absorption_monic_monomial(&self,
                                              glwe : &mut GlweCiphertext<Vec<u64>>,
                                              monomial_degree : MonomialDegree,
        )
        {
            let mut glwe_poly_list = glwe.as_mut_polynomial_list();
            for mut glwe_poly in glwe_poly_list.iter_mut(){
                // let glwe_poly_read_only = Polynomial::from_container(glwe_poly.as_ref().to_vec());
                polynomial_wrapping_monic_monomial_mul_assign(&mut glwe_poly, monomial_degree);
            }
        }
        pub fn glwe_sum(&self,
                        ct1 : &GlweCiphertext<Vec<u64>>,
                        ct2 : &GlweCiphertext<Vec<u64>>,
        )-> GlweCiphertext<Vec<u64>>
        {
            let mut res = GlweCiphertext::new(0_u64, ct1.glwe_size(), ct1.polynomial_size(),ct1.ciphertext_modulus());

            res.as_mut().iter_mut()
                .zip(
                    ct1.as_ref().iter().zip(ct2.as_ref().iter())
                ).for_each(|(dst, (&lhs, &rhs))| *dst = lhs.wrapping_add(rhs));
            return res;
        }


        pub fn glwe_sum_assign(&self, 
                            ct1: &mut GlweCiphertext<Vec<u64>>, 
                            ct2: &GlweCiphertext<Vec<u64>>
        )
        {
            ct1.as_mut().iter_mut()
                .zip(ct2.as_ref().iter())
                .for_each(|(dst, &rhs)| *dst += rhs);
        }


        pub fn lwe_ciphertext_plaintext_add(&self, lwe: &LweCiphertext<Vec<u64>>, constant: u64, ctx:&Context) -> LweCiphertextOwned<u64> {

            let constant_plain = Plaintext(constant*ctx.delta());
        
            let constant_lwe = allocate_and_trivially_encrypt_new_lwe_ciphertext(ctx.small_lwe_dimension().to_lwe_size(),constant_plain,ctx.ciphertext_modulus());
            let mut res = LweCiphertext::new(0,ctx.small_lwe_dimension().to_lwe_size(),ctx.ciphertext_modulus());
        
            lwe_ciphertext_add(&mut res,&constant_lwe,lwe);
            return res
        }



       
        // revoLUT operations

        /// Get an element of an `array` given it `index`
        pub fn blind_array_access(&self, index : &LweCiphertext<Vec<u64>>, array : &LUT, ctx : &Context )-> LweCiphertext<Vec<u64>>
        {
            let mut output = LweCiphertext::new(0u64, ctx.small_lwe_dimension().to_lwe_size(),ctx.ciphertext_modulus());
            programmable_bootstrap_lwe_ciphertext(&index, &mut output, &array.0, &self.fourier_bsk,);
            return output
        }

        /// Get an element of a `matrix` given it `index_line` and it `index_column`
        pub fn blind_matrix_access(&self, matrix : &Vec<LUT>, index_line : &LweCiphertext<Vec<u64>>, index_column : &LweCiphertext<Vec<u64>>, ctx : &Context)-> LweCiphertext<Vec<u64>>
        {
            let mut output = LweCiphertext::new(0u64, ctx.small_lwe_dimension().to_lwe_size(),ctx.ciphertext_modulus());

            // multi blind array access 
            let mut pbs_results: Vec<LweCiphertext<Vec<u64>>> = Vec::new();
            pbs_results.par_extend(
            matrix
                .into_par_iter()
                .map(|acc| {
                    let mut pbs_ct = LweCiphertext::new(0u64, ctx.big_lwe_dimension().to_lwe_size(),ctx.ciphertext_modulus());
                    programmable_bootstrap_lwe_ciphertext(
                        &index_column,
                        &mut pbs_ct,
                        &acc.0,
                        &self.fourier_bsk,
                    );
                    let mut switched = LweCiphertext::new(0, ctx.small_lwe_dimension().to_lwe_size(),ctx.ciphertext_modulus());
                    keyswitch_lwe_ciphertext(&self.lwe_ksk, &mut pbs_ct, &mut switched);
                    switched
                }),
            );

            let index_line_encoded = self.lwe_ciphertext_plaintext_add(&index_line, ctx.full_message_modulus() as u64, &ctx);

            // pack all the lwe
            let accumulator_final = LUT::from_vec_of_lwe(pbs_results, self, &ctx);
            // final blind array access
            let mut ct_res = LweCiphertext::new(0u64, ctx.big_lwe_dimension().to_lwe_size(),ctx.ciphertext_modulus());
            programmable_bootstrap_lwe_ciphertext(&index_line_encoded, &mut ct_res, &accumulator_final.0, &self.fourier_bsk,);
            keyswitch_lwe_ciphertext(&self.lwe_ksk, &mut ct_res, &mut output);
            return output
        }



        /// Insert an `element` in a `lut` at `index` and return the modified lut (très très sensible et pas très robuste...)
        pub fn blind_insertion(&self, lut: LUT, index: LweCiphertext<Vec<u64>>, element : &LweCiphertext<Vec<u64>>,  ctx: &Context, private_key: &PrivateKey) -> LUT{

            // One LUT to many LUT
            let mut many_lut = lut.to_many_lut(&self, &ctx);
            let lut_insertion = LUT::from_lwe(&element, &self, &ctx);
            print!("----lut_insertion : -----");
            lut_insertion.print(private_key, ctx);

        
            //Updating the index
            println!("-----many_lut : -----");
            let mut new_index : Vec<LweCiphertext<Vec<u64>>> = Vec::new();
            for original_index in 0..many_lut.len(){
    
                let mut ct_cp = self.leq_scalar(&index, original_index as u64, &ctx);
                lwe_ciphertext_plaintext_add_assign(&mut ct_cp, Plaintext((original_index as u64)*ctx.delta()));
                private_key.debug_lwe("ct_cp", &ct_cp, &ctx);
                new_index.push(ct_cp);

                many_lut[original_index].print(&private_key, &ctx);
            
            }
            new_index[ctx.full_message_modulus()-1] = index;
            many_lut[ctx.full_message_modulus()-1] = lut_insertion;
    
            println!("------ Multi Blind Rotate-------");
            // Multi Blind Rotate
            for (lut,index) in many_lut.iter_mut().zip(new_index.iter()){
                let mut rotation = self.allocate_and_trivially_encrypt_lwe(ctx.full_message_modulus() as u64, &ctx);
                lwe_ciphertext_sub_assign(&mut rotation, &index); // rotation = 16 - index = - index
                // let rotation = self.neg_lwe(&index, &ctx);
                blind_rotate_assign(&rotation, &mut lut.0, &self.fourier_bsk);
                lut.print(private_key, ctx);
            }
        
        
            // Sum all the rotated glwe to get the final glwe permuted
            let mut output = many_lut[0].0.clone();
            for i in 1..many_lut.len(){
                output = self.glwe_sum(&output,&many_lut[i].0);
            }

            LUT(output)
            
        }


        /// Swap the elements of a `lut` given a vector of `permutation` and return the lut permuted
        pub fn blind_permutation(&self, lut: LUT, permutation: Vec<LweCiphertext<Vec<u64>>>,ctx: Context,) -> LUT{
            let mut many_lut = lut.to_many_lut(&self, &ctx);
            // Multi Blind Rotate 
            for (lut,p) in many_lut.iter_mut().zip(permutation.iter()){
                blind_rotate_assign(p, &mut lut.0, &self.fourier_bsk);
            }
            // Sum all the rotated glwe to get the final glwe permuted
            let mut result_glwe = many_lut[0].0.clone();
            for i in 1..many_lut.len(){
                result_glwe = self.glwe_sum(&result_glwe,&many_lut[i].0);
            }
            
            LUT(result_glwe)
        }


        /// Retrieve an element from a `lut` given it `index` and return the retrieved element with the new lut
        pub fn blind_retrieve(&self, lut: &mut LUT, index_retrieve: LweCiphertext<Vec<u64>>,ctx: &Context,) -> (LweCiphertext<Vec<u64>>,LUT) {



            let mut big_lwe = LweCiphertext::new(0_64, ctx.big_lwe_dimension().to_lwe_size(), ctx.ciphertext_modulus());
            let mut lwe_retrieve = LweCiphertext::new(0_64, ctx.small_lwe_dimension().to_lwe_size(), ctx.ciphertext_modulus());

            // Delete the retrieved element from the lut
                // get the element wanted
            blind_rotate_assign(&index_retrieve, &mut lut.0, &self.fourier_bsk);
            extract_lwe_sample_from_glwe_ciphertext(&lut.0, &mut big_lwe, MonomialDegree(0));
            keyswitch_lwe_ciphertext(&self.lwe_ksk, &big_lwe , &mut lwe_retrieve);

            let lut_retrieve = LUT::from_lwe(&lwe_retrieve, self, &*ctx);
            let mut lut_sum = LUT(self.glwe_sum(&lut.0, &lut_retrieve.0 ));
                // rerotate the lut
            let neg_index_retrieve = self.neg_lwe(&index_retrieve, &*ctx);
            blind_rotate_assign(&neg_index_retrieve, &mut lut_sum.0, &self.fourier_bsk);
        
        

            // One LUT to many LUT
            let mut many_lut = lut_sum.to_many_lut(self, &*ctx);
        
            // Updating the index
            let mut new_index : Vec<LweCiphertext<Vec<u64>>> = Vec::new();
            for original_index in 0..many_lut.len(){
        
                let ct_cp = self.leq_scalar(&index_retrieve, original_index as u64, &*ctx);
                let ct_original_index = self.allocate_and_trivially_encrypt_lwe(original_index as u64, ctx);
                let mut ct_new_index = LweCiphertext::new(0_u64, ctx.small_lwe_dimension().to_lwe_size(), ctx.ciphertext_modulus());
                lwe_ciphertext_sub(&mut ct_new_index, &ct_original_index, &ct_cp); // new index = original_index - ct_cp
                new_index.push(ct_new_index);
            
            }

            
            // Multi Blind Rotate
            for (lut,index) in many_lut.iter_mut().zip(new_index.iter()){
                let rotation = self.neg_lwe(&index, &ctx);
                blind_rotate_assign(&rotation, &mut lut.0, &self.fourier_bsk);
            }
            
        
            // Sum all the rotated glwe to get the final glwe retrieved
        
            let mut result = many_lut[0].0.clone();
            for i in 1..many_lut.len(){
                result = self.glwe_sum(&result,&many_lut[i].0);
            }
        
            let new_lut = LUT(result);

            (lwe_retrieve,new_lut)


        }








        /// Pop and udpate the `lut_stack`
        pub fn blind_pop(&self, lut_stack: &mut LUTStack, ctx: &Context) -> LweCiphertext<Vec<u64>>{


            // rotation = stack_len - 1
            let lwe_one = self.allocate_and_trivially_encrypt_lwe(1_u64, &ctx);
            let mut lwe_pop = LweCiphertext::new(0, ctx.small_lwe_dimension().to_lwe_size(), ctx.ciphertext_modulus());
            let mut lwe_pop_not_switched = LweCiphertext::new(0, ctx.big_lwe_dimension().to_lwe_size(), ctx.ciphertext_modulus());
            let mut rotation = LweCiphertext::new(0_64,ctx.small_lwe_dimension().to_lwe_size(), ctx.ciphertext_modulus());
            lwe_ciphertext_sub(&mut rotation, &lut_stack.number_of_elements, &lwe_one);

            // rotate and extract to delete
            blind_rotate_assign(&rotation, &mut lut_stack.lut.0, &self.fourier_bsk);
            extract_lwe_sample_from_glwe_ciphertext(&lut_stack.lut.0, &mut lwe_pop_not_switched, MonomialDegree(0));
            keyswitch_lwe_ciphertext(&self.lwe_ksk, &lwe_pop_not_switched, &mut lwe_pop);
        
            // Delete from the stack and re-rotate
            let lut_used_to_delete = LUT::from_lwe(&lwe_pop, &self, &ctx);
            self.glwe_sum_assign(&mut lut_stack.lut.0,&lut_used_to_delete.0);
            self.wrapping_neg_lwe(&mut rotation);
            blind_rotate_assign(&rotation, &mut lut_stack.lut.0, &self.fourier_bsk);
            
            // udpating the number of element
            lwe_ciphertext_sub_assign(&mut lut_stack.number_of_elements, &lwe_one);

            lwe_pop
    
        }


        pub fn blind_push(&self, lut_stack: &mut LUTStack, lwe_push: &LweCiphertext<Vec<u64>>, ctx: &Context) {


            let mut to_push = LUT::from_lwe(&lwe_push, self, &ctx);
        
            let stack_len = &lut_stack.number_of_elements;
            let mut rotation = self.allocate_and_trivially_encrypt_lwe(ctx.full_message_modulus() as u64, &ctx);

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








        


    }


    pub struct LUT(pub GlweCiphertext<Vec<u64>>);



    impl LUT {
        pub fn new(ctx: &Context) -> LUT {
            let new_lut = GlweCiphertext::new(0_64, ctx.glwe_dimension().to_glwe_size(), ctx.polynomial_size(), ctx.ciphertext_modulus());
            LUT(new_lut)
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


        fn add_redundancy_many_lwe(many_lwe : Vec<LweCiphertext<Vec<u64>>>, ctx : &Context) -> Vec<LweCiphertext<Vec<u64>>>{

            let box_size = ctx.box_size();
            // Create the vector of redundancy
            let mut redundant_many_lwe : Vec<LweCiphertext<Vec<u64>>> = Vec::new();
        
            for lwe in many_lwe{
               let mut redundant_lwe = vec![lwe;box_size];
               redundant_many_lwe.append(&mut redundant_lwe);
    
            }
    
            redundant_many_lwe
            
        }
    

        fn add_redundancy(lwe: &LweCiphertext<Vec<u64>>, ctx: &Context) -> Vec<LweCiphertext<Vec<u64>>> {
            let box_size = ctx.box_size();
            let redundant_lwe: Vec<LweCiphertext<Vec<u64>>> = vec![(*lwe).clone(); box_size];
            redundant_lwe
        }


        pub fn from_function<F>(f: F, ctx: &Context) -> LUT where F: Fn(u64) -> u64 {
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

            let accumulator =
                allocate_and_trivially_encrypt_new_glwe_ciphertext(ctx.glwe_dimension().to_glwe_size(), &accumulator_plaintext, ctx.ciphertext_modulus());

            LUT(accumulator)
        }


        pub fn from_vec(vec: &Vec<u64>, private_key: &PrivateKey, ctx: &mut Context) -> LUT {
            let mut lut_as_glwe = GlweCiphertext::new(0_u64, ctx.glwe_dimension().to_glwe_size(), ctx.polynomial_size(), ctx.ciphertext_modulus());
            let redundant_lut = Self::add_redundancy_many_u64(vec, ctx);
            let accumulator_plaintext = PlaintextList::from_container(redundant_lut);
            private_key.encrypt_glwe(&mut lut_as_glwe, accumulator_plaintext, ctx);
            LUT(lut_as_glwe)
        }


        pub fn from_vec_of_lwe(many_lwe: Vec<LweCiphertext<Vec<u64>>>, public_key: &PublicKey, ctx: &Context) -> LUT {
            let redundant_many_lwe = Self::add_redundancy_many_lwe(many_lwe, &ctx);
            let mut lwe_container: Vec<u64> = Vec::new();
            for ct in redundant_many_lwe {
                let mut lwe = ct.into_container();
                lwe_container.append(&mut lwe);
            }
            let lwe_ciphertext_list = LweCiphertextList::from_container(lwe_container, ctx.small_lwe_dimension().to_lwe_size(), ctx.ciphertext_modulus());

            // Prepare our output GLWE in which we pack our LWEs
            let mut glwe = GlweCiphertext::new(0, ctx.glwe_dimension().to_glwe_size(), ctx.polynomial_size(), ctx.ciphertext_modulus());

            // Keyswitch and pack
            private_functional_keyswitch_lwe_ciphertext_list_and_pack_in_glwe_ciphertext(
                &public_key.pfpksk,
                &mut glwe,
                &lwe_ciphertext_list,
            );

            let poly_monomial_degree = MonomialDegree(2 * ctx.polynomial_size().0 - ctx.box_size() / 2);
            public_key.glwe_absorption_monic_monomial(&mut glwe, poly_monomial_degree);


            LUT(glwe)
        }


        pub fn from_lwe(lwe: &LweCiphertext<Vec<u64>>, public_key: &PublicKey, ctx: &Context) -> LUT {
            let redundant_lwe = Self::add_redundancy(lwe, &ctx);
            let mut container: Vec<u64> = Vec::new();
            for ct in redundant_lwe {
                let mut lwe = ct.into_container();
                container.append(&mut lwe);
            }
            let lwe_ciphertext_list = LweCiphertextList::from_container(container, ctx.small_lwe_dimension().to_lwe_size(), ctx.ciphertext_modulus());
            // Prepare our output GLWE
            let mut glwe = GlweCiphertext::new(0, ctx.glwe_dimension().to_glwe_size(), ctx.polynomial_size(), ctx.ciphertext_modulus());
            // Keyswitch and pack
            private_functional_keyswitch_lwe_ciphertext_list_and_pack_in_glwe_ciphertext(
                &public_key.pfpksk,
                &mut glwe,
                &lwe_ciphertext_list,
            );

            let poly_monomial_degree = MonomialDegree(2 * ctx.polynomial_size().0 - ctx.box_size() / 2);
            public_key.glwe_absorption_monic_monomial(&mut glwe, poly_monomial_degree);

            LUT(glwe)
        }

        pub fn to_many_lwe(&self, public_key: &PublicKey, ctx: &Context) -> Vec<LweCiphertext<Vec<u64>>> {
            let mut many_lwe: Vec<LweCiphertext<Vec<u64>>> = Vec::new();
            for i in 0..ctx.full_message_modulus() {
                let mut lwe_sample = LweCiphertext::new(0_64, ctx.big_lwe_dimension().to_lwe_size(), ctx.ciphertext_modulus());
                extract_lwe_sample_from_glwe_ciphertext(
                    &self.0,
                    &mut lwe_sample,
                    MonomialDegree(i * ctx.box_size()  as usize));
                let mut switched = LweCiphertext::new(0, ctx.small_lwe_dimension().to_lwe_size(), ctx.ciphertext_modulus());
                keyswitch_lwe_ciphertext(&public_key.lwe_ksk, &mut lwe_sample, &mut switched);
                many_lwe.push(switched);
            }
            many_lwe
        }

        pub fn to_many_lut(&self, public_key: &PublicKey, ctx: &Context) -> Vec<LUT> {
            let many_lwe = self.to_many_lwe(public_key, ctx);

            // Many-Lwe to Many-Glwe
            let mut many_glwe: Vec<LUT> = Vec::new();
            for lwe in many_lwe {
                let mut glwe = GlweCiphertext::new(0_u64, ctx.glwe_dimension().to_glwe_size(), ctx.polynomial_size(), ctx.ciphertext_modulus());
                let redundancy_lwe = public_key.one_lwe_to_lwe_ciphertext_list(lwe, ctx);
                private_functional_keyswitch_lwe_ciphertext_list_and_pack_in_glwe_ciphertext(
                    &public_key.pfpksk,
                    &mut glwe,
                    &redundancy_lwe);
                many_glwe.push(LUT(glwe));
            }
            many_glwe
        }


        pub fn add_lut(
            &self,
            lut_r: &LUT,
        )
            -> LUT
        {
            let ciphertext_modulus = CiphertextModulus::new_native();
            let mut res = GlweCiphertext::new(0_u64, self.0.glwe_size(), self.0.polynomial_size(), ciphertext_modulus);

            res.as_mut().iter_mut()
                .zip(
                    self.0.as_ref().iter().zip(lut_r.0.as_ref().iter())
                ).for_each(|(dst, (&lhs, &rhs))| *dst = lhs + rhs);
            return LUT(res);
        }


        pub fn print(
            &self,
            private_key: &PrivateKey,
            ctx: &Context,
        )
        {
            let box_size = ctx.polynomial_size().0 / ctx.message_modulus().0;

            let half_box_size = box_size / 2;


            // Create the accumulator
            let mut input_vec = Vec::new();
            let mut ct_big = LweCiphertext::new(0_64, ctx.big_lwe_dimension().to_lwe_size(), ctx.ciphertext_modulus(), );

            for i in 0..ctx.message_modulus().0 { //many_lwe.len()
                let index = (i * box_size) + half_box_size;
                extract_lwe_sample_from_glwe_ciphertext(&self.0, &mut ct_big, MonomialDegree(index));
                input_vec.push(private_key.decrypt_lwe_big_key(&ct_big, &ctx));
            }
            println!("{:?}", input_vec);
        }




        pub fn print_in_array_format(
            &self,
            private_key: &PrivateKey,
            ctx: &Context, ) 
        {
            let half_box_size = ctx.box_size() / 2;
        
            let mut result_insert: Vec<LweCiphertext<Vec<u64>>> = Vec::new();
            result_insert.par_extend(
            (0..ctx.full_message_modulus())
                .into_par_iter()
                .map(|i| {
                    let mut lwe_sample = LweCiphertext::new(0_64, ctx.big_lwe_dimension().to_lwe_size(), ctx.ciphertext_modulus());
                    extract_lwe_sample_from_glwe_ciphertext(
                        &self.0,
                        &mut lwe_sample,
                        MonomialDegree((i * ctx.box_size() + half_box_size) as usize),
                    );
                    let mut switched = LweCiphertext::new(0, ctx.small_lwe_dimension().to_lwe_size(),ctx.ciphertext_modulus());
                    keyswitch_lwe_ciphertext(&private_key.public_key.lwe_ksk, &mut lwe_sample, &mut switched);
        
                    // switched
        
                    // the result will be modulo 32
                    private_key.public_key.wrapping_neg_lwe(&mut switched);
                    switched
                }),
            );
        
        
            let mut result_retrieve_u64 : Vec<u64> = Vec::new();
            for lwe in result_insert{
                let pt = private_key.decrypt_lwe(&lwe, &ctx);
                result_retrieve_u64.push(pt);
            }
            println!("Final array : {:?} ",result_retrieve_u64 );
        }




    }







    pub struct LUTStack{
        pub lut : LUT,
        pub number_of_elements : LweCiphertext<Vec<u64>>
    }


    impl LUTStack{

        pub fn new(ctx : &Context) -> LUTStack{
            let lut = LUT(GlweCiphertext::new(0_64, ctx.glwe_dimension().to_glwe_size(), ctx.polynomial_size(),ctx.ciphertext_modulus()));
            let number_of_elements = LweCiphertext::new(0_u64,ctx.small_lwe_dimension().to_lwe_size(),ctx.ciphertext_modulus());
            LUTStack{
                lut,
                number_of_elements
            }
        }

        fn add_redundancy_many_u64(vec : &Vec<u64>, ctx : &Context) -> Vec<u64> {

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





        pub fn from_vec(vec : &Vec<u64>, private_key : &PrivateKey, ctx : &mut Context) -> LUTStack {


            let stack_len = private_key.allocate_and_trivially_encrypt_lwe((vec.len())  as u64, ctx);
            let mut lut_as_glwe = GlweCiphertext::new(0_u64, ctx.glwe_dimension().to_glwe_size() , ctx.polynomial_size(),ctx.ciphertext_modulus());
            let redundant_lut = Self::add_redundancy_many_u64(vec, ctx);
            let accumulator_plaintext = PlaintextList::from_container(redundant_lut);
            private_key.encrypt_glwe(&mut lut_as_glwe, accumulator_plaintext, ctx);

            LUTStack {
                lut: LUT(lut_as_glwe),
                number_of_elements: stack_len
            }
        }

        pub fn from_lut(lut : LUT, public_key : &PublicKey, ctx : &Context,) -> LUTStack{


            let mut number_of_elements = public_key.allocate_and_trivially_encrypt_lwe(ctx.full_message_modulus() as u64, ctx);


            for i in (0..ctx.full_message_modulus()).rev(){

                let mut lwe_sample = LweCiphertext::new(0_64, ctx.big_lwe_dimension().to_lwe_size(),ctx.ciphertext_modulus());
                extract_lwe_sample_from_glwe_ciphertext(
                    &lut.0,
                    &mut lwe_sample,
                    MonomialDegree(i*ctx.box_size() as usize));
                let mut switched = LweCiphertext::new(0, ctx.small_lwe_dimension().to_lwe_size(),ctx.ciphertext_modulus());
                keyswitch_lwe_ciphertext(&public_key.lwe_ksk, &mut lwe_sample, &mut switched);

                let cp = public_key.eq_scalar(&switched, 0, &ctx);

                lwe_ciphertext_sub_assign(&mut number_of_elements, &cp);

            }

            LUTStack {
                lut: lut,
                number_of_elements: number_of_elements
            }


        }



        pub fn print(
            &self,
            private_key: &PrivateKey,
            ctx: &Context,
        )
        {
            let box_size = ctx.polynomial_size().0 / ctx.message_modulus().0;

            // Create the accumulator
            let mut input_vec = Vec::new();
            let mut ct_big = LweCiphertext::new(0_64, ctx.big_lwe_dimension().to_lwe_size(), ctx.ciphertext_modulus(), );

            for i in 0..ctx.message_modulus().0 { //many_lwe.len()
                let index = i * box_size;
                extract_lwe_sample_from_glwe_ciphertext(&self.lut.0, &mut ct_big, MonomialDegree(index));
                input_vec.push(private_key.decrypt_lwe_big_key(&ct_big, &ctx));
            }

            
            println!("LUT Stack : {:?}", input_vec);
            println!("LUT Stack size : {:?}", private_key.decrypt_lwe(&self.number_of_elements, ctx) );
        }
    }




    #[cfg(test)]

    mod test{


        // use tfhe::core_crypto::prelude::*;
        use tfhe::shortint::parameters::PARAM_MESSAGE_4_CARRY_0;

        use super::*;

        #[test]
        fn test_lwe_enc(){
            let mut ctx = Context::from(PARAM_MESSAGE_4_CARRY_0);
            let private_key = PrivateKey::new(&mut ctx);
            let input : u64 = 3;
            let lwe = private_key.allocate_and_encrypt_lwe(input, &mut ctx);
            let clear = private_key.decrypt_lwe(&lwe, &mut ctx);
            println!("Test encryption-decryption");
            assert_eq!(input,clear);
        }


        #[test]
        fn test_lut_enc(){
            let mut ctx = Context::from(PARAM_MESSAGE_4_CARRY_0);
            let private_key = PrivateKey::new(&mut ctx);
            let array = vec![0,1,2,3,4];
            let _lut = LUT::from_vec(&array, &private_key, &mut ctx);
        }


        #[test]
        fn test_neg_lwe(){
            let mut ctx = Context::from(PARAM_MESSAGE_4_CARRY_0);
            let private_key = PrivateKey::new(&mut ctx);
            let public_key = &private_key.public_key;
            let input : u64 = 3;
            let mut lwe = private_key.allocate_and_encrypt_lwe(input, &mut ctx);
            public_key.wrapping_neg_lwe(&mut lwe);
            let clear = private_key.decrypt_lwe(&lwe, &mut ctx);
            println!("Test encryption-decryption");
            println!("neg_lwe = {}", clear);
            // assert_eq!(input,16-clear);
        }

        #[test]
        fn test_neg_lwe_assign(){
            let mut ctx = Context::from(PARAM_MESSAGE_4_CARRY_0);
            let private_key = PrivateKey::new(&mut ctx);
            let public_key = &private_key.public_key;
            let input : u64 = 3;
            let mut lwe = private_key.allocate_and_encrypt_lwe(input, &mut ctx);
            let neg_lwe = public_key.neg_lwe(&mut lwe, &ctx);
            let clear = private_key.decrypt_lwe(&neg_lwe, &mut ctx);
            println!("Test encryption-decryption");
            println!("neg_lwe = {}", clear);
            // assert_eq!(input,16-clear);
        }

        #[test]
        fn test_many_lwe_to_glwe(){
            let mut ctx = Context::from(PARAM_MESSAGE_4_CARRY_0);
            let private_key = PrivateKey::new(&mut ctx);
            let public_key = &private_key.public_key;
            let our_input : Vec<u64> = vec![1,2,3,15];
            let mut many_lwe : Vec<LweCiphertext<Vec<u64>>> = vec![];
            for input in our_input {
                let lwe = private_key.allocate_and_encrypt_lwe(input, &mut ctx);
                many_lwe.push(lwe);
            }
            let lut = LUT::from_vec_of_lwe(many_lwe, public_key, &ctx);
            let output_pt =  private_key.decrypt_and_decode_glwe(&lut.0, &ctx);
            println!("Test many LWE to one GLWE");
            println!("{:?}", output_pt);
        }



        #[test]
        fn test_lwe_to_lut(){
            let mut ctx = Context::from(PARAM_MESSAGE_4_CARRY_0);
            let private_key = PrivateKey::new(&mut ctx);
            let public_key = &private_key.public_key;
            let our_input = 8u64;
            let lwe = private_key.allocate_and_encrypt_lwe(our_input, &mut ctx);
            let lut = LUT::from_lwe(&lwe, public_key, &ctx);
            let output_pt =  private_key.decrypt_and_decode_glwe(&lut.0, &ctx);
            println!("Test LWE to LUT");
            println!("{:?}", output_pt);
        }


        #[test]

        fn test_eq_scalar(){

            let mut ctx = Context::from(PARAM_MESSAGE_4_CARRY_0);
            let private_key = PrivateKey::new(&mut ctx);
            let public_key = &private_key.get_public_key();
            let our_input = 0u64;
            let lwe = private_key.allocate_and_encrypt_lwe(our_input, &mut ctx);

            for i in 0..16{
                let cp = public_key.eq_scalar(&lwe, i, &ctx);
                let res = private_key.decrypt_lwe(&cp, &ctx);
                println!("{} == {} : {}", our_input, i, res);
            }

        }


        #[test]
        fn test_lut_stack_from_lut(){
            let mut ctx = Context::from(PARAM_MESSAGE_4_CARRY_0);
            let private_key = PrivateKey::new(&mut ctx);
            let public_key = &private_key.public_key;
            let array = vec![2,1,2,3,4];
            let lut = LUT::from_vec(&array, &private_key, &mut ctx);

            let lut_stack = LUTStack::from_lut(lut, public_key, &ctx);

            lut_stack.print(&private_key, &ctx);
        }











    }