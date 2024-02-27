use std::fs;

use rayon::iter::{IntoParallelIterator, ParallelExtend, ParallelIterator};
use serde::{Deserialize, Serialize};
use tfhe::{
    core_crypto::{
        algorithms::{
            allocate_and_encrypt_new_lwe_ciphertext,
            allocate_and_trivially_encrypt_new_lwe_ciphertext,
            convert_standard_lwe_bootstrap_key_to_fourier, decrypt_constant_ggsw_ciphertext,
            decrypt_glwe_ciphertext, decrypt_lwe_ciphertext, encrypt_glwe_ciphertext,
            extract_lwe_sample_from_glwe_ciphertext, generate_lwe_keyswitch_key,
            keyswitch_lwe_ciphertext,
            par_allocate_and_generate_new_circuit_bootstrap_lwe_pfpksk_list,
            par_allocate_and_generate_new_lwe_bootstrap_key,
            par_generate_lwe_private_functional_packing_keyswitch_key,
        },
        commons::{parameters::MonomialDegree, traits::ContiguousEntityContainer},
        entities::{
            FourierLweBootstrapKey, GgswCiphertext, GlweCiphertext, GlweSecretKey, LweCiphertext,
            LweCiphertextOwned, LweKeyswitchKey, LwePrivateFunctionalPackingKeyswitchKey,
            LweSecretKey, Plaintext, PlaintextList, Polynomial,
        },
    },
    shortint::wopbs::PlaintextCount,
};

use crate::{context::Context, lut::LUT, public_key::PublicKey};

#[derive(Serialize, Deserialize)]
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
        let small_lwe_sk = LweSecretKey::generate_new_binary(
            ctx.parameters.lwe_dimension,
            &mut ctx.secret_generator,
        );

        // Generate a GlweSecretKey with binary coefficients
        let glwe_sk = GlweSecretKey::generate_new_binary(
            ctx.parameters.glwe_dimension,
            ctx.parameters.polynomial_size,
            &mut ctx.secret_generator,
        );

        // Create a copy of the GlweSecretKey re-interpreted as an LweSecretKey
        let big_lwe_sk = glwe_sk.clone().into_lwe_secret_key();

        // Generate the bootstrapping key, we use the parallel variant for performance reason
        let std_bootstrapping_key = par_allocate_and_generate_new_lwe_bootstrap_key(
            &small_lwe_sk,
            &glwe_sk,
            ctx.parameters.ks_base_log,
            ctx.parameters.ks_level,
            ctx.parameters.glwe_modular_std_dev,
            ctx.ciphertext_modulus,
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
            ctx.parameters.ks_base_log,
            ctx.parameters.ks_level,
            ctx.big_lwe_dimension,
            ctx.parameters.lwe_dimension,
            ctx.ciphertext_modulus,
        );

        generate_lwe_keyswitch_key(
            &big_lwe_sk,
            &small_lwe_sk,
            &mut lwe_ksk,
            ctx.parameters.lwe_modular_std_dev,
            &mut ctx.encryption_generator,
        );

        // Create Packing Key Switch

        let mut pfpksk = LwePrivateFunctionalPackingKeyswitchKey::new(
            0,
            ctx.parameters.pbs_base_log,
            ctx.parameters.pbs_level,
            ctx.parameters.lwe_dimension,
            ctx.parameters.glwe_dimension.to_glwe_size(),
            ctx.parameters.polynomial_size,
            ctx.ciphertext_modulus,
        );

        // Here there is some freedom for the choice of the last polynomial from algorithm 2
        // By convention from the paper the polynomial we use here is the constant -1
        let mut last_polynomial = Polynomial::new(0, ctx.parameters.polynomial_size);
        // Set the constant term to u64::MAX == -1i64
        last_polynomial[0] = u64::MAX;
        // Generate the LWE private functional packing keyswitch key
        par_generate_lwe_private_functional_packing_keyswitch_key(
            &small_lwe_sk,
            &glwe_sk,
            &mut pfpksk,
            ctx.parameters.glwe_modular_std_dev,
            &mut ctx.encryption_generator,
            |x| x,
            &last_polynomial,
        );

        let cbs_pfpksk = par_allocate_and_generate_new_circuit_bootstrap_lwe_pfpksk_list(
            &big_lwe_sk,
            &glwe_sk,
            ctx.parameters.ks_base_log,
            ctx.parameters.ks_level,
            ctx.parameters.glwe_modular_std_dev,
            ctx.ciphertext_modulus,
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

    /// Load a private key from a file instead of generating it
    pub fn from_file(path: &str) -> Self {
        fs::read(path)
            .ok()
            .and_then(|buf| bincode::deserialize(&buf).ok())
            .unwrap()
    }

    pub fn encrypt_permutation(
        &self,
        permutation: Vec<u64>,
        ctx: &mut Context,
    ) -> Vec<LweCiphertext<Vec<u64>>> {
        Vec::from_iter(permutation.iter().map(|perm| {
            self.allocate_and_encrypt_lwe((2 * ctx.full_message_modulus as u64) - perm, ctx)
        }))
    }

    pub fn allocate_and_encrypt_lwe(
        &self,
        input: u64,
        ctx: &mut Context,
    ) -> LweCiphertext<Vec<u64>> {
        let plaintext = Plaintext(ctx.delta.wrapping_mul(input));

        // Allocate a new LweCiphertext and encrypt our plaintext
        let lwe_ciphertext: LweCiphertextOwned<u64> = allocate_and_encrypt_new_lwe_ciphertext(
            &self.small_lwe_sk,
            plaintext,
            ctx.parameters.lwe_modular_std_dev,
            ctx.ciphertext_modulus,
            &mut ctx.encryption_generator,
        );
        lwe_ciphertext
    }

    pub fn allocate_and_encrypt_lwe_big_key(
        &self,
        input: u64,
        ctx: &mut Context,
    ) -> LweCiphertext<Vec<u64>> {
        let plaintext = Plaintext(ctx.delta.wrapping_mul(input));

        // Allocate a new LweCiphertext and encrypt our plaintext
        let lwe_ciphertext: LweCiphertextOwned<u64> = allocate_and_encrypt_new_lwe_ciphertext(
            &self.big_lwe_sk,
            plaintext,
            ctx.parameters.lwe_modular_std_dev,
            ctx.ciphertext_modulus,
            &mut ctx.encryption_generator,
        );
        lwe_ciphertext
    }

    pub fn allocate_and_trivially_encrypt_lwe(
        &self,
        input: u64,
        ctx: &Context,
    ) -> LweCiphertext<Vec<u64>> {
        let plaintext = Plaintext(ctx.delta.wrapping_mul(input));
        // Allocate a new LweCiphertext and encrypt trivially our plaintext
        let lwe_ciphertext: LweCiphertextOwned<u64> =
            allocate_and_trivially_encrypt_new_lwe_ciphertext(
                ctx.parameters.lwe_dimension.to_lwe_size(),
                plaintext,
                ctx.ciphertext_modulus,
            );
        lwe_ciphertext
    }

    pub fn decrypt_lwe(&self, ciphertext: &LweCiphertext<Vec<u64>>, ctx: &Context) -> u64 {
        // Decrypt the PBS multiplication result
        let plaintext: Plaintext<u64> = decrypt_lwe_ciphertext(&self.small_lwe_sk, &ciphertext);
        let result: u64 = ctx.signed_decomposer.closest_representable(plaintext.0) / ctx.delta
            % ctx.full_message_modulus as u64;
        result
    }

    pub fn decrypt_lwe_big_key(&self, ciphertext: &LweCiphertext<Vec<u64>>, ctx: &Context) -> u64 {
        // Decrypt the PBS multiplication result
        let plaintext: Plaintext<u64> = decrypt_lwe_ciphertext(&self.big_lwe_sk, &ciphertext);
        let result: u64 = ctx.signed_decomposer.closest_representable(plaintext.0) / ctx.delta
            % ctx.full_message_modulus as u64;
        result
    }

    pub fn decrypt_lut(&self, lut: &LUT, ctx: &Context) -> Vec<u64> {
        let half_box_size = ctx.box_size / 2;

        let mut result_insert: Vec<LweCiphertext<Vec<u64>>> = Vec::new();
        result_insert.par_extend((0..ctx.full_message_modulus).into_par_iter().map(|i| {
            let mut lwe_sample = LweCiphertext::new(
                0_64,
                ctx.big_lwe_dimension.to_lwe_size(),
                ctx.ciphertext_modulus,
            );
            extract_lwe_sample_from_glwe_ciphertext(
                &lut.0,
                &mut lwe_sample,
                MonomialDegree((i * ctx.box_size + half_box_size) as usize),
            );
            let mut switched = LweCiphertext::new(
                0,
                ctx.parameters.lwe_dimension.to_lwe_size(),
                ctx.ciphertext_modulus,
            );
            keyswitch_lwe_ciphertext(&self.public_key.lwe_ksk, &mut lwe_sample, &mut switched);

            // switched

            // the result will be modulo 32
            self.public_key.wrapping_neg_lwe(&mut switched);
            switched
        }));

        let mut result_retrieve_u64: Vec<u64> = Vec::new();
        for lwe in result_insert {
            let pt = self.decrypt_lwe(&lwe, &ctx);
            result_retrieve_u64.push(pt);
        }
        result_retrieve_u64
    }

    pub fn allocate_and_encrypt_glwe(
        &self,
        pt_list: PlaintextList<Vec<u64>>,
        ctx: &mut Context,
    ) -> GlweCiphertext<Vec<u64>> {
        let mut output_glwe = GlweCiphertext::new(
            0,
            ctx.parameters.glwe_dimension.to_glwe_size(),
            ctx.parameters.polynomial_size,
            ctx.ciphertext_modulus,
        );
        encrypt_glwe_ciphertext(
            &self.glwe_sk,
            &mut output_glwe,
            &pt_list,
            ctx.parameters.glwe_modular_std_dev,
            &mut ctx.encryption_generator,
        );
        output_glwe
    }

    pub fn encrypt_glwe(
        &self,
        output_glwe: &mut GlweCiphertext<Vec<u64>>,
        pt: PlaintextList<Vec<u64>>,
        ctx: &mut Context,
    ) {
        encrypt_glwe_ciphertext(
            &self.glwe_sk,
            output_glwe,
            &pt,
            ctx.parameters.glwe_modular_std_dev,
            &mut ctx.encryption_generator,
        );
    }

    pub fn decrypt_and_decode_glwe_as_neg(
        &self,
        input_glwe: &GlweCiphertext<Vec<u64>>,
        ctx: &Context,
    ) -> Vec<u64> {
        let mut plaintext_res =
            PlaintextList::new(0, PlaintextCount(ctx.parameters.polynomial_size.0));
        decrypt_glwe_ciphertext(&self.glwe_sk, &input_glwe, &mut plaintext_res);

        // To round our 4 bits of message
        // In the paper we return the complicated sum times -1, so here we invert that -1, otherwise we
        // could apply the wrapping_neg on our function and remove it here
        let decoded: Vec<_> = plaintext_res
            .iter()
            .map(|x| {
                (ctx.signed_decomposer.closest_representable(*x.0) / ctx.delta).wrapping_neg()
                    % ctx.full_message_modulus as u64
            })
            .collect();

        decoded
    }

    pub fn decrypt_and_decode_glwe(
        &self,
        input_glwe: &GlweCiphertext<Vec<u64>>,
        ctx: &Context,
    ) -> Vec<u64> {
        let mut plaintext_res =
            PlaintextList::new(0, PlaintextCount(ctx.parameters.polynomial_size.0));
        decrypt_glwe_ciphertext(&self.glwe_sk, &input_glwe, &mut plaintext_res);

        // To round our 4 bits of message
        // In the paper we return the complicated sum times -1, so here we invert that -1, otherwise we
        // could apply the wrapping_neg on our function and remove it here
        let decoded: Vec<_> = plaintext_res
            .iter()
            .map(|x| {
                (ctx.signed_decomposer.closest_representable(*x.0) / ctx.delta)
                    % ctx.full_message_modulus as u64
            })
            .collect();

        decoded
    }

    pub fn decrypt_ggsw(
        &self,
        input_ggsw: &GgswCiphertext<Vec<u64>>,
        private_key: &PrivateKey,
    ) -> u64 {
        let plain = decrypt_constant_ggsw_ciphertext(&private_key.glwe_sk, &input_ggsw);
        plain.0
    }

    pub fn debug_lwe(&self, string: &str, ciphertext: &LweCiphertext<Vec<u64>>, ctx: &Context) {
        // Decrypt the PBS multiplication result
        let plaintext: Plaintext<u64> = decrypt_lwe_ciphertext(&self.small_lwe_sk, &ciphertext);
        let result: u64 = ctx.signed_decomposer.closest_representable(plaintext.0) / ctx.delta;
        println!("{} {}", string, result);
    }
    pub fn debug_big_lwe(&self, string: &str, ciphertext: &LweCiphertext<Vec<u64>>, ctx: &Context) {
        // Decrypt the PBS multiplication result
        let plaintext: Plaintext<u64> = decrypt_lwe_ciphertext(&self.big_lwe_sk, &ciphertext);
        let result: u64 = ctx.signed_decomposer.closest_representable(plaintext.0) / ctx.delta;
        println!("{} {}", string, result);
    }

    pub fn debug_glwe(&self, string: &str, input_glwe: &GlweCiphertext<Vec<u64>>, ctx: &Context) {
        let mut plaintext_res =
            PlaintextList::new(0, PlaintextCount(ctx.parameters.polynomial_size.0));
        decrypt_glwe_ciphertext(&self.glwe_sk, &input_glwe, &mut plaintext_res);

        // To round our 4 bits of message
        // In the paper we return the complicated sum times -1, so here we invert that -1, otherwise we
        // could apply the wrapping_neg on our function and remove it here
        let decoded: Vec<_> = plaintext_res
            .iter()
            .map(|x| {
                (ctx.signed_decomposer.closest_representable(*x.0) / ctx.delta).wrapping_neg()
                    % ctx.full_message_modulus as u64
            })
            .collect();

        println!("{} {:?}", string, decoded);
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
        for _i in ct_matrix.len()..ctx.parameters.message_modulus.0 {
            let ct_padding = LUT::from_vec(&vec![0u64], self, &mut ctx);
            ct_matrix.push(ct_padding);
        }
        return ct_matrix;
    }

    pub fn decrypt_and_print_matrix(&self, ctx: &Context, ct_matrix: &Vec<LUT>) {
        let mut result = Vec::new();
        for i in ct_matrix {
            let res = self.print_lut(i, &ctx);
            result.push(res);
        }
        println!("{:?}", result);
    }

    pub fn print_lut(&self, lut: &LUT, ctx: &Context) {
        let box_size = ctx.parameters.polynomial_size.0 / ctx.parameters.message_modulus.0;

        // let half_box_size = box_size / 2;

        // Create the accumulator
        let mut input_vec: Vec<u64> = Vec::new();
        let mut ct_big = LweCiphertext::new(
            0_64,
            ctx.big_lwe_dimension.to_lwe_size(),
            ctx.ciphertext_modulus,
        );

        for i in 0..ctx.parameters.message_modulus.0 {
            //many_lwe.len()
            let index = i * box_size;
            extract_lwe_sample_from_glwe_ciphertext(&lut.0, &mut ct_big, MonomialDegree(index));
            input_vec.push(self.decrypt_lwe_big_key(&ct_big, &ctx));
        }
        println!("{:?}", input_vec);
    }
}
