use tfhe::{
    core_crypto::{
        algorithms::{
            allocate_and_trivially_encrypt_new_glwe_ciphertext,
            extract_lwe_sample_from_glwe_ciphertext, keyswitch_lwe_ciphertext,
            lwe_ciphertext_sub_assign,
            private_functional_keyswitch_lwe_ciphertext_list_and_pack_in_glwe_ciphertext,
        },
        commons::parameters::MonomialDegree,
        entities::{GlweCiphertext, LweCiphertext, LweCiphertextList, PlaintextList},
    },
    shortint::{parameters::PolynomialSize, CiphertextModulus},
};

use crate::{context::Context, private_key::PrivateKey, public_key::PublicKey};
pub struct LUT(pub GlweCiphertext<Vec<u64>>);

impl LUT {
    pub fn new(ctx: &Context) -> LUT {
        let new_lut = GlweCiphertext::new(
            0_64,
            ctx.parameters.glwe_dimension.to_glwe_size(),
            ctx.parameters.polynomial_size,
            ctx.ciphertext_modulus,
        );
        LUT(new_lut)
    }

    fn add_redundancy_many_u64(vec: &Vec<u64>, ctx: &Context) -> Vec<u64> {
        // N/(p/2) = size of each block, to correct noise from the input we introduce the notion of
        // box, which manages redundancy to yield a denoised value for several noisy values around
        // a true input value.
        let box_size = ctx.box_size;

        // Create the output
        let PolynomialSize(size) = ctx.parameters.polynomial_size;
        let mut accumulator_u64 = vec![0_u64; size];

        // Fill each box with the encoded denoised value
        for i in 0..vec.len() {
            let index = i * box_size;
            for j in index..index + box_size {
                accumulator_u64[j] = vec[i] * ctx.delta as u64;
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

    fn add_redundancy_many_lwe(
        many_lwe: Vec<LweCiphertext<Vec<u64>>>,
        ctx: &Context,
    ) -> Vec<LweCiphertext<Vec<u64>>> {
        let box_size = ctx.box_size;
        // Create the vector of redundancy
        let mut redundant_many_lwe: Vec<LweCiphertext<Vec<u64>>> = Vec::new();

        for lwe in many_lwe {
            let mut redundant_lwe = vec![lwe; box_size];
            redundant_many_lwe.append(&mut redundant_lwe);
        }

        redundant_many_lwe
    }

    fn add_redundancy(
        lwe: &LweCiphertext<Vec<u64>>,
        ctx: &Context,
    ) -> Vec<LweCiphertext<Vec<u64>>> {
        let box_size = ctx.box_size;
        let redundant_lwe: Vec<LweCiphertext<Vec<u64>>> = vec![(*lwe).clone(); box_size];
        redundant_lwe
    }

    pub fn from_function<F>(f: F, ctx: &Context) -> LUT
    where
        F: Fn(u64) -> u64,
    {
        let box_size = ctx.box_size;
        // Create the accumulator
        let mut accumulator_u64 = vec![0_u64; ctx.parameters.polynomial_size.0];

        // Fill each box with the encoded denoised value
        for i in 0..ctx.full_message_modulus {
            let index = i * box_size;
            accumulator_u64[index..index + box_size]
                .iter_mut()
                .for_each(|a| *a = f(i as u64) * ctx.delta);
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
            ctx.parameters.glwe_dimension.to_glwe_size(),
            &accumulator_plaintext,
            ctx.ciphertext_modulus,
        );

        LUT(accumulator)
    }

    pub fn from_vec(vec: &Vec<u64>, private_key: &PrivateKey, ctx: &mut Context) -> LUT {
        let mut lut_as_glwe = GlweCiphertext::new(
            0_u64,
            ctx.parameters.glwe_dimension.to_glwe_size(),
            ctx.parameters.polynomial_size,
            ctx.ciphertext_modulus,
        );
        let redundant_lut = Self::add_redundancy_many_u64(vec, ctx);
        let accumulator_plaintext = PlaintextList::from_container(redundant_lut);
        private_key.encrypt_glwe(&mut lut_as_glwe, accumulator_plaintext, ctx);
        LUT(lut_as_glwe)
    }

    /// create a new LUT from data in the given vec by trivially encrypting them
    pub fn from_vec_trivially(vec: &Vec<u64>, ctx: &Context) -> LUT {
        LUT(allocate_and_trivially_encrypt_new_glwe_ciphertext(
            ctx.parameters.glwe_dimension.to_glwe_size(),
            &PlaintextList::from_container(Self::add_redundancy_many_u64(vec, ctx)),
            ctx.ciphertext_modulus,
        ))
    }

    pub fn from_vec_of_lwe(
        many_lwe: Vec<LweCiphertext<Vec<u64>>>,
        public_key: &PublicKey,
        ctx: &Context,
    ) -> LUT {
        let redundant_many_lwe = Self::add_redundancy_many_lwe(many_lwe, &ctx);
        let mut lwe_container: Vec<u64> = Vec::new();
        for ct in redundant_many_lwe {
            let mut lwe = ct.into_container();
            lwe_container.append(&mut lwe);
        }
        let lwe_ciphertext_list = LweCiphertextList::from_container(
            lwe_container,
            ctx.parameters.lwe_dimension.to_lwe_size(),
            ctx.ciphertext_modulus,
        );

        // Prepare our output GLWE in which we pack our LWEs
        let mut glwe = GlweCiphertext::new(
            0,
            ctx.parameters.glwe_dimension.to_glwe_size(),
            ctx.parameters.polynomial_size,
            ctx.ciphertext_modulus,
        );

        // Keyswitch and pack
        private_functional_keyswitch_lwe_ciphertext_list_and_pack_in_glwe_ciphertext(
            &public_key.pfpksk,
            &mut glwe,
            &lwe_ciphertext_list,
        );

        let poly_monomial_degree =
            MonomialDegree(2 * ctx.parameters.polynomial_size.0 - ctx.box_size / 2);
        public_key.glwe_absorption_monic_monomial(&mut glwe, poly_monomial_degree);

        LUT(glwe)
    }

    fn add_redundancy_many_lwe_with_padding(
        many_lwe: Vec<LweCiphertext<Vec<u64>>>,
        public_key: &PublicKey,
        ctx: &Context,
    ) -> Vec<LweCiphertext<Vec<u64>>> {
        let box_size = ctx.parameters.polynomial_size.0 / ctx.full_message_modulus;
        // Create the vector which will contain the redundant lwe
        let mut redundant_many_lwe: Vec<LweCiphertext<Vec<u64>>> = Vec::new();
        let ct_0 = LweCiphertext::new(
            0_64,
            ctx.parameters.lwe_dimension.to_lwe_size(),
            ctx.ciphertext_modulus,
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
        redundant_many_lwe.resize(ctx.full_message_modulus * box_size, ct_0);
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
            ctx.parameters.lwe_dimension.to_lwe_size(),
            ctx.ciphertext_modulus,
        );

        // Prepare our output GLWE in which we pack our LWEs
        let mut glwe = GlweCiphertext::new(
            0,
            ctx.parameters.glwe_dimension.to_glwe_size(),
            ctx.parameters.polynomial_size,
            ctx.ciphertext_modulus,
        );

        // Keyswitch and pack
        private_functional_keyswitch_lwe_ciphertext_list_and_pack_in_glwe_ciphertext(
            &public_key.pfpksk,
            &mut glwe,
            &lwe_ciphertext_list,
        );
        LUT(glwe)
    }

    pub fn from_lwe(lwe: &LweCiphertext<Vec<u64>>, public_key: &PublicKey, ctx: &Context) -> LUT {
        let redundant_lwe = Self::add_redundancy(lwe, &ctx);
        let mut container: Vec<u64> = Vec::new();
        for ct in redundant_lwe {
            let mut lwe = ct.into_container();
            container.append(&mut lwe);
        }
        let lwe_ciphertext_list = LweCiphertextList::from_container(
            container,
            ctx.parameters.lwe_dimension.to_lwe_size(),
            ctx.ciphertext_modulus,
        );
        // Prepare our output GLWE
        let mut glwe = GlweCiphertext::new(
            0,
            ctx.parameters.glwe_dimension.to_glwe_size(),
            ctx.parameters.polynomial_size,
            ctx.ciphertext_modulus,
        );
        // Keyswitch and pack
        private_functional_keyswitch_lwe_ciphertext_list_and_pack_in_glwe_ciphertext(
            &public_key.pfpksk,
            &mut glwe,
            &lwe_ciphertext_list,
        );

        let poly_monomial_degree =
            MonomialDegree(2 * ctx.parameters.polynomial_size.0 - ctx.box_size / 2);
        public_key.glwe_absorption_monic_monomial(&mut glwe, poly_monomial_degree);

        LUT(glwe)
    }

    pub fn to_many_lwe(
        &self,
        public_key: &PublicKey,
        ctx: &Context,
    ) -> Vec<LweCiphertext<Vec<u64>>> {
        let mut many_lwe: Vec<LweCiphertext<Vec<u64>>> = Vec::new();
        for i in 0..ctx.full_message_modulus {
            let mut lwe_sample = LweCiphertext::new(
                0_64,
                ctx.big_lwe_dimension.to_lwe_size(),
                ctx.ciphertext_modulus,
            );
            extract_lwe_sample_from_glwe_ciphertext(
                &self.0,
                &mut lwe_sample,
                MonomialDegree(i * ctx.box_size as usize),
            );
            let mut switched = LweCiphertext::new(
                0,
                ctx.parameters.lwe_dimension.to_lwe_size(),
                ctx.ciphertext_modulus,
            );
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
            let mut glwe = GlweCiphertext::new(
                0_u64,
                ctx.parameters.glwe_dimension.to_glwe_size(),
                ctx.parameters.polynomial_size,
                ctx.ciphertext_modulus,
            );
            let redundancy_lwe = public_key.one_lwe_to_lwe_ciphertext_list(lwe, ctx);
            private_functional_keyswitch_lwe_ciphertext_list_and_pack_in_glwe_ciphertext(
                &public_key.pfpksk,
                &mut glwe,
                &redundancy_lwe,
            );
            many_glwe.push(LUT(glwe));
        }
        many_glwe
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

    pub fn print_in_glwe_format(&self, private_key: &PrivateKey, ctx: &Context) {
        println!("{:?}", private_key.decrypt_lut(self, ctx));
    }

    pub fn public_rotate_right(&mut self, rotation: u64, public_key: &PublicKey) {
        let LUT(glwe) = self;
        public_key.glwe_absorption_monic_monomial(glwe, MonomialDegree(rotation as usize));
    }

    pub fn public_rotate_left(&mut self, rotation: usize, public_key: &PublicKey, ctx: &Context) {
        let PolynomialSize(size) = ctx.parameters.polynomial_size;
        let LUT(glwe) = self;
        public_key.glwe_absorption_monic_monomial(glwe, MonomialDegree(2 * size - rotation));
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
            ctx.parameters.glwe_dimension.to_glwe_size(),
            ctx.parameters.polynomial_size,
            ctx.ciphertext_modulus,
        ));
        let number_of_elements = LweCiphertext::new(
            0_u64,
            ctx.parameters.lwe_dimension.to_lwe_size(),
            ctx.ciphertext_modulus,
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
        let box_size = ctx.box_size;

        // Create the output
        let mut accumulator_u64 = vec![0_u64; ctx.parameters.polynomial_size.0];

        // Fill each box with the encoded denoised value
        for i in 0..vec.len() {
            let index = i * box_size;
            for j in index..index + box_size {
                accumulator_u64[j] = vec[i] * ctx.delta as u64;
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
            ctx.parameters.glwe_dimension.to_glwe_size(),
            ctx.parameters.polynomial_size,
            ctx.ciphertext_modulus,
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
            public_key.allocate_and_trivially_encrypt_lwe(ctx.full_message_modulus as u64, ctx);

        for i in (0..ctx.full_message_modulus).rev() {
            let mut lwe_sample = LweCiphertext::new(
                0_64,
                ctx.big_lwe_dimension.to_lwe_size(),
                ctx.ciphertext_modulus,
            );
            extract_lwe_sample_from_glwe_ciphertext(
                &lut.0,
                &mut lwe_sample,
                MonomialDegree(i * ctx.box_size as usize),
            );
            let mut switched = LweCiphertext::new(
                0,
                ctx.parameters.lwe_dimension.to_lwe_size(),
                ctx.ciphertext_modulus,
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
        let box_size = ctx.parameters.polynomial_size.0 / ctx.parameters.message_modulus.0;

        // Create the accumulator
        let mut input_vec = Vec::new();
        let mut ct_big = LweCiphertext::new(
            0_64,
            ctx.big_lwe_dimension.to_lwe_size(),
            ctx.ciphertext_modulus,
        );

        for i in 0..ctx.parameters.message_modulus.0 {
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
