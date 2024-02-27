use std::sync::OnceLock;

use aligned_vec::ABox;
use num_complex::Complex;
use rayon::iter::{IntoParallelIterator, ParallelExtend, ParallelIterator};
use serde::{Deserialize, Serialize};
use tfhe::core_crypto::{
    algorithms::{
        allocate_and_trivially_encrypt_new_lwe_ciphertext, blind_rotate_assign,
        extract_lwe_sample_from_glwe_ciphertext, keyswitch_lwe_ciphertext, lwe_ciphertext_add,
        lwe_ciphertext_add_assign, lwe_ciphertext_cleartext_mul,
        lwe_ciphertext_plaintext_add_assign, lwe_ciphertext_sub, lwe_ciphertext_sub_assign,
        polynomial_algorithms::polynomial_wrapping_monic_monomial_mul_assign,
        programmable_bootstrap_lwe_ciphertext,
    },
    commons::{parameters::MonomialDegree, traits::ContiguousEntityContainerMut},
    entities::{
        Cleartext, FourierLweBootstrapKey, GlweCiphertext, LweCiphertext, LweCiphertextList,
        LweCiphertextOwned, LweKeyswitchKey, LwePrivateFunctionalPackingKeyswitchKey,
        LwePrivateFunctionalPackingKeyswitchKeyListOwned, Plaintext,
    },
};

use crate::context::Context;
use crate::lut::LUTStack;
use crate::lut::LUT;

/// lazily compute a trivially encrypted boolean comparison matrix of the form:
/// ```text
/// 0 0 0
/// 1 0 0
/// 1 1 0
/// ```
fn cmp_matrix(ctx: &Context) -> &'static Vec<LUT> {
    static MATRIX: OnceLock<Vec<LUT>> = OnceLock::new();
    MATRIX.get_or_init(|| {
        Vec::from_iter((0..ctx.full_message_modulus).map(|i| {
            LUT::from_vec_trivially(
                &Vec::from_iter((0..ctx.full_message_modulus).map(|j| if j < i { 1 } else { 0 })),
                ctx,
            )
        }))
    })
}

#[derive(Serialize, Deserialize)]
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
            ctx.parameters.lwe_dimension.to_lwe_size(),
            ctx.ciphertext_modulus,
        );
        neg_lwe
            .as_mut()
            .iter_mut()
            .zip(lwe.as_ref().iter())
            .for_each(|(dst, &lhs)| *dst = lhs.wrapping_neg());
        neg_lwe
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

    /// run f(ct_input), assuming self was constructed with LUT::from_function(f)
    pub fn run_lut(
        &self,
        ct_input: &LweCiphertext<Vec<u64>>,
        lut: &LUT,
        ctx: &Context,
    ) -> LweCiphertext<Vec<u64>> {
        let mut res_cmp = LweCiphertext::new(
            0u64,
            ctx.big_lwe_dimension.to_lwe_size(),
            ctx.ciphertext_modulus,
        );
        programmable_bootstrap_lwe_ciphertext(&ct_input, &mut res_cmp, &lut.0, &self.fourier_bsk);
        let mut switched = LweCiphertext::new(
            0,
            ctx.parameters.lwe_dimension.to_lwe_size(),
            ctx.ciphertext_modulus,
        );
        keyswitch_lwe_ciphertext(&self.lwe_ksk, &mut res_cmp, &mut switched);

        switched
    }

    pub fn leq_scalar(
        &self,
        ct_input: &LweCiphertext<Vec<u64>>,
        scalar: u64,
        ctx: &Context,
    ) -> LweCiphertext<Vec<u64>> {
        let cmp_scalar_accumulator = LUT::from_function(|x| (x <= scalar as u64) as u64, ctx);
        self.run_lut(ct_input, &cmp_scalar_accumulator, ctx)
    }

    pub fn geq_scalar(
        &self,
        ct_input: &LweCiphertext<Vec<u64>>,
        scalar: u64,
        ctx: &Context,
    ) -> LweCiphertext<Vec<u64>> {
        let cmp_scalar_accumulator = LUT::from_function(|x| (x >= scalar) as u64, ctx);
        self.run_lut(ct_input, &cmp_scalar_accumulator, ctx)
    }

    pub fn eq_scalar(
        &self,
        ct_input: &LweCiphertext<Vec<u64>>,
        scalar: u64,
        ctx: &Context,
    ) -> LweCiphertext<Vec<u64>> {
        let eq_scalar_accumulator = LUT::from_function(|x| (x == scalar as u64) as u64, ctx);
        self.run_lut(ct_input, &eq_scalar_accumulator, ctx)
    }

    pub fn one_lwe_to_lwe_ciphertext_list(
        &self,
        input_lwe: LweCiphertext<Vec<u64>>,
        ctx: &Context,
    ) -> LweCiphertextList<Vec<u64>> {
        let redundant_lwe = vec![input_lwe.into_container(); ctx.box_size].concat();
        let lwe_ciphertext_list = LweCiphertextList::from_container(
            redundant_lwe,
            ctx.parameters.lwe_dimension.to_lwe_size(),
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

    // TODO : nom a changer : plaintext -> cleartext puisque Plaintext = Plaintext(cleartext)
    pub fn lwe_ciphertext_plaintext_add(
        &self,
        lwe: &LweCiphertext<Vec<u64>>,
        constant: u64,
        ctx: &Context,
    ) -> LweCiphertextOwned<u64> {
        let constant_plain = Plaintext(constant * ctx.delta);

        let constant_lwe = allocate_and_trivially_encrypt_new_lwe_ciphertext(
            ctx.parameters.lwe_dimension.to_lwe_size(),
            constant_plain,
            ctx.ciphertext_modulus,
        );
        let mut res = LweCiphertext::new(
            0,
            ctx.parameters.lwe_dimension.to_lwe_size(),
            ctx.ciphertext_modulus,
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
        // let constant_plain = Plaintext(constant*ctx.delta);

        // let constant_lwe = allocate_and_trivially_encrypt_new_lwe_ciphertext(ctx.parameters.lwe_dimension.to_lwe_size(),constant_plain,ctx.ciphertext_modulus);
        let mut res = LweCiphertext::new(
            0,
            ctx.parameters.lwe_dimension.to_lwe_size(),
            ctx.ciphertext_modulus,
        );

        lwe_ciphertext_cleartext_mul(&mut res, &lwe, Cleartext(constant));

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
            ctx.big_lwe_dimension.to_lwe_size(),
            ctx.ciphertext_modulus,
        );
        programmable_bootstrap_lwe_ciphertext(&index, &mut output, &array.0, &self.fourier_bsk);
        let mut switched = LweCiphertext::new(
            0_64,
            ctx.parameters.lwe_dimension.to_lwe_size(),
            ctx.ciphertext_modulus,
        );
        keyswitch_lwe_ciphertext(&self.lwe_ksk, &output, &mut switched);
        return switched;
    }

    /// Get an element of a `matrix` given it `index_line` and it `index_column`
    pub fn blind_matrix_access(
        &self,
        matrix: &Vec<LUT>,
        index_line: &LweCiphertext<Vec<u64>>,
        index_column: &LweCiphertext<Vec<u64>>,
        ctx: &Context,
    ) -> LweCiphertext<Vec<u64>> {
        let mut output = LweCiphertext::new(
            0u64,
            ctx.parameters.lwe_dimension.to_lwe_size(),
            ctx.ciphertext_modulus,
        );

        // multi blind array access
        let mut pbs_results: Vec<LweCiphertext<Vec<u64>>> = Vec::new();
        pbs_results.extend(matrix.iter().map(|acc| {
            let mut pbs_ct = LweCiphertext::new(
                0u64,
                ctx.big_lwe_dimension.to_lwe_size(),
                ctx.ciphertext_modulus,
            );
            programmable_bootstrap_lwe_ciphertext(
                &index_column,
                &mut pbs_ct,
                &acc.0,
                &self.fourier_bsk,
            );
            // #[cfg(test)]
            // crate::debug_key().debug_big_lwe("", &pbs_ct, ctx);
            let mut switched = LweCiphertext::new(
                0,
                ctx.parameters.lwe_dimension.to_lwe_size(),
                ctx.ciphertext_modulus,
            );
            keyswitch_lwe_ciphertext(&self.lwe_ksk, &mut pbs_ct, &mut switched);
            switched
        }));

        let index_line_encoded =
            self.lwe_ciphertext_plaintext_add(&index_line, ctx.full_message_modulus as u64, &ctx);

        // pack all the lwe
        let accumulator_final = LUT::from_vec_of_lwe(pbs_results, self, &ctx);
        // for line in matrix {
        //     #[cfg(test)]
        //     crate::debug_key().print_lut(&line, ctx);
        // }
        // final blind array access
        let mut ct_res = LweCiphertext::new(
            0u64,
            ctx.big_lwe_dimension.to_lwe_size(),
            ctx.ciphertext_modulus,
        );
        programmable_bootstrap_lwe_ciphertext(
            &index_line_encoded,
            &mut ct_res,
            &accumulator_final.0,
            &self.fourier_bsk,
        );
        // #[cfg(test)]
        // crate::debug_key().debug_glwe("", &accumulator_final.0, ctx);
        keyswitch_lwe_ciphertext(&self.lwe_ksk, &mut ct_res, &mut output);
        return output;
    }

    /// Insert an `element` in a `lut` at `index` and return the modified lut (très très sensible et pas très robuste...)
    pub fn blind_insertion(
        &self,
        lut: LUT,
        index: LweCiphertext<Vec<u64>>,
        element: &LweCiphertext<Vec<u64>>,
        ctx: &Context,
    ) -> LUT {
        // One LUT to many LUT
        let mut many_lut = lut.to_many_lut(&self, &ctx);
        let lut_insertion = LUT::from_lwe(&element, &self, &ctx);
        print!("----lut_insertion : -----");
        #[cfg(test)]
        crate::debug_key().print_lut(&lut_insertion, ctx);

        //Updating the index
        println!("-----many_lut : -----");
        let mut new_index: Vec<LweCiphertext<Vec<u64>>> = Vec::new();
        for original_index in 0..many_lut.len() {
            let mut ct_cp = self.leq_scalar(&index, original_index as u64, &ctx);
            lwe_ciphertext_plaintext_add_assign(
                &mut ct_cp,
                Plaintext((original_index as u64) * ctx.delta),
            );
            #[cfg(test)]
            crate::debug_key().debug_lwe("ct_cp", &ct_cp, &ctx);
            new_index.push(ct_cp);

            #[cfg(test)]
            crate::debug_key().print_lut(&many_lut[original_index], &ctx);
        }
        new_index[ctx.full_message_modulus - 1] = index;
        many_lut[ctx.full_message_modulus - 1] = lut_insertion;

        println!("------ Multi Blind Rotate-------");
        // Multi Blind Rotate
        for (lut, index) in many_lut.iter_mut().zip(new_index.iter()) {
            let mut rotation =
                self.allocate_and_trivially_encrypt_lwe(ctx.full_message_modulus as u64, &ctx);
            lwe_ciphertext_sub_assign(&mut rotation, &index); // rotation = 16 - index = - index
                                                              // let rotation = self.neg_lwe(&index, &ctx);
            blind_rotate_assign(&rotation, &mut lut.0, &self.fourier_bsk);
            #[cfg(test)]
            crate::debug_key().print_lut(&lut, ctx);
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
            blind_rotate_assign(p, &mut lut.0, &self.fourier_bsk);
        }

        // Sum all the rotated glwe to get the final glwe permuted
        let mut result_glwe = many_lut[0].0.clone();
        for i in 1..many_lut.len() {
            result_glwe = self.glwe_sum(&result_glwe, &many_lut[i].0);
        }

        LUT(result_glwe)
    }

    /// Retrieve an element from a `lut` given it `index` and return the retrieved element with the new lut
    pub fn blind_retrieve(
        &self,
        lut: &mut LUT,
        index_retrieve: LweCiphertext<Vec<u64>>,
        ctx: &Context,
    ) -> (LweCiphertext<Vec<u64>>, LUT) {
        let mut big_lwe = LweCiphertext::new(
            0_64,
            ctx.big_lwe_dimension.to_lwe_size(),
            ctx.ciphertext_modulus,
        );
        let mut lwe_retrieve = LweCiphertext::new(
            0_64,
            ctx.parameters.lwe_dimension.to_lwe_size(),
            ctx.ciphertext_modulus,
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
                ctx.parameters.lwe_dimension.to_lwe_size(),
                ctx.ciphertext_modulus,
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
            ctx.parameters.lwe_dimension.to_lwe_size(),
            ctx.ciphertext_modulus,
        );
        let mut lwe_pop_not_switched = LweCiphertext::new(
            0,
            ctx.big_lwe_dimension.to_lwe_size(),
            ctx.ciphertext_modulus,
        );
        let mut rotation = LweCiphertext::new(
            0_64,
            ctx.parameters.lwe_dimension.to_lwe_size(),
            ctx.ciphertext_modulus,
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
            self.allocate_and_trivially_encrypt_lwe(ctx.full_message_modulus as u64, &ctx);

        lwe_ciphertext_sub_assign(&mut rotation, &stack_len);
        // rotation = 16 - index_to_push = - index_to_push
        blind_rotate_assign(&rotation, &mut to_push.0, &self.fourier_bsk);

        // Sum all the rotated glwe to get the final glwe permuted
        self.glwe_sum_assign(&mut lut_stack.lut.0, &to_push.0);

        let lwe_one = self.allocate_and_trivially_encrypt_lwe(1_u64, &ctx);
        // let mut new_number_of_element = LweCiphertext::new(0_u64, ctx.parameters.lwe_dimension.to_lwe_size(), ctx.ciphertext_modulus);
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
                ctx.big_lwe_dimension.to_lwe_size(),
                ctx.ciphertext_modulus,
            );
            programmable_bootstrap_lwe_ciphertext(
                &index_column,
                &mut pbs_ct,
                &acc.0,
                &self.fourier_bsk,
            );
            let mut switched = LweCiphertext::new(
                0,
                ctx.parameters.lwe_dimension.to_lwe_size(),
                ctx.ciphertext_modulus,
            );
            keyswitch_lwe_ciphertext(&self.lwe_ksk, &mut pbs_ct, &mut switched);
            switched
        }));

        let mut lut_column = LUT::from_vec_of_lwe(pbs_results, self, &ctx);

        let index_line_encoded =
            self.lwe_ciphertext_plaintext_mul(&index_line, nb_of_channels as u64, &ctx); // line = line * nb_of_channel
        let index_line_encoded = self.lwe_ciphertext_plaintext_add(
            &index_line_encoded,
            ctx.full_message_modulus as u64,
            &ctx,
        ); // line = msg_mod + line \in [16,32] for 4_0

        blind_rotate_assign(&index_line_encoded, &mut lut_column.0, &self.fourier_bsk);

        let mut outputs_channels: Vec<LweCiphertext<Vec<u64>>> = Vec::new();
        for channel in 0..nb_of_channels {
            let mut ct_res = LweCiphertext::new(
                0u64,
                ctx.big_lwe_dimension.to_lwe_size(),
                ctx.ciphertext_modulus,
            );
            extract_lwe_sample_from_glwe_ciphertext(
                &lut_column.0,
                &mut ct_res,
                MonomialDegree(0 + channel * ctx.box_size as usize),
            );
            let mut switched = LweCiphertext::new(
                0,
                ctx.parameters.lwe_dimension.to_lwe_size(),
                ctx.ciphertext_modulus,
            );
            keyswitch_lwe_ciphertext(&self.lwe_ksk, &mut ct_res, &mut switched);
            outputs_channels.push(switched);
        }

        outputs_channels
    }

    /// compares a and b blindly, returning a cipher of 1 if a < b else 0
    fn blind_lt(
        &self,
        a: &LweCiphertext<Vec<u64>>,
        b: &LweCiphertext<Vec<u64>>,
        ctx: &Context,
    ) -> LweCiphertext<Vec<u64>> {
        self.blind_matrix_access(cmp_matrix(ctx), b, a, ctx)
    }

    pub fn extract_lwe_sample(
        &self,
        lut: &LUT,
        i: usize,
        ctx: &Context,
    ) -> LweCiphertext<Vec<u64>> {
        let mut lwe = LweCiphertext::new(
            0u64,
            ctx.big_lwe_dimension.to_lwe_size(),
            ctx.ciphertext_modulus,
        );
        extract_lwe_sample_from_glwe_ciphertext(&lut.0, &mut lwe, MonomialDegree(i));
        let mut switched = LweCiphertext::new(
            0,
            ctx.parameters.lwe_dimension.to_lwe_size(),
            ctx.ciphertext_modulus,
        );
        keyswitch_lwe_ciphertext(&self.lwe_ksk, &mut lwe, &mut switched);

        switched
    }

    /// TODO: handle equality (post-process permutation)
    fn blind_sort(&self, lut: LUT, ctx: &Context) -> LUT {
        let n = ctx.full_message_modulus;
        let notlut = LUT::from_function(|i| if i == 0 { 1 } else { 0 }, ctx);
        let zero = self.allocate_and_trivially_encrypt_lwe(0, ctx);
        let mut permutation = vec![zero; n];
        for col in 0..n {
            let a = self.extract_lwe_sample(&lut, col, ctx);
            for lin in 0..col {
                let b = self.extract_lwe_sample(&lut, lin, ctx);
                let res = self.blind_lt(&a, &b, ctx);
                lwe_ciphertext_add_assign(&mut permutation[col], &res);
                let notres = self.run_lut(&res, &notlut, ctx);
                lwe_ciphertext_add_assign(&mut permutation[lin], &notres);
            }
        }
        self.blind_permutation(lut, permutation, ctx)
    }
}

#[cfg(test)]
mod tests {
    use crate::{context::Context, lut::LUT, private_key::PrivateKey};
    use tfhe::shortint::parameters::{PARAM_MESSAGE_2_CARRY_0, PARAM_MESSAGE_4_CARRY_0};

    use super::cmp_matrix;

    #[test]
    fn test_cmp_matrix() {
        let ctx = Context::from(PARAM_MESSAGE_4_CARRY_0);
        let private_key = PrivateKey::from_file("PrivateKey4");

        let matrix = cmp_matrix(&ctx);
        for lut in matrix {
            private_key.print_lut(lut, &ctx);
        }
    }

    #[test]
    fn test_blind_lt() {
        let mut ctx = Context::from(PARAM_MESSAGE_4_CARRY_0);
        let private_key = PrivateKey::from_file("PrivateKey4");

        for i in 0..4 {
            for j in 0..4 {
                let a = private_key.allocate_and_encrypt_lwe(i, &mut ctx);
                let b = private_key.allocate_and_encrypt_lwe(j, &mut ctx);
                let result = private_key.public_key.blind_lt(&a, &b, &ctx);
                let expected = if i < j { 1 } else { 0 };
                let actual = private_key.decrypt_lwe(&result, &ctx);
                println!("{} < {}: expected {}, got {}", i, j, expected, actual);
                assert_eq!(actual, expected);
            }
        }
    }

    #[test]
    fn test_blind_sort() {
        let mut ctx = Context::from(PARAM_MESSAGE_2_CARRY_0);
        let private_key = PrivateKey::from_file("PrivateKey2");

        let array = vec![1, 0, 3, 2];
        let mut lut = LUT::from_vec(&array, &private_key, &mut ctx);
        private_key.print_lut(&lut, &ctx);
        // let expected = Vec::from_iter(sorted(array));

        lut = private_key.public_key.blind_sort(lut, &ctx);
        println!("result");
        private_key.print_lut(&lut, &ctx);
    }

    #[test]
    fn test_blind_matrix_access() {
        let mut ctx = Context::from(PARAM_MESSAGE_4_CARRY_0);
        let private_key = PrivateKey::from_file("PrivateKey4");

        let matrix = vec![
            vec![0, 1, 2, 3],
            vec![1, 2, 3, 0],
            vec![2, 3, 0, 1],
            vec![3, 0, 1, 2],
        ];

        let encrypted_matrix = private_key.encrypt_matrix(&mut ctx, &matrix);

        for i in 0..4 {
            let idx = private_key.allocate_and_encrypt_lwe(i, &mut ctx);
            for j in 0..4 {
                let jdx = private_key.allocate_and_encrypt_lwe(j, &mut ctx);
                let expected = matrix[i as usize][j as usize];

                let ciphertext =
                    private_key
                        .public_key
                        .blind_matrix_access(&encrypted_matrix, &idx, &jdx, &ctx);
                let actual = private_key.decrypt_lwe(&ciphertext, &ctx);
                println!(
                    "matrix[{}][{}]: expected {}, got {}",
                    i, j, expected, actual
                );
                assert_eq!(actual, expected);
            }
        }
    }
}
