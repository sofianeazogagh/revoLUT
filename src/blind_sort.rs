use std::sync::OnceLock;

use tfhe::{
    core_crypto::{
        algorithms::{lwe_ciphertext_add_assign, lwe_ciphertext_sub_assign},
        entities::LweCiphertext,
    },
    shortint::parameters::*,
};

use crate::{Context, LUT};

/// lazily compute a trivially encrypted boolean comparison matrix of the form:
/// ```text
/// 0 0 0
/// 1 0 0
/// 1 1 0
/// ```
fn cmp_matrix(bitsize: usize) -> &'static Vec<LUT> {
    let params = [
        PARAM_MESSAGE_1_CARRY_0,
        PARAM_MESSAGE_2_CARRY_0,
        PARAM_MESSAGE_3_CARRY_0,
        PARAM_MESSAGE_4_CARRY_0,
        PARAM_MESSAGE_5_CARRY_0,
    ];
    static MATRICES: OnceLock<Vec<Vec<LUT>>> = OnceLock::new();
    &MATRICES.get_or_init(|| {
        Vec::from_iter((1..=5).map(|b| {
            let n = 1 << b;
            Vec::from_iter((0..n).map(|i| {
                LUT::from_vec_trivially(
                    &Vec::from_iter((0..n).map(|j| if j < i { 1 } else { 0 })),
                    &Context::from(params[b - 1]),
                )
            }))
        }))
    })[bitsize - 1]
}

impl crate::PublicKey {
    /// compares a and b blindly, returning a cipher of 1 if a < b else 0
    fn blind_lt(
        &self,
        a: &LweCiphertext<Vec<u64>>,
        b: &LweCiphertext<Vec<u64>>,
        ctx: &Context,
    ) -> LweCiphertext<Vec<u64>> {
        let bitsize = ctx.full_message_modulus().ilog2() as usize;
        self.blind_matrix_access(cmp_matrix(bitsize), b, a, ctx)
    }

    /// Direct Sort of distinct values
    pub fn blind_sort_bma(&self, lut: LUT, ctx: &Context) -> LUT {
        let n = ctx.full_message_modulus;
        let zero = self.allocate_and_trivially_encrypt_lwe(0, ctx);
        let mut permutation = vec![zero; n];
        let one = self.allocate_and_trivially_encrypt_lwe(1, ctx);
        for col in 0..n {
            let a = self.sample_extract(&lut, col, ctx);
            for lin in 0..col {
                let b = self.sample_extract(&lut, lin, ctx);
                let res = self.blind_lt(&a, &b, ctx);
                lwe_ciphertext_add_assign(&mut permutation[lin], &res);
                lwe_ciphertext_add_assign(&mut permutation[col], &one);
                lwe_ciphertext_sub_assign(&mut permutation[col], &res);
            }
        }

        self.blind_permutation(lut, permutation, ctx)
    }

    /// given a sparse but ordered lut, returns a permutation that compacts non-null values to the left
    fn compute_compact_permutation(
        &self,
        lut: &LUT,
        ctx: &Context,
    ) -> Vec<LweCiphertext<Vec<u64>>> {
        let n = ctx.full_message_modulus;
        let mut cpt = self.allocate_and_trivially_encrypt_lwe(0, ctx);
        let mut permutation = vec![];
        for i in 0..n {
            let mut current = self.sample_extract(&lut, i, ctx);
            let b = self.eq_scalar(&current, 0, ctx);
            lwe_ciphertext_add_assign(&mut cpt, &b);
            lwe_ciphertext_sub_assign(&mut current, &cpt);
            permutation.push(current);
        }
        permutation
    }

    /// no zero values
    /// all (non zero) values must be distinct
    pub fn blind_sort_2bp(&self, lut: LUT, ctx: &Context) -> LUT {
        let n = ctx.full_message_modulus;

        // read the lut as a permutation, and apply it to itself
        let permutation = Vec::from_iter((0..n).map(|i| self.sample_extract(&lut, i, &ctx)));
        let permuted_lut = self.blind_permutation(lut, permutation, ctx);

        // compacts non-null values to the left
        let second_permutation = self.compute_compact_permutation(&permuted_lut, ctx);
        self.blind_permutation(permuted_lut, second_permutation, ctx)
    }

    pub fn blind_counting_sort(&self, lut: LUT, ctx: &Context) -> LUT {
        let n = ctx.full_message_modulus;
        let one = self.allocate_and_trivially_encrypt_lwe(1, ctx);
        let mut count = LUT::from_vec_trivially(&vec![0; n], ctx);

        // step 1: count values
        // println!("counting values");
        for i in 0..n {
            let x = self.sample_extract(&lut, i, ctx);
            self.blind_array_add_trivial(&mut count, &x, 1, ctx);
        }
        count.bootstrap(self, ctx);

        // step 2: sort
        // println!("step 2: sorting");
        let mut result = LUT::from_vec_trivially(&vec![0; n], ctx);
        let mut i = self.allocate_and_trivially_encrypt_lwe(0, ctx);
        let mut j = self.allocate_and_trivially_encrypt_lwe(0, ctx);
        let isnull = LUT::from_function(|v| if v == 0 { 1 } else { 0 }, ctx);

        for _idx in 0..2 * n {
            let x = self.blind_array_access(&i, &count, ctx);
            let b = self.run_lut(&x, &isnull, ctx);
            let mut notb = one.clone();
            lwe_ciphertext_sub_assign(&mut notb, &b);
            let f = LUT::from_lwe(&i, &self, &ctx);
            let y = self.run_lut(&b, &f, ctx);
            self.blind_array_add(&mut result, &j, &y, ctx);
            let minusnotb = self.neg_lwe(&notb, ctx);
            self.blind_array_add(&mut count, &i, &minusnotb, ctx);
            count.bootstrap(self, ctx);
            lwe_ciphertext_add_assign(&mut i, &b);
            lwe_ciphertext_add_assign(&mut j, &notb);
        }

        result.bootstrap(self, ctx)
    }
}

#[cfg(test)]
mod tests {
    use std::time::Instant;

    use crate::*;
    use itertools::sorted;
    use tfhe::shortint::parameters::*;

    #[test]
    fn test_blind_lt() {
        let mut ctx = Context::from(PARAM_MESSAGE_2_CARRY_0);
        let private_key = key(PARAM_MESSAGE_2_CARRY_0);
        let public_key = &private_key.public_key;

        for a in 0..ctx.message_modulus().0 {
            let c_a = private_key.allocate_and_encrypt_lwe(a as u64, &mut ctx);
            for b in 0..ctx.message_modulus().0 {
                let c_b = private_key.allocate_and_encrypt_lwe(b as u64, &mut ctx);
                // let begin = Instant::now();
                let c_res = public_key.blind_lt(&c_a, &c_b, &ctx);
                // let elapsed = Instant::now() - begin;
                let res = private_key.decrypt_lwe(&c_res, &ctx);
                // println!("{} < {} is {} ({}) ({:?})", a, b, res, res == 1, elapsed);

                assert!(res == if a < b { 1 } else { 0 });
            }
        }
    }

    #[test]
    fn test_blind_sort_bma() {
        let params = [PARAM_MESSAGE_2_CARRY_0, PARAM_MESSAGE_3_CARRY_0];
        let arrays = [vec![1, 2, 1, 0], vec![1, 3, 2, 4, 4, 7, 6, 5]];
        for (&param, array) in params.iter().zip(arrays) {
            let mut ctx = Context::from(param);
            let private_key = key(ctx.parameters);
            let public_key = &private_key.public_key;
            let lut = LUT::from_vec(&array, &private_key, &mut ctx);

            let begin = Instant::now();
            let sorted_lut = public_key.blind_sort_bma(lut, &ctx);
            let elapsed = Instant::now() - begin;
            println!("{:?}", elapsed);

            let expected_array = Vec::from_iter(sorted(array));
            println!("expected: {:?}", expected_array);
            println!("actual: ");
            sorted_lut.print(&private_key, &ctx);
            for i in 0..ctx.full_message_modulus {
                let lwe = public_key.sample_extract(&sorted_lut, i, &ctx);
                let actual = private_key.decrypt_lwe(&lwe, &ctx);
                assert_eq!(actual, expected_array[i]);
            }
        }
    }

    #[test]
    fn test_blind_sort_2bp() {
        let mut ctx = Context::from(PARAM_MESSAGE_4_CARRY_0);
        let private_key = key(PARAM_MESSAGE_4_CARRY_0);
        let public_key = &private_key.public_key;
        let array = vec![1, 3, 2, 0];
        let lut = LUT::from_vec(&array, &private_key, &mut ctx);
        print!("lut: ");
        lut.print(&private_key, &ctx);

        let begin = Instant::now();
        let sorted_lut = public_key.blind_sort_2bp(lut, &ctx);
        let elapsed = Instant::now() - begin;
        print!("sorted {:?}: ", elapsed);
        sorted_lut.print(&private_key, &ctx);

        let expected_array = vec![1, 2, 3, 0];
        for i in 0..4 {
            let lwe = public_key.sample_extract(&sorted_lut, i, &ctx);
            let actual = private_key.decrypt_lwe(&lwe, &ctx);
            assert_eq!(actual, expected_array[i]);
        }
    }

    #[test]
    fn test_compute_compact_permutation() {
        let mut ctx = Context::from(PARAM_MESSAGE_4_CARRY_0);
        let private_key = key(PARAM_MESSAGE_4_CARRY_0);
        let public_key = &private_key.public_key;
        let array = vec![0, 0, 2, 3, 0, 5, 0, 7];
        let lut = LUT::from_vec(&array, &private_key, &mut ctx);

        let permutation = public_key.compute_compact_permutation(&lut, &ctx);

        let expected_array = vec![15, 14, 0, 1, 13, 2, 12, 3, 11, 10, 9, 8, 7, 6, 5, 4];
        for (p, expected) in permutation.iter().zip(expected_array) {
            let actual = private_key.decrypt_lwe(&p, &ctx);
            assert_eq!(actual, expected);
        }
    }

    #[test]
    fn test_blind_counting_sort() {
        let param = PARAM_MESSAGE_3_CARRY_0;
        let mut ctx = Context::from(param);
        let private_key = key(param);
        let public_key = &private_key.public_key;
        let array = vec![2, 1, 3, 1, 0, 0, 0, 0];

        // for i in 0..100 {
        let lut = LUT::from_vec(&array, &private_key, &mut ctx);
        // let begin = Instant::now();
        let sorted_lut = public_key.blind_counting_sort(lut, &ctx);
        // let elapsed = Instant::now() - begin;
        // println!("run {} ({:?})", i, elapsed);

        let expected_array = vec![0, 0, 0, 0, 1, 1, 2, 3];
        for i in 0..array.len() {
            let lwe = public_key.sample_extract(&sorted_lut, i, &ctx);
            let actual = private_key.decrypt_lwe(&lwe, &ctx);
            assert_eq!(actual, expected_array[i]);
        }
        // }
    }
}
