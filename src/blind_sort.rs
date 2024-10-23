use tfhe::core_crypto::{
    algorithms::{lwe_ciphertext_add_assign, lwe_ciphertext_sub, lwe_ciphertext_sub_assign},
    entities::LweCiphertext,
};

use crate::{Context, LUT};

impl crate::PublicKey {
    /// compares a and b blindly, returning a cipher of 1 if a < b else 0
    /// if working in param n bits, expect a and b to be in n-1 bits
    fn blind_lt(
        &self,
        a: &LweCiphertext<Vec<u64>>,
        b: &LweCiphertext<Vec<u64>>,
        ctx: &Context,
    ) -> LweCiphertext<Vec<u64>> {
        let n = ctx.full_message_modulus();
        let mut container = vec![0; n / 2];
        container.extend(vec![2 * n as u64 - 1; n / 2]);
        let lut = LUT::from_vec_trivially(&container, ctx);
        let mut output = self.allocate_and_trivially_encrypt_lwe(0, ctx);
        lwe_ciphertext_sub(&mut output, &a, &b);
        let res = self.blind_array_access(&output, &lut, ctx);
        res
    }

    /// Direct Sort of values
    /// given param n bits, assume inputs are n-1 bits
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
        let identity = LUT::from_function(|x| x, ctx);
        let isnull = LUT::from_function(|x| if x == 0 { 1 } else { 0 }, ctx);
        let mut permutation = vec![];
        for i in 0..n {
            let mut current = self.sample_extract(&lut, i, ctx);
            let b = self.run_lut(&current, &isnull, &ctx);
            lwe_ciphertext_add_assign(&mut cpt, &b);
            cpt = self.run_lut(&cpt, &identity, ctx); // refresh cpt noise
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

    pub fn blind_counting_sort(&self, lut: &LUT, ctx: &Context) -> LUT {
        let n = ctx.full_message_modulus;
        let mut count = LUT::from_vec_trivially(&vec![0; n], ctx);

        // step 1: count values
        for i in 0..n {
            let j = self.sample_extract(&lut, i, ctx);
            self.blind_array_inject_trivial(&mut count, &j, 1, ctx);
        }

        // step 2: build prefix sum
        for i in 1..n {
            let c = self.sample_extract(&count, i - 1, ctx);
            let j = self.allocate_and_trivially_encrypt_lwe(i as u64, ctx);
            self.blind_array_inject(&mut count, &j, &c, ctx);
        }

        // step 3: rebuild sorted list
        let mut result = LUT::from_vec_trivially(&vec![0; n], ctx);
        for i in (0..n).rev() {
            let j = self.sample_extract(&lut, i, ctx);
            self.blind_array_inject_trivial(&mut count, &j, 2 * n as u64 - 1, ctx);
            let c = self.blind_array_access(&j, &count, ctx);
            self.blind_array_inject(&mut result, &c, &j, ctx);
        }

        result
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
        let mut ctx = Context::from(PARAM_MESSAGE_4_CARRY_0);
        let private_key = key(ctx.parameters);
        let n = ctx.full_message_modulus();
        let public_key = &private_key.public_key;

        for a in 0..n / 2 {
            let c_a = private_key.allocate_and_encrypt_lwe(a as u64, &mut ctx);
            for b in 0..n / 2 {
                let c_b = private_key.allocate_and_encrypt_lwe(b as u64, &mut ctx);
                let begin = Instant::now();
                let c_res = public_key.blind_lt(&c_a, &c_b, &ctx);
                let elapsed = Instant::now() - begin;
                let res = private_key.decrypt_lwe(&c_res, &ctx);
                println!("{} < {} is {} ({}) ({:?})", a, b, res, res == 1, elapsed);

                assert!(res == if a < b { 1 } else { 0 });
            }
        }
    }

    #[test]
    fn test_blind_sort_bma() {
        let params = [PARAM_MESSAGE_3_CARRY_0, PARAM_MESSAGE_4_CARRY_0];
        let arrays = [
            vec![1, 2, 1, 0, 2, 1, 2, 3],
            vec![1, 3, 2, 4, 4, 7, 6, 5, 6, 6, 6, 6, 6, 6, 6, 6],
        ];
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
        let array = vec![1, 3, 2, 0, 6, 5, 7, 4, 8, 10, 9, 11, 13, 15, 14, 12];
        let lut = LUT::from_vec(&array, &private_key, &mut ctx);
        print!("lut: ");
        lut.print(&private_key, &ctx);

        let begin = Instant::now();
        let sorted_lut = public_key.blind_sort_2bp(lut, &ctx);
        let elapsed = Instant::now() - begin;
        print!("sorted {:?}: ", elapsed);
        sorted_lut.print(&private_key, &ctx);

        let expected_array = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 0];
        for i in 0..expected_array.len() {
            let lwe = public_key.sample_extract(&sorted_lut, i, &ctx);
            let actual = private_key.decrypt_lwe(&lwe, &ctx);
            assert_eq!(actual, expected_array[i as usize]);
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
        // let array = vec![2, 1, 3, 1, 0, 0, 0, 0];
        let array = vec![2, 2, 4, 2, 7, 4, 4, 7];

        // for i in 0..100 {
        let lut = LUT::from_vec(&array, &private_key, &mut ctx);
        let begin = Instant::now();
        let sorted_lut = public_key.blind_counting_sort(&lut, &ctx);
        let elapsed = Instant::now() - begin;
        println!("run ({:?})", elapsed);
        sorted_lut.print(&private_key, &ctx);

        // let expected_array = vec![0, 0, 0, 0, 1, 1, 2, 3];
        let expected_array = vec![2, 2, 2, 4, 4, 4, 7, 7];
        for i in 0..array.len() {
            let lwe = public_key.sample_extract(&sorted_lut, i, &ctx);
            let actual = private_key.decrypt_lwe(&lwe, &ctx);
            assert_eq!(actual, expected_array[i]);
        }
        // }
    }
}
