use std::sync::OnceLock;

use tfhe::core_crypto::{
    algorithms::{lwe_ciphertext_add_assign, lwe_ciphertext_sub_assign},
    entities::LweCiphertext,
};

#[cfg(test)]
use crate::{key2, key4};
use crate::{Context, LUT};

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

impl crate::PublicKey {
    /// compares a and b blindly, returning a cipher of 1 if a < b else 0
    fn blind_lt(
        &self,
        a: &LweCiphertext<Vec<u64>>,
        b: &LweCiphertext<Vec<u64>>,
        ctx: &Context,
    ) -> LweCiphertext<Vec<u64>> {
        self.blind_matrix_access(cmp_matrix(ctx), b, a, ctx)
    }

    /// Direct Sort of distinct values
    pub fn blind_sort_bma(&self, lut: LUT, ctx: &Context) -> LUT {
        let n = ctx.full_message_modulus;
        let zero = self.allocate_and_trivially_encrypt_lwe(0, ctx);
        let mut permutation = vec![zero; n];
        let one = self.allocate_and_trivially_encrypt_lwe(1, ctx);
        for col in 0..n {
            let a = self.at(&lut, col, ctx);
            for lin in 0..col {
                let b = self.at(&lut, lin, ctx);
                let res = self.blind_lt(&a, &b, ctx);
                lwe_ciphertext_add_assign(&mut permutation[lin], &res);
                lwe_ciphertext_add_assign(&mut permutation[col], &one);
                lwe_ciphertext_sub_assign(&mut permutation[col], &res);
            }
        }

        #[cfg(test)]
        {
            let private_key = key2();
            let decrypted: Vec<u64> = (0..n)
                .map(|i| private_key.decrypt_lwe(&permutation[i], ctx))
                .collect();
            println!("decrypted permutation {:?}", decrypted);
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
            let mut current = self.at(&lut, i, ctx);
            let b = self.eq_scalar(&current, 0, ctx);
            lwe_ciphertext_add_assign(&mut cpt, &b);
            lwe_ciphertext_sub_assign(&mut current, &cpt);
            permutation.push(current);
        }
        permutation
    }

    pub fn blind_sort_2bp(&self, lut: LUT, ctx: &Context) -> LUT {
        let n = ctx.full_message_modulus;

        // read the lut as a permutation, and apply it to itself
        let permutation = Vec::from_iter((0..n).map(|i| self.at(&lut, i, &ctx)));
        #[cfg(test)]
        {
            let v = Vec::from_iter(permutation.iter().map(|p| key4().decrypt_lwe(p, ctx)));
            println!("permutation: {:?}", v);
        }
        let permuted_lut = self.blind_permutation(lut, permutation, ctx);

        print!("permuted lut: ");
        #[cfg(test)]
        permuted_lut.print(key4(), ctx);

        // compacts non-null values to the left
        let second_permutation = self.compute_compact_permutation(&permuted_lut, ctx);
        self.blind_permutation(permuted_lut, second_permutation, ctx)
    }
}

#[cfg(test)]
mod tests {
    use tfhe::shortint::parameters::{PARAM_MESSAGE_2_CARRY_0, PARAM_MESSAGE_4_CARRY_0};

    use crate::{key2, key4, Context, LUT};


    #[test]
    fn test_blind_lt() {
        let mut ctx = Context::from(PARAM_MESSAGE_2_CARRY_0);
        let private_key = key2();
        let public_key = &private_key.public_key;

        for a in 0..ctx.message_modulus().0 {
            let c_a = private_key.allocate_and_encrypt_lwe(a as u64, &mut ctx);
            for b in 0..ctx.message_modulus().0 {
                let c_b = private_key.allocate_and_encrypt_lwe(b as u64, &mut ctx);
                let c_res = public_key.blind_lt(&c_a, &c_b, &ctx);
                let res = private_key.decrypt_lwe(&c_res, &ctx);

                assert!(res == if a < b { 1 } else { 0 });
            }
        }
    }

    #[test]
    fn test_blind_sort_bma() {
        let mut ctx = Context::from(PARAM_MESSAGE_2_CARRY_0);
        let private_key = key2();
        let public_key = &private_key.public_key;
        let array = vec![1, 3, 2, 0];
        let lut = LUT::from_vec(&array, &private_key, &mut ctx);
        lut.print(&private_key, &ctx);

        let sorted_lut = public_key.blind_sort_bma(lut, &ctx);
        println!("sorted");
        sorted_lut.print(&private_key, &ctx);

        let expected_array = vec![0, 1, 2, 3];
        for i in 0..ctx.full_message_modulus {
            let lwe = public_key.at(&sorted_lut, i, &ctx);
            let actual = private_key.decrypt_lwe(&lwe, &ctx);
            assert_eq!(actual, expected_array[i]);
        }
    }

    #[test]
    fn test_blind_sort_2bp() {
        let mut ctx = Context::from(PARAM_MESSAGE_4_CARRY_0);
        let private_key = key4();
        let public_key = &private_key.public_key;
        let array = vec![5, 7, 3, 2];
        let lut = LUT::from_vec(&array, &private_key, &mut ctx);
        print!("lut: ");
        lut.print(&private_key, &ctx);

        let sorted_lut = public_key.blind_sort_2bp(lut, &ctx);
        print!("sorted: ");
        sorted_lut.print(&private_key, &ctx);

        let expected_array = vec![2, 3, 5, 7];
        for i in 0..4 {
            let lwe = public_key.at(&sorted_lut, i, &ctx);
            let actual = private_key.decrypt_lwe(&lwe, &ctx);
            assert_eq!(actual, expected_array[i]);
        }
    }

    #[test]
    fn test_compute_compact_permutation() {
        let mut ctx = Context::from(PARAM_MESSAGE_4_CARRY_0);
        let private_key = key4();
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
}
