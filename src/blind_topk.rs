use std::{sync::Mutex, time::Instant};

use rayon::{
    iter::{ParallelBridge, ParallelIterator},
    ThreadPoolBuilder,
};
use tfhe::core_crypto::algorithms::lwe_ciphertext_sub;

use crate::{Context, LUT, LWE};

impl crate::PublicKey {
    pub fn blind_topk(&self, lwes: &[LWE], k: usize, ctx: &Context) -> Vec<LWE> {
        self.blind_topk_many_lut(&(vec![lwes.to_vec()]), k, ctx)
            .into_iter()
            .next()
            .unwrap()
    }

    pub fn blind_topk_many_lut(
        &self,
        many_lwes: &Vec<Vec<LWE>>, // slice of slices
        k: usize,
        ctx: &Context,
    ) -> Vec<Vec<LWE>> {
        self.blind_topk_many_lut_par(many_lwes, k, 4, ctx)
    }

    pub fn blind_topk_many_lut_par(
        &self,
        many_lwes: &Vec<Vec<LWE>>, // slice of slices
        k: usize,
        num_threads: usize,
        ctx: &Context,
    ) -> Vec<Vec<LWE>> {
        let n = ctx.full_message_modulus();
        let m = many_lwes.len();
        let num_elements = many_lwes[0].len();
        for lwes in many_lwes {
            assert_eq!(lwes.len(), num_elements);
        }
        // Créez un pool de threads avec 4 threads
        let pool = ThreadPoolBuilder::new()
            .num_threads(num_threads)
            .build()
            .unwrap();

        println!("new round of top{k} with {} elements", many_lwes[0].len());
        if num_elements <= k {
            return many_lwes.to_vec();
        }
        assert!(k < n);

        // Utilisez le pool de threads pour paralléliser l'itération
        let results = pool.scope(|_| {
            (0..many_lwes[0].len())
                .collect::<Vec<usize>>()
                .chunks(n)
                .par_bridge()
                .map(|chunk| {
                    // make a lut from each sequence of lwes
                    let luts = Vec::from_iter(many_lwes.iter().map(|lwes| {
                        LUT::from_vec_of_lwe(
                            &Vec::from_iter(chunk.iter().map(|&i| lwes[i].clone())),
                            self,
                            ctx,
                        )
                    }));
                    let start = Instant::now();
                    let sorted_luts = self.many_blind_counting_sort_k(
                        &Vec::from_iter(luts.iter()),
                        ctx,
                        chunk.len(),
                    );
                    println!("{:?}", Instant::now() - start);

                    Vec::from_iter(sorted_luts.iter().map(|sorted_lut| {
                        Vec::from_iter(
                            (0..k.min(chunk.len())).map(|i| self.lut_extract(sorted_lut, i, ctx)),
                        )
                    }))
                })
                .collect::<Vec<_>>()
        });

        let mut next_many_lwes = vec![vec![]; m];
        for result in results {
            for i in 0..m {
                // result is a m-vector of vector of up to k elements
                next_many_lwes[i].extend(result[i].iter().cloned())
            }
        }

        // Appel récursif en style tournoi
        self.blind_topk_many_lut_par(&next_many_lwes, k, num_threads, ctx)
    }

    /// blind comparator costing 1 bit of precision
    pub fn blind_comparator_zuber(&self, (a, b): (LWE, LWE), ctx: &Context) -> (LWE, LWE) {
        let n = ctx.full_message_modulus();
        let mut container = vec![a.clone(); n / 2];
        container.extend(vec![self.neg_lwe(&b, ctx); n / 2]);
        let lut = LUT::from_vec_of_lwe(&container, &self, ctx);
        let mut output = self.allocate_and_trivially_encrypt_lwe(0, ctx);
        lwe_ciphertext_sub(&mut output, &b, &a);
        let fst = self.blind_array_access(&output, &lut, ctx);

        let mut output = self.allocate_and_trivially_encrypt_lwe(0, ctx);
        lwe_ciphertext_sub(&mut output, &a, &b);
        let snd = self.blind_array_access(&output, &lut, ctx);

        (fst, snd)
    }

    /// compare and swaps a and b blindly
    pub fn blind_comparator_bcs(&self, (a, b): (LWE, LWE), ctx: &Context) -> (LWE, LWE) {
        let lut = LUT::from_vec_of_lwe(&[a, b], &self, ctx);
        // lut.print(crate::key(ctx.parameters()), ctx);
        let sorted_lut = self.blind_counting_sort_k(&lut, ctx, 2);
        // print!("sorted:\t");
        // sorted_lut.print(crate::key(ctx.parameters()), ctx);
        (
            self.lut_extract(&sorted_lut, 0, ctx),
            self.lut_extract(&sorted_lut, 1, ctx),
        )
    }

    pub fn blind_comparator_bma(&self, (a, b): (LWE, LWE), ctx: &Context) -> (LWE, LWE) {
        let n = ctx.full_message_modulus;
        let matrix = Vec::from_iter(
            (0..n).map(|lin| Vec::from_iter((0..n).map(|col| if lin < col { 1 } else { 0 }))),
        );
        let twice_bit = self.blind_matrix_access_mv(&matrix, &a, &b, &ctx);
        let mut lut = LUT::from_vec_of_lwe(
            &vec![b.clone(), a.clone(), a.clone(), b.clone()],
            &self,
            &ctx,
        );
        self.blind_rotation_assign(&twice_bit, &mut lut, &ctx);
        (
            self.lut_extract(&lut, 0, ctx),
            self.lut_extract(&lut, 1, ctx),
        )
    }

    // pub fn yao_topk(&self, lwes: &[LWE], k: usize, ctx: &Context) -> Vec<LWE> {
    //     vec![]
    // }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::key;
    use std::time::Instant;
    use tfhe::shortint::parameters::*;

    #[test]
    pub fn test_blind_topk() {
        let param = PARAM_MESSAGE_4_CARRY_0;
        let mut ctx = Context::from(param);
        let private_key = key(ctx.parameters);
        let public_key = &private_key.public_key;

        let mut array = vec![10u64; 30];
        array[1] = 1;
        // array[100] = 2;
        // array[150] = 3;
        // array[200] = 4;

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
    pub fn test_many_blind_topk_lut() {
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

        let lwes2: Vec<LWE> = (0..array.len())
            .map(|i| private_key.allocate_and_encrypt_lwe(i as u64, &mut ctx))
            .collect();

        let many_lwes = vec![lwes1, lwes2];

        let start = Instant::now();
        let res = public_key.blind_topk_many_lut(&many_lwes, 3, &ctx);
        println!("total time: {:?}", Instant::now() - start);

        for vec_lwe in res {
            println!("vec_lwe");
            for lwe in vec_lwe {
                println!("{}", private_key.decrypt_lwe(&lwe, &ctx));
            }
        }
    }

    #[test]
    fn test_blind_comparator() {
        let param = PARAM_MESSAGE_4_CARRY_0;
        let mut ctx = Context::from(param);
        let param_zuber = PARAM_MESSAGE_5_CARRY_0;
        let mut ctx_zuber = Context::from(param_zuber);
        let n = ctx.full_message_modulus();
        let private_key = key(ctx.parameters);
        let public_key = &private_key.public_key;
        let private_key_zuber = key(ctx_zuber.parameters());
        let public_key_zuber = &private_key_zuber.public_key;

        for i in (0..n as u64).step_by(2) {
            for j in (0..n as u64).step_by(3) {
                let a = private_key_zuber.allocate_and_encrypt_lwe(i, &mut ctx_zuber);
                let b = private_key_zuber.allocate_and_encrypt_lwe(j, &mut ctx_zuber);
                let start = Instant::now();
                let (sa, sb) = public_key_zuber.blind_comparator_zuber((a, b), &ctx_zuber);
                print!("zuber: {}ms\t", (Instant::now() - start).as_millis());
                let dsa1 = private_key_zuber.decrypt_lwe(&sa, &ctx_zuber);
                let dsb1 = private_key_zuber.decrypt_lwe(&sb, &ctx_zuber);

                let a = private_key.allocate_and_encrypt_lwe(i, &mut ctx);
                let b = private_key.allocate_and_encrypt_lwe(j, &mut ctx);
                let start = Instant::now();
                let (sa, sb) = public_key.blind_comparator_bcs((a, b), &ctx);
                print!("bcs: {:?}ms\t", (Instant::now() - start).as_millis());
                let dsa2 = private_key.decrypt_lwe(&sa, &ctx);
                let dsb2 = private_key.decrypt_lwe(&sb, &ctx);

                let a = private_key.allocate_and_encrypt_lwe(i, &mut ctx);
                let b = private_key.allocate_and_encrypt_lwe(j, &mut ctx);
                let start = Instant::now();
                let (sa, sb) = public_key.blind_comparator_bma((a, b), &ctx);
                print!("bma: {:?}ms\t", (Instant::now() - start).as_millis());
                let dsa3 = private_key.decrypt_lwe(&sa, &ctx);
                let dsb3 = private_key.decrypt_lwe(&sb, &ctx);

                println!("({i}, {j}) -> ({dsa1}, {dsb1}) = ({dsa2}, {dsb2}) = ({dsa3}, {dsb3})");

                assert_eq!((dsa1, dsb1), (i.min(j), i.max(j)));
                assert_eq!((dsa2, dsb2), (i.min(j), i.max(j)));
                assert_eq!((dsa3, dsb3), (i.min(j), i.max(j)));
            }
        }
    }
}
