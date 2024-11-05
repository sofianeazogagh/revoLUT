use std::sync::Mutex;

use rayon::{
    iter::{ParallelBridge, ParallelIterator},
    ThreadPoolBuilder,
};
use tfhe::core_crypto::algorithms::lwe_ciphertext_sub;

use crate::{Context, LUT, LWE};

impl crate::PublicKey {
    pub fn blind_topk(&self, lwes: &[LWE], k: usize, ctx: &Context) -> Vec<LWE> {
        self.blind_topk_many_lut(&(vec![lwes.to_vec()]), k, ctx)[0].clone()
    }

    pub fn blind_topk_many_lut(
        &self,
        many_lwes: &Vec<Vec<LWE>>, // slice of slices
        k: usize,
        ctx: &Context,
    ) -> Vec<Vec<LWE>> {
        self.blind_topk_many_lut_par(many_lwes, k, 1, ctx)
    }

    // TODO : a generalisé pour m vecteurs de lwe (pour l'instant m=2)
    pub fn blind_topk_many_lut_par(
        &self,
        many_lwes: &Vec<Vec<LWE>>, // slice of slices
        k: usize,
        num_threads: usize,
        ctx: &Context,
    ) -> Vec<Vec<LWE>> {
        // Créez un pool de threads avec 4 threads
        let pool = ThreadPoolBuilder::new()
            .num_threads(num_threads)
            .build()
            .unwrap();

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
        self.blind_topk_many_lut_par(&result, k, num_threads, ctx)
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
            self.sample_extract(&sorted_lut, 0, ctx),
            self.sample_extract(&sorted_lut, 1, ctx),
        )
    }

    pub fn yao_topk(&self, lwes: &[LWE], k: usize, ctx: &Context) -> Vec<LWE> {
        vec![]
    }
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

        let lwes2: Vec<LWE> = (0..array.len() - 1)
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

        for i in 0..n as u64 {
            for j in 0..n as u64 {
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

                println!("({i}, {j}) -> ({dsa1}, {dsb1}) = ({dsa2}, {dsb2})");

                assert_eq!((dsa1, dsb1), (i.min(j), i.max(j)));
                assert_eq!((dsa2, dsb2), (i.min(j), i.max(j)));
            }
        }
    }
}
