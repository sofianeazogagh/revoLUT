use crate::{
    key,
    nlwe::{from_digits, to_digits, NLWE},
    packed_lut::PackedMNLUT,
    Context, PrivateKey, PublicKey, LUT,
};
use ndarray::{Array, Dimension, IxDyn};
use std::time::Instant;

/// A structure holding N digit values indexed by M digit values
#[derive(Clone)]
pub struct MNLUT {
    /// M dimensional array of NLWEs
    pub nlwes: Array<NLWE, IxDyn>,
}

impl MNLUT {
    /// Returns M, the number of digits to index a single value
    pub fn m(&self) -> usize {
        self.nlwes.dim().ndim()
    }

    /// Returns N, the number of digits held by values
    pub fn n(&self) -> usize {
        self.nlwes.first().map(|nlwe| nlwe.n()).unwrap_or(0)
    }

    pub fn from_plain(
        input: &[u64],
        m: usize,
        n: usize,
        private_key: &PrivateKey,
        ctx: &mut Context,
    ) -> Self {
        let p = ctx.full_message_modulus as u64;
        Self {
            nlwes: Array::from_shape_fn(IxDyn(&vec![p as usize; m]), |indices| {
                let idx_digits = Vec::from_iter((0..m).map(|i| indices[i] as u64));
                let idx = from_digits(&idx_digits, p) as usize;
                NLWE::from_plain(input[idx], n, ctx, private_key)
            }),
        }
    }

    pub fn bootstrap(&mut self, ctx: &Context, public_key: &PublicKey) {
        for nlwe in self.nlwes.iter_mut() {
            nlwe.bootstrap(ctx, public_key);
        }
    }

    pub fn to_plain(&self, ctx: &Context, private_key: &PrivateKey) -> Vec<u64> {
        self.nlwes
            .iter()
            .map(|nlwe| nlwe.to_plain(ctx, private_key))
            .collect()
    }

    pub fn from_plain_trivially(
        input: &[u64],
        m: usize,
        n: usize,
        public_key: &PublicKey,
        ctx: &Context,
    ) -> Self {
        let p = ctx.full_message_modulus as u64;
        Self {
            nlwes: Array::from_shape_fn(IxDyn(&vec![p as usize; m]), |indices| {
                let idx_digits = Vec::from_iter((0..m).map(|i| indices[i] as u64));
                let idx = from_digits(&idx_digits, p) as usize;
                NLWE::from_plain_trivially(input[idx], n, ctx, public_key)
            }),
        }
    }

    /// Read a n-digit value from the LUT at index given by a m-digit value
    pub fn at(&self, index: u64, ctx: &Context) -> NLWE {
        self.at_digits(to_digits(index, self.m(), ctx.full_message_modulus as u64))
    }

    /// Read a n-digit value from the LUT at index given by a m-digit value
    pub fn at_digits(&self, index: Vec<u64>) -> NLWE {
        let idx_digits = Vec::from_iter(index.iter().map(|&d| d as usize));
        self.nlwes[IxDyn(&idx_digits)].clone()
    }

    /// Fetch an encrypted n-digit value from the LUT at index given by an encrypted m-digit value
    pub fn blind_tensor_access(&self, index: &NLWE, ctx: &Context, public_key: &PublicKey) -> NLWE {
        assert_eq!(index.n(), self.m());
        let p = ctx.full_message_modulus as u64;
        if self.m() == 1 {
            return NLWE {
                digits: (0..self.n())
                    .map(|i| {
                        let data =
                            Vec::from_iter(self.nlwes.iter().map(|nlwe| nlwe.digits[i].clone()));
                        let lut = LUT::from_vec_of_lwe(&data, public_key, ctx);
                        public_key.blind_array_access(&index.digits[0], &lut, ctx)
                    })
                    .collect(),
            };
        }

        // construct the index into the lower dimensional MNLUT by ignoring the first digit
        let rest = &NLWE {
            digits: index.digits[1..].to_vec(),
        };

        // Otherwise M at least 2, pack p NLWEs from subspaces into a single MNLUT with m = 1
        let line = Self {
            nlwes: Array::from_shape_fn(IxDyn(&vec![p as usize; 1]), |i| {
                // get a lower dimensional MNLUT by fixing the first index digit to i
                let subspace = Self {
                    nlwes: Array::from_shape_fn(
                        IxDyn(&vec![p as usize; self.m() - 1]),
                        |indices| {
                            let mut idx = vec![i[0]];
                            idx.extend_from_slice(&Vec::from_iter(
                                (0..self.m() - 1).map(|j| indices[j]),
                            ));
                            self.nlwes[IxDyn(&idx)].clone()
                        },
                    ),
                };

                subspace.blind_tensor_access(rest, ctx, public_key)
            }),
        };

        line.blind_tensor_access(
            &NLWE {
                digits: vec![index.digits[0].clone()],
            },
            ctx,
            public_key,
        )
    }

    /// Write a n-digit value to the LUT at index given by a m-digit value (Overwriting previous value)
    /// Returns the previous and new values
    pub fn blind_tensor_update<F: Fn(&NLWE) -> NLWE>(
        &mut self,
        index: &NLWE,
        f: F,
        ctx: &Context,
        public_key: &PublicKey,
    ) -> (NLWE, NLWE) {
        assert_eq!(index.n(), self.m());
        // prefetch and negate current value to offset the addition
        let prev = self.blind_tensor_access(&index, ctx, public_key);
        let next = f(&prev);
        assert_eq!(next.n(), self.n());
        let value = next.sub_digitwise_overflow(&prev);

        self.blind_tensor_add_digitwise_overflow(index, &value, ctx, public_key);
        (prev, next)
    }

    /// Adds a n-digit value to the LUT at index given by a m-digit value (digit-wise, without carry)
    pub fn blind_tensor_add_digitwise_overflow(
        &mut self,
        index: &NLWE,
        value: &NLWE,
        ctx: &Context,
        public_key: &PublicKey,
    ) {
        assert_eq!(index.n(), self.m());
        assert_eq!(value.n(), self.n());
        let mask = Self::blind_tensor_lift(index, value, ctx, public_key);
        // add computed luts to the current luts
        self.nlwes.zip_mut_with(&mask.nlwes, |a, b| {
            *a = a.add_digitwise_overflow(&b);
        });
    }

    /// Lift a n-digit value to the LUT at index given by a m-digit value
    pub fn blind_tensor_lift(
        index: &NLWE,
        value: &NLWE,
        ctx: &Context,
        public_key: &PublicKey,
    ) -> MNLUT {
        let p = ctx.full_message_modulus as u64;
        let m = index.n();
        let n = value.n();

        let mut nlwes = Array::from_shape_fn(IxDyn(&vec![p as usize; 0]), |_| value.clone());

        for d in 1..=m {
            // Lift all LWEs to the next dimension and rotate along the newly created axis
            let luts = Array::from_shape_fn(IxDyn(&vec![p as usize; d - 1]), |indices| {
                Vec::from_iter((0..n).map(|i| {
                    let mut lut = LUT::from_lwe(&nlwes[&indices].digits[i], public_key, ctx);
                    let ndigit = public_key.neg_lwe(&index.digits[d - 1], ctx);
                    public_key.blind_rotation_assign(&ndigit, &mut lut, ctx);
                    lut.to_many_lwe(public_key, ctx)
                }))
            });

            // extract LWEs from rotated LUTs
            nlwes = Array::from_shape_fn(IxDyn(&vec![p as usize; d]), |indices| {
                let idx = Vec::from_iter((0..d - 1).map(|k| indices[k]));
                NLWE {
                    digits: Vec::from_iter(
                        (0..n).map(|i| luts[&IxDyn(&idx)][i][indices[d - 1]].clone()),
                    ),
                }
            });
        }

        MNLUT { nlwes }
    }

    pub fn blind_tensor_increment(&mut self, index: &NLWE, ctx: &Context, public_key: &PublicKey) {
        assert_eq!(index.n(), self.m());

        self.blind_tensor_update(
            index,
            |nlwe| nlwe.increment(ctx, public_key),
            ctx,
            public_key,
        );
    }

    /// Decrements NLWE at given index and return value after decrement
    pub fn blind_tensor_post_decrement(
        &mut self,
        index: &NLWE,
        ctx: &Context,
        public_key: &PublicKey,
    ) -> NLWE {
        assert_eq!(index.n(), self.m());

        let (_, next) = self.blind_tensor_update(
            index,
            |nlwe| nlwe.decrement(ctx, public_key),
            ctx,
            public_key,
        );

        next
    }

    /// Sort the LUT using a blind counting sort by a key function
    pub fn blind_counting_sort(&self, d: usize, ctx: &Context, public_key: &PublicKey) -> MNLUT {
        let p = ctx.full_message_modulus;
        let (m, n) = (self.m(), self.n());
        let private_key = key(ctx.parameters);
        let count = MNLUT::from_plain_trivially(&vec![0; p], 1, m, public_key, ctx);
        let mut count = PackedMNLUT::from_mnlut(&count, ctx, public_key);

        println!("self {:02x?}", self.to_plain(ctx, private_key));
        // count the number of elements in each bucket
        println!("counting phase");
        let start = Instant::now();
        for nlwe in self.nlwes.iter() {
            count.blind_tensor_increment(&NLWE::from(&nlwe[d]), ctx, public_key);
            println!(
                "{:?} {:?}",
                count.to_mnlut(ctx, public_key).to_plain(ctx, private_key),
                Instant::now() - start,
            );
        }
        println!("count {:?}", Instant::now() - start);

        // unpack count and compute the prefix sum
        println!("prefix sum");
        let start = Instant::now();
        let mut count = count.to_mnlut(ctx, public_key);
        for i in 1..p {
            let prev = count.at(i as u64 - 1, ctx);
            let idx = IxDyn(&vec![i]);
            count.nlwes[&idx] = count.nlwes[&idx].add(&prev, ctx, public_key);
            println!("{:?}", count.to_plain(ctx, private_key));
        }
        println!("acc {:?}", Instant::now() - start);

        // rebuild the sorted LUT
        println!("rebuild LUT");
        let mut count = PackedMNLUT::from_mnlut(&count, ctx, public_key);
        let start = Instant::now();
        let zeroes = &vec![0; p.pow(self.m() as u32)];
        let result = MNLUT::from_plain_trivially(zeroes, m, n, public_key, ctx);
        let mut result = PackedMNLUT::from_mnlut(&result, ctx, public_key);
        for i in (0..p.pow(m as u32)).rev() {
            let nlwe = self.at(i as u64, ctx);
            let pos = count.blind_tensor_post_decrement(&NLWE::from(&nlwe[d]), ctx, public_key);
            result.blind_tensor_add_digitwise_overflow(&pos, &nlwe, ctx, public_key);
            println!(
                "added {:?} at index {:?}: {:?} (count: {:?})",
                nlwe.to_plain(ctx, private_key),
                pos.to_plain(ctx, private_key),
                result.to_mnlut(ctx, public_key).to_plain(ctx, private_key),
                count.to_mnlut(ctx, public_key).to_plain(ctx, private_key)
            );
        }
        let result = result.to_mnlut(ctx, public_key);
        println!("rebuild {:?}", Instant::now() - start);
        println!("{:02x?}", result.to_plain(ctx, private_key));
        result
    }

    pub fn blind_radix_sort(&self, ctx: &Context, public_key: &PublicKey) -> MNLUT {
        let mut sorted = self.clone();
        for d in (0..self.n()).rev() {
            println!("sorting by digit {d}");
            let start = Instant::now();
            sorted = sorted.blind_counting_sort(d, ctx, public_key);
            println!("sortin by digit {d} took {:?}", Instant::now() - start);
        }
        sorted
    }
}

#[cfg(test)]
mod tests {
    use std::time::Instant;

    use super::*;
    use crate::key;
    use itertools::Itertools;
    use tfhe::shortint::parameters::*;

    #[test]
    pub fn test_blind_tensor_access() {
        let mut ctx = Context::from(PARAM_MESSAGE_4_CARRY_0);
        let private_key = key(ctx.parameters);
        let data = Vec::from_iter(0..16);
        let lut = MNLUT::from_plain(&data, 1, 1, &private_key, &mut ctx);
        println!("testing MNLUT M = 1, N = 1");
        for i in 0..16 {
            let nlwe = lut.at(i, &ctx);
            assert_eq!(nlwe.to_plain(&ctx, &private_key), i);

            let index = NLWE::from_plain(i, 1, &mut ctx, &private_key);
            let start = Instant::now();
            let nlwe = lut.blind_tensor_access(&index, &ctx, &private_key.public_key);
            println!("{i} {:?}", Instant::now() - start);
            assert_eq!(nlwe.to_plain(&ctx, &private_key), i);
        }

        println!("testing MNLUT M = 2, N = 1");
        let data = Vec::from_iter(0..256);
        // println!("{:?}", data);
        let lut = MNLUT::from_plain(&data, 2, 1, &private_key, &mut ctx);
        for i in 0..256 {
            let nlwe = lut.at(i, &ctx);
            assert_eq!(nlwe.to_plain(&ctx, &private_key), data[i as usize] % 16);

            let index = NLWE::from_plain(i, 2, &mut ctx, &private_key);
            let start = Instant::now();
            let nlwe = lut.blind_tensor_access(&index, &ctx, &private_key.public_key);
            let elapsed = Instant::now() - start;
            println!("{}: {:?}", i, elapsed);
            assert_eq!(nlwe.to_plain(&ctx, &private_key), data[i as usize] % 16);
        }
    }

    #[test]
    pub fn test_blind_tensor_add_no_carry() {
        let mut ctx = Context::from(PARAM_MESSAGE_4_CARRY_0);
        let private_key = key(ctx.parameters);

        println!("testing MNLUT M = 2, N = 2");
        // let data = Vec::from_iter(0..256);
        let data = vec![0; 256];
        let mut lut = MNLUT::from_plain(&data, 2, 2, &private_key, &mut ctx);
        // for i in (0..256).step_by(15) {
        for i in 0..16 {
            let index = NLWE::from_plain(i * 15, 2, &mut ctx, &private_key);
            let value = NLWE::from_plain(i, 2, &mut ctx, &private_key);
            let start = Instant::now();
            // let actual =
            //     MNLUT::blind_tensor_lift(&index, &value, &ctx, &private_key.public_key);
            //
            lut.blind_tensor_add_digitwise_overflow(&index, &value, &ctx, &private_key.public_key);
            println!(
                "add {} to lut at {} ({:?})",
                i,
                i * 15,
                Instant::now() - start
            );
            println!("{:02x?}", lut.to_plain(&ctx, private_key));
            let nlwe = lut.at(i * 15, &ctx);
            assert_eq!(nlwe.to_plain(&ctx, &private_key), i % 256);
        }
    }

    #[test]
    pub fn test_blind_tensor_increment() {
        let mut ctx = Context::from(PARAM_MESSAGE_4_CARRY_0);
        let p = ctx.full_message_modulus() as u64;
        let private_key = key(ctx.parameters);
        let (m, n) = (1, 2);
        let size = p.pow(m as u32);
        let range = p.pow(n as u32);

        let data = Vec::from_iter((0..size).map(|i| i % range));
        let mut lut = MNLUT::from_plain(&data, m, n, &private_key, &mut ctx);

        for i in 0..size {
            let index = NLWE::from_plain(i, m, &mut ctx, &private_key);
            let start = Instant::now();
            lut.blind_tensor_increment(&index, &ctx, &private_key.public_key);
            let elapsed = Instant::now() - start;
            let actual = lut.at(i, &ctx).to_plain(&ctx, &private_key);
            let expected = (data[i as usize] + 1) % range;
            println!("{i}: got {actual} expected {expected} elapsed {elapsed:?}",);
            assert_eq!(actual, expected);
        }
    }

    #[test]
    pub fn test_blind_radix_sort() {
        let mut ctx = Context::from(PARAM_MESSAGE_4_CARRY_0);
        let private_key = key(ctx.parameters);
        let (m, n) = (2, 2);
        let size = ctx.full_message_modulus().pow(m as u32) as u64;
        let range = ctx.full_message_modulus().pow(n as u32) as u64;
        let data = Vec::from_iter((0..size as u64).map(|x| x % range).rev());
        println!("{:?}", data);
        let lut = MNLUT::from_plain(&data, m, n, &private_key, &mut ctx);
        let start = Instant::now();
        let sorted = lut.blind_radix_sort(&ctx, &private_key.public_key);
        println!("total elapsed {:?}", Instant::now() - start);

        for i in 0..size {
            let nlwe = sorted.at(i, &ctx);
            println!("{}", nlwe.to_plain(&ctx, private_key));
        }

        let expected = data.iter().sorted().collect::<Vec<_>>();
        for i in 0..size {
            let nlwe = sorted.at(i, &ctx);
            assert_eq!(nlwe.to_plain(&ctx, &private_key), *expected[i as usize]);
        }
    }
}
