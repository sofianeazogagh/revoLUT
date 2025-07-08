use std::time::Instant;

use crate::{lut::MNLUT, nlwe::NLWE, Context, PublicKey, LUT};
use ndarray::{Array, Dimension, IxDyn, Zip};
use tfhe::core_crypto::{commons::utils::ZipChecked, prelude::glwe_ciphertext_add_assign};

/// Pre-packed array of LUT ciphertexts holding p^M values mod p^N
/// last coordinate is index within LUT
pub struct PackedMNLUT {
    /// A (M-1)-way array of N luts
    pub luts: Array<Vec<LUT>, IxDyn>,
}

impl PackedMNLUT {
    pub fn from_mnlut(mnlut: &MNLUT, ctx: &Context, public_key: &PublicKey) -> Self {
        let m = mnlut.m();
        let n = mnlut.n();
        let p = ctx.full_message_modulus();
        Self {
            luts: Array::from_shape_fn(IxDyn(&vec![p; m - 1]), |indices| -> Vec<LUT> {
                let nlwes = Vec::from_iter((0..p).map(|i| {
                    let mut idx = Vec::from_iter((0..m - 1).map(|i| indices[i]));
                    idx.push(i);
                    &mnlut.nlwes[&IxDyn(&idx)]
                }));

                Vec::from_iter((0..n).map(|i| {
                    let lwes = Vec::from_iter(nlwes.iter().map(|&nlwe| nlwe[i].clone()));
                    LUT::from_vec_of_lwe(&lwes, public_key, ctx)
                }))
            }),
        }
    }

    pub fn to_mnlut(&self, ctx: &Context, public_key: &PublicKey) -> MNLUT {
        let m = self.m();
        let n = self.n();
        let p = ctx.full_message_modulus();
        MNLUT {
            nlwes: Array::from_shape_fn(IxDyn(&vec![p; m]), |indices| -> NLWE {
                // extract LWEs from rotated LUTs
                let idx = Vec::from_iter((0..m - 1).map(|k| indices[k]));
                NLWE {
                    digits: Vec::from_iter((0..n).map(|i| {
                        let lut = &self.luts[&IxDyn(&idx)][i];
                        public_key.lut_extract(&lut, indices[m - 1], ctx)
                    })),
                }
            }),
        }
    }

    /// Returns M, the number of digits to index a single value
    pub fn m(&self) -> usize {
        self.luts.dim().ndim() + 1
    }

    /// Returns N, the number of digits held by values
    pub fn n(&self) -> usize {
        self.luts.first().map(|v| v.len()).unwrap_or(0)
    }

    pub fn blind_tensor_access(&self, index: &NLWE, ctx: &Context, public_key: &PublicKey) -> NLWE {
        assert_eq!(index.n(), self.m());
        let p = ctx.full_message_modulus as u64;
        if self.m() == 1 {
            return NLWE {
                digits: self.luts[IxDyn(&[])]
                    .iter()
                    .map(|lut| public_key.blind_array_access(&index.digits[0], &lut, ctx))
                    .collect(),
            };
        }

        // construct the index into the lower dimensional MNLUT by ignoring the first digit
        let rest = &NLWE {
            digits: index.digits[1..].to_vec(),
        };

        // Otherwise M at least 2, pack p NLWEs from subspaces into a single MNLUT with m = 1
        let spaces = Array::from_shape_fn(IxDyn(&vec![p as usize; 1]), |i| {
            // get a lower dimensional MNLUT by fixing the first index digit to i
            Self {
                luts: Array::from_shape_fn(IxDyn(&vec![p as usize; self.m() - 2]), |indices| {
                    let mut idx = vec![i[0]];
                    idx.extend_from_slice(&Vec::from_iter((0..self.m() - 2).map(|j| indices[j])));
                    self.luts[IxDyn(&idx)].clone()
                }),
            }
        });

        let nlwes = Zip::from(&spaces)
            // .par_map_collect(|subspace| subspace.blind_tensor_access(rest, ctx, public_key));
            .map_collect(|subspace| subspace.blind_tensor_access(rest, ctx, public_key));

        let line = MNLUT { nlwes };

        let line = Self::from_mnlut(&line, ctx, public_key);
        line.blind_tensor_access(
            &NLWE {
                digits: vec![index.digits[0].clone()],
            },
            ctx,
            public_key,
        )
    }

    pub fn blind_tensor_update<F: Fn(&NLWE) -> NLWE>(
        &mut self,
        index: &NLWE,
        f: F,
        ctx: &Context,
        public_key: &PublicKey,
    ) -> (NLWE, NLWE) {
        let start = Instant::now();
        let prev = self.blind_tensor_access(index, ctx, public_key);
        println!(
            "blind_tensor_update access: {}",
            start.elapsed().as_millis()
        );
        let start = Instant::now();
        let next = f(&prev);
        println!(
            "blind_tensor_update compute: {}",
            start.elapsed().as_millis()
        );
        assert_eq!(next.n(), self.n());
        let value = next.sub_digitwise_overflow(&prev);

        let start = Instant::now();
        self.blind_tensor_add_digitwise_overflow(&index, &value, ctx, public_key);
        println!("blind_tensor_update add: {}", start.elapsed().as_millis());
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
        // add computed luts to the current luts (will overflow coefficients)
        self.luts.zip_mut_with(&mask.luts, |a, b| {
            for (l1, l2) in a.zip_checked(b) {
                glwe_ciphertext_add_assign(&mut l1.0, &l2.0);
            }
        });
    }

    /// Lift a n-digit value to the LUT at index given by a m-digit value
    pub fn blind_tensor_lift(
        index: &NLWE,
        value: &NLWE,
        ctx: &Context,
        public_key: &PublicKey,
    ) -> Self {
        let p = ctx.full_message_modulus as u64;
        let m = index.n();
        let n = value.n();

        let mut luts = Array::from_shape_fn(IxDyn(&vec![p as usize; 0]), |_| {
            Vec::from_iter((0..n).map(|i| {
                let mut lut = LUT::from_lwe(&value.digits[i], public_key, ctx);
                let idx = public_key.neg_lwe(&index.digits[0], ctx);
                public_key.blind_rotation_assign(&idx, &mut lut, ctx);
                lut
            }))
        });

        for d in 1..m {
            // extract LWEs from rotated LUTs
            let nlwes = Array::from_shape_fn(IxDyn(&vec![p as usize; d]), |indices| {
                let idx = Vec::from_iter((0..d - 1).map(|k| indices[k]));
                NLWE {
                    digits: Vec::from_iter((0..n).map(|i| {
                        let lut = &luts[&IxDyn(&idx)][i];
                        public_key.lut_extract(&lut, indices[d - 1], ctx)
                    })),
                }
            });

            // Lift all LWEs to the next dimension and rotate along the newly created axis
            // luts = Zip::from(&nlwes).par_map_collect(|nlwe| {
            luts = Zip::from(&nlwes).map_collect(|nlwe| {
                Vec::from_iter((0..n).map(|i| {
                    let mut lut = LUT::from_lwe(&nlwe.digits[i], public_key, ctx);
                    let ndigit = public_key.neg_lwe(&index.digits[d], ctx);
                    public_key.blind_rotation_assign(&ndigit, &mut lut, ctx);
                    lut
                }))
            });
        }

        let out = Self { luts };
        assert_eq!(out.m(), m);
        assert_eq!(out.n(), n);
        out
    }

    pub fn blind_tensor_increment(&mut self, index: &NLWE, ctx: &Context, public_key: &PublicKey) {
        self.blind_tensor_update(
            index,
            |nlwe| nlwe.increment(ctx, public_key),
            ctx,
            public_key,
        );
    }

    pub fn blind_tensor_post_decrement(
        &mut self,
        index: &NLWE,
        ctx: &Context,
        public_key: &PublicKey,
    ) -> NLWE {
        let (_, next) = self.blind_tensor_update(
            index,
            |nlwe| nlwe.decrement(ctx, public_key),
            ctx,
            public_key,
        );
        next
    }
}
