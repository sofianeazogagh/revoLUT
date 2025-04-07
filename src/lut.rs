use std::{
    ops::{Add, Index},
    time::Instant,
};

// generalized LUT module
use crate::{counte::Counter, key, Context, PrivateKey, PublicKey, LUT, LWE};
use ndarray::{Array, Dimension, IxDyn};
use tfhe::core_crypto::prelude::lwe_ciphertext_add_assign;

/// Convert a value to a vector of n digits base p (most significant first)
pub fn to_digits(value: u64, n: usize, p: u64) -> Vec<u64> {
    Vec::from_iter((0..n).rev().map(|i| (value / p.pow(i as u32)) & (p - 1)))
}

/// Convert a vector of digits base p to a value (most significant first)
pub fn from_digits(digits: &[u64], p: u64) -> u64 {
    digits
        .iter()
        .rev()
        .enumerate()
        .map(|(i, digit)| p.pow(i as u32) * digit)
        .sum()
}

pub fn lwe_add_no_overflow(a: &LWE, b: &LWE, ctx: &Context, public_key: &PublicKey) -> LWE {
    let p = ctx.full_message_modulus as u64;
    let lut = LUT::from_function(|x| x, ctx);
    let mut c = a.clone();
    lwe_ciphertext_add_assign(&mut c, &b);
    public_key.blind_array_access(&c, &lut, ctx)
}

pub fn lwe_add(a: &LWE, b: &LWE, ctx: &Context, public_key: &PublicKey) -> LWE {
    // let mut c = a.clone();
    // lwe_ciphertext_add_assign(&mut c, &b);
    // c
    let p = ctx.full_message_modulus as u64;
    let tab = Vec::from_iter((0..p).map(|i| Vec::from_iter((0..p).map(|j| ((i + j) % p) as u64))));
    public_key.blind_matrix_access_clear(&tab, &a, &b, ctx)
}

/// A structure holding a N digit value
#[derive(Clone)]
pub struct NLWE {
    /// The digits, most significant first
    pub digits: Vec<LWE>,
}

impl From<&LWE> for NLWE {
    fn from(lwe: &LWE) -> Self {
        Self {
            digits: vec![lwe.clone()],
        }
    }
}

impl Index<usize> for NLWE {
    type Output = LWE;

    fn index(&self, index: usize) -> &Self::Output {
        &self.digits[index]
    }
}

impl NLWE {
    /// Returns N, the number of digits
    pub fn n(&self) -> usize {
        self.digits.len()
    }

    /// Create a NLWE from a vector of plain digits
    fn from_plain_digits(digits: Vec<u64>, ctx: &mut Context, private_key: &PrivateKey) -> NLWE {
        Self {
            digits: digits
                .iter()
                .map(|&digit| private_key.allocate_and_encrypt_lwe(digit, ctx))
                .collect(),
        }
    }

    pub fn from_plain_digits_trivially(
        digits: Vec<u64>,
        ctx: &Context,
        public_key: &PublicKey,
    ) -> NLWE {
        Self {
            digits: digits
                .iter()
                .map(|&digit| public_key.allocate_and_trivially_encrypt_lwe(digit, ctx))
                .collect(),
        }
    }

    /// Create a NLWE from a plain value
    pub fn from_plain(value: u64, n: usize, ctx: &mut Context, private_key: &PrivateKey) -> Self {
        let digits = to_digits(value, n, ctx.full_message_modulus as u64);
        Self::from_plain_digits(digits, ctx, private_key)
    }

    pub fn from_plain_trivially(
        value: u64,
        n: usize,
        ctx: &Context,
        public_key: &PublicKey,
    ) -> Self {
        let digits = to_digits(value, n, ctx.full_message_modulus as u64);
        Self::from_plain_digits_trivially(digits, ctx, public_key)
    }

    /// Decrypt the NLWE into a plain value
    pub fn to_plain(&self, ctx: &Context, private_key: &PrivateKey) -> u64 {
        let decrypted_digits = self.to_plain_digits(ctx, private_key);
        from_digits(&decrypted_digits, ctx.full_message_modulus as u64)
    }

    /// Decrypt the NLWE into a vector of plain digits
    pub fn to_plain_digits(&self, ctx: &Context, private_key: &PrivateKey) -> Vec<u64> {
        Vec::from_iter(
            self.digits
                .iter()
                .map(|digit| private_key.decrypt_lwe(&digit, ctx)),
        )
    }

    pub fn bootstrap(&mut self, ctx: &Context, public_key: &PublicKey) {
        let lut = LUT::from_function(|x| x, ctx);
        for digit in &mut self.digits {
            *digit = public_key.blind_array_access(&digit, &lut, ctx);
        }
    }

    /// Adds other NLWE to self, digit-wise (with carry)
    /// TODO: impl for N > 2
    pub fn add(&self, other: &NLWE, ctx: &Context, public_key: &PublicKey) -> NLWE {
        let p = ctx.full_message_modulus as u64;
        let n = self.n();
        let carry =
            Vec::from_iter((0..p).map(|i| Vec::from_iter((0..p).map(|j| ((i + j) >= p) as u64))));
        let mut output = NLWE::from_plain_trivially(0, n, ctx, public_key);
        output.digits[n - 1] = lwe_add(&self.digits[n - 1], &other.digits[n - 1], ctx, public_key);
        if n > 1 {
            let b = public_key.blind_matrix_access_clear(
                &carry,
                &self.digits[n - 1],
                &other.digits[n - 1],
                ctx,
            );
            output.digits[n - 2] =
                lwe_add(&self.digits[n - 2], &other.digits[n - 2], ctx, public_key);
            output.digits[n - 2] = lwe_add(&output.digits[n - 2], &b, ctx, public_key);
            let private_key = key(ctx.parameters);
            println!("{:?}", output.to_plain(ctx, private_key));
        }
        output
    }

    /// Adds other NLWE to self, digit-wise (without carry)
    pub fn add_no_carry(&self, other: &NLWE, ctx: &Context, public_key: &PublicKey) -> NLWE {
        // let lut = LUT::from_function(|x| x, ctx);
        // let p = ctx.full_message_modulus as u64;
        // let tab = Vec::from_iter((0..p).map(|i| Vec::from_iter((0..p).map(|j| (i + j) % p))));
        NLWE {
            digits: self
                .digits
                .iter()
                .zip(other.digits.iter())
                // .map(|(a, b)| public_key.blind_matrix_access_clear(&tab, a, b, ctx))
                .map(|(a, b)| lwe_add(&a, &b, ctx, public_key))
                .collect(),
        }
    }

    /// Special addition case where one of the operands is zero
    fn addz(&self, b: &NLWE, ctx: &Context, public_key: &PublicKey) -> NLWE {
        let lut = LUT::from_function(|x| x, ctx);
        NLWE {
            digits: self
                .digits
                .iter()
                .zip(b.digits.iter())
                .map(|(a, b)| {
                    let mut c = a.clone();
                    lwe_ciphertext_add_assign(&mut c, b);
                    public_key.blind_array_access(&c, &lut, ctx)
                })
                .collect(),
        }
    }

    // Increment the NLWE
    pub fn increment(&self, ctx: &Context, public_key: &PublicKey) -> NLWE {
        let mask = self.carry_mask(true, ctx, public_key);
        self.add_no_carry(&mask, ctx, public_key)
    }

    /// Construct a digit-wise additive mask to increment or decrement the NLWE
    pub fn carry_mask(&self, increment: bool, ctx: &Context, public_key: &PublicKey) -> NLWE {
        let mut one = NLWE::from_plain_trivially(1, self.n(), &ctx, public_key);
        let sentinel = (ctx.full_message_modulus as u64 - 1) * increment as u64;
        let carry = LUT::from_function(|x| (x == sentinel) as u64, ctx);

        let mut acc = public_key.allocate_and_trivially_encrypt_lwe(1, ctx);
        for i in (1..self.n()).rev() {
            let b = public_key.blind_array_access(&self.digits[i], &carry, ctx);
            let zero = public_key.allocate_and_trivially_encrypt_lwe(0, ctx);
            let andb = LUT::from_vec_of_lwe(&vec![zero, b], public_key, ctx);
            acc = public_key.blind_array_access(&acc, &andb, ctx);
            one.digits[i - 1] = lwe_add(&one.digits[i - 1], &acc, ctx, public_key);
        }

        if !increment {
            one = one.negate(ctx, public_key);
        }

        one
    }

    /// Decrement the NLWE
    pub fn decrement(&self, ctx: &Context, public_key: &PublicKey) -> NLWE {
        let mask = self.carry_mask(false, ctx, public_key);
        self.add_no_carry(&mask, ctx, public_key)
    }

    /// Negate the NLWE
    pub fn negate(&self, ctx: &Context, public_key: &PublicKey) -> NLWE {
        let p = ctx.full_message_modulus as u64;
        let lut = LUT::from_function(|x| (0 - x) % p, ctx);
        NLWE {
            digits: self
                .digits
                .iter()
                .map(|a| public_key.blind_array_access(&a, &lut, ctx))
                .collect(),
        }
    }
}

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

        // Otherwise M at least 2, pack p NLWEs from subspaces into a single MNLUT with m = 1
        let line = MNLUT {
            nlwes: Array::from_shape_fn(IxDyn(&vec![p as usize; 1]), |i| {
                // get a lower dimensional MNLUT by fixing the first index digit to i
                let subspace = MNLUT {
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

                // construct the index into the lower dimensional MNLUT by ignoring the first digit
                let rest = &NLWE {
                    digits: index.digits[1..].to_vec(),
                };
                subspace.blind_tensor_access(rest, ctx, public_key)
            }),
        };

        line.blind_tensor_access(&index, ctx, public_key)
    }

    /// Write a n-digit value to the LUT at index given by a m-digit value
    /// (Overwriting previous value)
    pub fn blind_tensor_assign(
        &mut self,
        index: &NLWE,
        value: &NLWE,
        ctx: &Context,
        public_key: &PublicKey,
    ) {
        assert_eq!(index.n(), self.m());
        assert_eq!(value.n(), self.n());
        // prefetch and negate current value to offset the addition
        let current = self.blind_tensor_access(&index, ctx, public_key);
        let ncurrent = current.negate(ctx, public_key);
        let value = ncurrent.add_no_carry(value, ctx, public_key);

        self.blind_tensor_add_no_carry(index, &value, ctx, public_key);
    }

    /// Write a n-digit value to the LUT at index given by a m-digit value
    /// (Assuming the value at given index is zero)
    pub fn blind_tensor_init(
        &mut self,
        index: &NLWE,
        value: &NLWE,
        ctx: &Context,
        public_key: &PublicKey,
    ) {
        assert_eq!(index.n(), self.m());
        assert_eq!(value.n(), self.n());
        // special case where all additions have at least one operand zero
        let mask = Self::blind_tensor_lift(index, value, ctx, public_key);
        self.nlwes.zip_mut_with(&mask.nlwes, |a, b| {
            *a = a.addz(&b, ctx, public_key);
        });
    }

    /// Adds a n-digit value to the LUT at index given by a m-digit value (digit-wise, without carry)
    pub fn blind_tensor_add_no_carry(
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
            *a = a.add_no_carry(&b, ctx, public_key);
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

        let nlwe = self
            .blind_tensor_access(index, ctx, public_key)
            .carry_mask(true, ctx, public_key);

        self.blind_tensor_add_no_carry(index, &nlwe, ctx, public_key);
    }

    /// Decrements NLWE at given index and return value after decrement
    pub fn blind_tensor_post_decrement(
        &mut self,
        index: &NLWE,
        ctx: &Context,
        public_key: &PublicKey,
    ) -> NLWE {
        assert_eq!(index.n(), self.m());

        let nlwe = self.blind_tensor_access(index, ctx, public_key);
        let mask = nlwe.carry_mask(false, ctx, public_key);
        self.blind_tensor_add_no_carry(index, &mask, ctx, public_key);
        nlwe.add_no_carry(&mask, ctx, public_key)
    }

    /// Sort the LUT using a blind counting sort by a key function
    pub fn blind_counting_sort(&self, d: usize, ctx: &Context, public_key: &PublicKey) -> MNLUT {
        let p = ctx.full_message_modulus;
        let (m, n) = (self.m(), self.n());
        let private_key = key(ctx.parameters);
        let mut count = MNLUT::from_plain_trivially(&vec![0; p], 1, m, public_key, ctx);
        // let mut count = Counter::new(m, ctx);

        println!("self {:02x?}", self.to_plain(ctx, private_key));
        // count the number of elements in each bucket
        println!("counting phase");
        let start = Instant::now();
        for nlwe in self.nlwes.iter() {
            count.blind_tensor_increment(&NLWE::from(&nlwe[d]), ctx, public_key);
            println!("{:?}", count.to_plain(ctx, private_key));
            // count.blind_increment(&nlwe[d], ctx, public_key);
        }
        println!("count {:?}", Instant::now() - start);

        // compute the prefix sum
        println!("prefix sum");
        let start = Instant::now();
        // let mut acc = Vec::from_iter((0..p).map(|i| count.at(i, ctx, public_key)));
        for i in 1..p {
            // acc[i] = acc[i].add_no_carry(&acc[i - 1]);
            let prev = count.at(i as u64 - 1, ctx);
            let idx = IxDyn(&vec![i]);
            count.nlwes[&idx] = count.nlwes[&idx].add(&prev, ctx, public_key);
            println!("{:?}", count.to_plain(ctx, private_key));
        }
        println!("acc {:?}", Instant::now() - start);

        // rebuild the sorted LUT
        println!("rebuild LUT");
        let start = Instant::now();
        // let mut count = Counter::from_nlwes(acc, ctx, public_key);
        let zeroes = &vec![0; p.pow(self.m() as u32)];
        let mut result = MNLUT::from_plain_trivially(zeroes, m, n, public_key, ctx);
        for i in (0..p.pow(m as u32)).rev() {
            let nlwe = self.at(i as u64, ctx);
            let pos = count.blind_tensor_post_decrement(&NLWE::from(&nlwe[d]), ctx, public_key);
            // let pos = count.blind_post_decrement(&nlwe[d], ctx, public_key);
            result.blind_tensor_init(&pos, &nlwe, ctx, public_key);
            println!(
                "added {:?} at index {:?}: {:?}",
                nlwe.to_plain(ctx, private_key),
                pos.to_plain(ctx, private_key),
                result.to_plain(ctx, private_key)
            );
        }
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
            // sorted.bootstrap(ctx, public_key);
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
    use tfhe::{
        core_crypto::prelude::lwe_ciphertext_sub_assign,
        shortint::parameters::{
            PARAM_MESSAGE_1_CARRY_0, PARAM_MESSAGE_2_CARRY_0, PARAM_MESSAGE_3_CARRY_0,
            PARAM_MESSAGE_4_CARRY_0,
        },
    };

    #[test]
    pub fn test_to_digits() {
        assert_eq!(to_digits(0b01, 2, 2), vec![0, 1]);
        assert_eq!(to_digits(0o1234, 4, 8), vec![1, 2, 3, 4]);
        assert_eq!(
            to_digits(0x0123456789ABCDEF, 16, 16),
            vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]
        );
        for i in 0..256 {
            assert_eq!(from_digits(&to_digits(i, 2, 16), 16), i);
        }
    }

    #[test]
    pub fn test_nlwe() {
        let mut ctx = Context::from(PARAM_MESSAGE_1_CARRY_0);
        let private_key = key(ctx.parameters);
        let nlwe = NLWE::from_plain(0b01, 2, &mut ctx, &private_key);
        assert_eq!(nlwe.to_plain(&ctx, &private_key), 0b01);
        let mut ctx = Context::from(PARAM_MESSAGE_3_CARRY_0);
        let private_key = key(ctx.parameters);
        let nlwe = NLWE::from_plain(0o1234, 4, &mut ctx, &private_key);
        assert_eq!(nlwe.to_plain(&ctx, &private_key), 0o1234);
        let mut ctx = Context::from(PARAM_MESSAGE_4_CARRY_0);
        let private_key = key(ctx.parameters);
        let nlwe = NLWE::from_plain(0x0123456789ABCDEF, 16, &mut ctx, &private_key);
        assert_eq!(nlwe.to_plain(&ctx, &private_key), 0x0123456789ABCDEF);
    }

    #[test]
    pub fn test_nlwe_add() {
        let mut ctx = Context::from(PARAM_MESSAGE_4_CARRY_0);
        let private_key = key(ctx.parameters);
        for i in 0..256 {
            let a = NLWE::from_plain(i, 2, &mut ctx, &private_key);
            for j in 0..256 {
                let b = NLWE::from_plain(j, 2, &mut ctx, &private_key);
                let start = Instant::now();
                let c = a.add(&b, &ctx, &private_key.public_key);
                println!("{:?}", Instant::now() - start);
                assert_eq!(c.to_plain(&ctx, &private_key), (i + j) % 256);
            }
        }
    }

    #[test]
    pub fn test_blind_read() {
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
    pub fn test_blind_write() {
        let mut ctx = Context::from(PARAM_MESSAGE_4_CARRY_0);
        let private_key = key(ctx.parameters);

        // println!("testing MNLUT M = 1, N = 1");
        // let data = Vec::from_iter(0..16);
        // let lut = MNLUT::from_plain(&data, 1, 1, &private_key, &mut ctx);
        // for i in 0..16 {
        //     for x in 0..16 {
        //         let mut actual = lut.clone();
        //         let index = NLWE::from_plain(i, 1, &mut ctx, &private_key);
        //         let value = NLWE::from_plain(x, 1, &mut ctx, &private_key);
        //         let start = Instant::now();
        //         actual.blind_tensor_add_no_carry(&index, &value, &ctx, &private_key.public_key);
        //         println!("{i} {x} ({:?})", Instant::now() - start);
        //         let nlwe = actual.at(i, &ctx);
        //         assert_eq!(
        //             nlwe.to_plain(&ctx, &private_key),
        //             (data[i as usize] + x) % 16
        //         );
        //     }
        // }

        // println!("testing MNLUT M = 1, N = 2");
        // for i in 0..16 {
        //     for x in (0..256).step_by(15) {
        //         let index = NLWE::from_plain(i, 1, &mut ctx, &private_key);
        //         let value = NLWE::from_plain(x, 2, &mut ctx, &private_key);
        //         let start = Instant::now();
        //         let actual =
        //             MNLUT::blind_tensor_lift(&index, &value, &ctx, &private_key.public_key);
        //         println!("{i} {x} ({:?})", Instant::now() - start);
        //         let nlwe = actual.at(i, &ctx);
        //         assert_eq!(nlwe.to_plain(&ctx, &private_key), x);
        //     }
        // }

        // println!("testing MNLUT M = 2, N = 1");
        // for i in (0..256).step_by(15) {
        //     for x in 0..16 {
        //         let index = NLWE::from_plain(i, 2, &mut ctx, &private_key);
        //         let value = NLWE::from_plain(x, 1, &mut ctx, &private_key);
        //         let start = Instant::now();
        //         let actual =
        //             MNLUT::blind_tensor_lift(&index, &value, &ctx, &private_key.public_key);
        //         println!("{i} {x} ({:?})", Instant::now() - start);
        //         let nlwe = actual.at(i, &ctx);
        //         assert_eq!(nlwe.to_plain(&ctx, &private_key), x);
        //     }
        // }

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
            lut.blind_tensor_add_no_carry(&index, &value, &ctx, &private_key.public_key);
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
    pub fn test_nlwe_increment() {
        let mut ctx = Context::from(PARAM_MESSAGE_4_CARRY_0);
        let p = ctx.full_message_modulus() as u64;
        let private_key = key(ctx.parameters);
        let n = 2;
        let range = p.pow(n as u32);

        for i in 0..range {
            let nlwe = NLWE::from_plain(i, n, &mut ctx, &private_key);
            let start = Instant::now();
            let next = nlwe.increment(&ctx, &private_key.public_key);
            let elapsed = Instant::now() - start;
            println!("{:?}", next.to_plain_digits(&ctx, private_key));
            let actual = next.to_plain(&ctx, &private_key);
            let expected = (i + 1) % range;
            println!("{i}: got {actual} expected {expected} elapsed {elapsed:?}",);
            assert_eq!(actual, expected);
        }
    }

    #[test]
    pub fn test_nlwe_decrement() {
        let mut ctx = Context::from(PARAM_MESSAGE_4_CARRY_0);
        let p = ctx.full_message_modulus() as u64;
        let private_key = key(ctx.parameters);
        let n = 2;
        let range = p.pow(n as u32);

        for i in 0..range {
            let nlwe = NLWE::from_plain(i, n, &mut ctx, &private_key);
            let start = Instant::now();
            let next = nlwe.decrement(&ctx, &private_key.public_key);
            let elapsed = Instant::now() - start;
            println!("{:?}", next.to_plain_digits(&ctx, private_key));
            let actual = next.to_plain(&ctx, &private_key);
            let expected = (i - 1) % range;
            println!("{i}: got {actual} expected {expected} elapsed {elapsed:?}",);
            assert_eq!(actual, expected);
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
        let mut ctx = Context::from(PARAM_MESSAGE_2_CARRY_0);
        let private_key = key(ctx.parameters);
        let (m, n) = (1, 1);
        let size = ctx.full_message_modulus().pow(m as u32) as u64;
        let range = ctx.full_message_modulus().pow(n as u32) as u64;
        let data = Vec::from_iter((0..size as u64).rev());
        let data = vec![3, 3, 2, 1];
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

    #[test]
    pub fn test_lut_id() {
        let mut ctx = Context::from(PARAM_MESSAGE_4_CARRY_0);
        let private_key = key(ctx.parameters);
        let public_key = &private_key.public_key;
        let p = ctx.full_message_modulus() as u64;
        let lut = LUT::from_function(|x| x, &ctx);

        for j in 0..4 * p {
            let full = private_key.allocate_and_encrypt_lwe(j, &mut ctx);
            println!("{j} dec {:?}", private_key.decrypt_lwe(&full, &ctx));
        }

        for i in 0..p {
            let index = private_key.allocate_and_encrypt_lwe(i, &mut ctx);
            // let x = public_key.blind_array_access(&index, &lut, &ctx);
            let rotated = public_key.blind_rotation(&index, &lut, &ctx);
            let x = public_key.lut_extract(&rotated, 0, &ctx);
            let dec = private_key.decrypt_lwe(&x, &ctx);
            assert_eq!(dec, i);
        }
    }
}
