use std::ops::Index;

use tfhe::core_crypto::prelude::{lwe_ciphertext_add_assign, lwe_ciphertext_sub_assign};

use crate::{Context, PrivateKey, PublicKey, LUT, LWE};

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

pub fn lwe_add(a: &LWE, b: &LWE, ctx: &Context, public_key: &PublicKey) -> LWE {
    let p = ctx.full_message_modulus as u64;
    let matrix = Vec::from_iter((0..p).map(|i| Vec::from_iter((0..p).map(|j| (i + j) % p as u64))));
    public_key.blind_matrix_access_clear(&matrix, &a, &b, ctx)
}

pub fn lwe_add_overflow(a: &LWE, b: &LWE) -> LWE {
    let mut c = a.clone();
    lwe_ciphertext_add_assign(&mut c, &b);
    c
}

pub fn lwe_sub_overflow(a: &LWE, b: &LWE) -> LWE {
    let mut c = a.clone();
    lwe_ciphertext_sub_assign(&mut c, &b);
    c
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
    pub fn add(&self, other: &NLWE, ctx: &Context, public_key: &PublicKey) -> NLWE {
        let p = ctx.full_message_modulus as u64;
        let n = self.n();
        let carry = ((0..p).map(|i| ((0..p).map(|j| ((i + j) >= p) as u64)).collect())).collect();
        let inc = LUT::from_function(|x| (x + 1) % p, ctx);
        let mut output = NLWE::from_plain_trivially(0, n, ctx, public_key);

        // from right to left
        output.digits[n - 1] = lwe_add(&self[n - 1], &other[n - 1], ctx, public_key);
        for i in (0..n - 1).rev() {
            let sum = lwe_add(&self[i], &other[i], ctx, public_key);
            let b = public_key.blind_matrix_access_clear(&carry, &self[i + 1], &other[i + 1], ctx);
            let next = public_key.blind_array_access(&sum, &inc, ctx);
            let sel = LUT::from_vec_of_lwe(&vec![sum, next], public_key, ctx);
            output.digits[i] = public_key.blind_array_access(&b, &sel, ctx);
        }

        output
    }

    /// Adds other NLWE to self, digit-wise (without carry)
    pub fn add_digitwise_overflow(&self, other: &NLWE) -> NLWE {
        NLWE {
            digits: self
                .digits
                .iter()
                .zip(other.digits.iter())
                .map(|(a, b)| lwe_add_overflow(&a, &b))
                .collect(),
        }
    }

    pub fn sub_digitwise_overflow(&self, other: &NLWE) -> NLWE {
        NLWE {
            digits: self
                .digits
                .iter()
                .zip(other.digits.iter())
                .map(|(a, b)| lwe_sub_overflow(&a, &b))
                .collect(),
        }
    }

    // Increment the NLWE
    // TODO: optimize
    pub fn increment(&self, ctx: &Context, public_key: &PublicKey) -> NLWE {
        let p = ctx.full_message_modulus as u64;
        let mut out = self.clone();
        let is_mone = LUT::from_function(|x| (x == p - 1) as u64, ctx);
        let inc = LUT::from_function(|x| (x + 1) % p, ctx);

        let mut acc = public_key.allocate_and_trivially_encrypt_lwe(1, ctx);
        // from right to left
        for digit in out.digits.iter_mut().rev() {
            // digit stays self or becomes next
            let next = public_key.blind_array_access(&digit, &inc, ctx);
            let sel = LUT::from_vec_of_lwe(&vec![digit.clone(), next], public_key, ctx);
            let next_digit = public_key.blind_array_access(&acc, &sel, ctx);

            // is current digit full?
            let b = public_key.blind_array_access(digit, &is_mone, ctx);
            // are all digits so far full?
            let zero = public_key.allocate_and_trivially_encrypt_lwe(0, ctx);
            let andb = LUT::from_vec_of_lwe(&vec![zero, b], public_key, ctx);

            acc = public_key.blind_array_access(&acc, &andb, ctx);
            *digit = next_digit;
        }

        out
    }

    /// Decrement the NLWE
    /// TODO: refactor with increment
    pub fn decrement(&self, ctx: &Context, public_key: &PublicKey) -> NLWE {
        let p = ctx.full_message_modulus as u64;
        let mut out = self.clone();
        let is_zero = LUT::from_function(|x| (x == 0) as u64, ctx);
        let dec = LUT::from_function(|x| (x - 1) % p, ctx);

        let mut acc = public_key.allocate_and_trivially_encrypt_lwe(1, ctx);
        // from right to left
        for digit in out.digits.iter_mut().rev() {
            // digit stays self or becomes next
            let next = public_key.blind_array_access(&digit, &dec, ctx);
            let sel = LUT::from_vec_of_lwe(&vec![digit.clone(), next], public_key, ctx);
            let next_digit = public_key.blind_array_access(&acc, &sel, ctx);

            // is current digit full?
            let b = public_key.blind_array_access(digit, &is_zero, ctx);
            // are all digits so far full?
            let zero = public_key.allocate_and_trivially_encrypt_lwe(0, ctx);
            let andb = LUT::from_vec_of_lwe(&vec![zero, b], public_key, ctx);

            acc = public_key.blind_array_access(&acc, &andb, ctx);
            *digit = next_digit;
        }

        out
    }
}
