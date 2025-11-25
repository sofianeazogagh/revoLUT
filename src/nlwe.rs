use std::ops::Index;

use tfhe::core_crypto::prelude::{lwe_ciphertext_add_assign, lwe_ciphertext_sub_assign};

use crate::{Context, LUT, LWE, PrivateKey, PublicKey, key};

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
        let n = self.n();
        let mut out = self.clone();
        let is_end = LUT::from_function(|x| (x == p - 1) as u64, ctx);
        let inc = LUT::from_function(|x| (x + 1) % p, ctx);

        // increment last digit
        out.digits[n - 1] = public_key.blind_array_access(&out.digits[n - 1], &inc, ctx);

        if self.n() > 1 {
            // is last digit full?
            let mut acc = public_key.blind_array_access(&self.digits[n - 1], &is_end, ctx);
            // keep folding from right to left
            for i in (1..n - 1).rev() {
                // digit stays self or becomes next
                let digit = &mut out.digits[i];
                let next = public_key.blind_array_access(&digit, &inc, ctx);
                let sel = LUT::from_vec_of_lwe(&vec![digit.clone(), next], public_key, ctx);
                let next_digit = public_key.blind_array_access(&acc, &sel, ctx);

                // is current digit full?
                let b = public_key.blind_array_access(digit, &is_end, ctx);
                // are all digits so far full?
                let zero = public_key.allocate_and_trivially_encrypt_lwe(0, ctx);
                let andb = LUT::from_vec_of_lwe(&vec![zero, b], public_key, ctx);
                acc = public_key.blind_array_access(&acc, &andb, ctx);

                *digit = next_digit;
            }

            // digit stays self or becomes next
            let digit = &mut out.digits[0];
            let next = public_key.blind_array_access(&digit, &inc, ctx);
            let sel = LUT::from_vec_of_lwe(&vec![digit.clone(), next], public_key, ctx);
            *digit = public_key.blind_array_access(&acc, &sel, ctx);
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

impl PublicKey {

    pub fn half_adder(&self, digit: &LWE, op: &LWE, carry: &LWE, ctx: &Context) -> (LWE, LWE) {

        let private_key = key(ctx.parameters);
        let p = ctx.full_message_modulus as u64;
        let b = self.cmux(&self.allocate_and_trivially_encrypt_lwe(0u64, ctx), op, carry, ctx);
        
        private_key.debug_lwe("b", &b, ctx);
        // Identity luts
        let lut_id = LUT::from_vec_trivially(&(0..p).collect::<Vec<_>>(), ctx);
        // Increment lut
        let lut_inc =
            LUT::from_vec_trivially(&(0..p).map(|x| (x + 1) % p).collect::<Vec<_>>(), ctx);
        // Decrement lut
        let lut_dec =
            LUT::from_vec_trivially(&(0..p).map(|x| (x - 1) % p).collect::<Vec<_>>(), ctx);
        let new_digit = self.switch_case3(digit, &b, &vec![lut_id.clone(), lut_inc.clone(), lut_dec.clone()], ctx);
        private_key.debug_lwe("digit", &digit, ctx);


        let zeros = vec![0; p as usize];
        let mut vec_last = zeros.clone();
        vec_last[p as usize - 1] = 1;
        let mut vec_first = zeros.clone();
        vec_first[0] = 1;

        let lut_z = LUT::from_vec_trivially(&zeros, ctx); // [0,..,0]
        let lut_last = LUT::from_vec_trivially(&vec_last, ctx); // [0,..,0,1]
        let lut_first = LUT::from_vec_trivially(&vec_first, ctx); // [1,0,..,0]

        let new_carry = self.switch_case3(&digit, &b, &vec![lut_z.clone(), lut_last.clone(), lut_first.clone()], ctx);
        private_key.debug_lwe("carry", &new_carry, ctx);
        (new_digit, new_carry)
    }


    pub fn nlwe_maybe_inc_or_dec(&self, a: &NLWE, b: &LWE, ctx: &Context) -> NLWE {
        let mut carry = self.allocate_and_trivially_encrypt_lwe(1u64, ctx);

        let mut output = NLWE::from_plain_trivially(0, a.n(), ctx, self);
        for (i, digit) in a.digits.iter().rev().enumerate() {
            let idx = a.n() - 1 - i;
            println!("i: {}", idx);
            (output.digits[idx], carry) = self.half_adder(digit, b, &carry, ctx);
        }
        output


            
    }
}

#[cfg(test)]
mod tests {
    use crate::{key, nlwe::*};
    use quickcheck::TestResult;
    use std::time::Instant;
    use tfhe::shortint::parameters::*;

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

    #[quickcheck]
    pub fn test_nlwe_add(i: u8, j: u8) -> TestResult {
        let mut ctx = Context::from(PARAM_MESSAGE_4_CARRY_0);
        let p = ctx.full_message_modulus() as u64;
        let n = 2;
        let size = p.pow(n as u32);
        let private_key = key(ctx.parameters);

        let a = NLWE::from_plain(i as u64, n, &mut ctx, &private_key);
        let b = NLWE::from_plain(j as u64, n, &mut ctx, &private_key);
        let start = Instant::now();
        let c = a.add(&b, &ctx, &private_key.public_key);
        let elapsed = Instant::now() - start;
        println!(
            "{:?} + {:?} = {:?} {:?}",
            to_digits(i as u64, n, p),
            to_digits(j as u64, n, p),
            c.to_plain_digits(&ctx, private_key),
            elapsed
        );
        let dc = c.to_plain(&ctx, &private_key);
        TestResult::from_bool(dc == (i as u64 + j as u64) % size)
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
        let mut ctx = Context::from(PARAM_MESSAGE_2_CARRY_0);
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
    fn test_nlwe_maybe_inc_or_dec() {
        let mut ctx = Context::from(PARAM_MESSAGE_4_CARRY_0);
        let private_key = key(ctx.parameters);
        let public_key = &private_key.public_key;

        let a = 0x110;
        let b = 2;

        let enc_a = NLWE::from_plain(a, 3, &mut ctx, private_key);
        let enc_b = private_key.allocate_and_encrypt_lwe(b, &mut ctx);

        let start = Instant::now();
        let c = public_key.nlwe_maybe_inc_or_dec(&enc_a, &enc_b, &ctx);

        let actual = c.to_plain(&ctx, private_key);
        println!(
            "elapsed {:?}, a: {:03X}, b: {:02X}, actual: {:03X}",
            Instant::now() - start,
            a as u64,
            b as u64,
            actual as u64
        );
    }
}
