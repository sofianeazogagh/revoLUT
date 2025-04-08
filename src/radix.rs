use std::time::Instant;

/// Assuming we work in param4
use tfhe::core_crypto::algorithms::lwe_ciphertext_add_assign;

use crate::{key, Context, PrivateKey, PublicKey, LUT, LWE};

/// A byte represented by two lwe ciphertexts
pub struct ByteLWE {
    pub lo: LWE,
    pub hi: LWE,
}

impl ByteLWE {
    pub fn from_byte(input: u8, ctx: &mut Context, private_key: &PrivateKey) -> Self {
        let lo = private_key.allocate_and_encrypt_lwe(((input >> 0) & 0b1111) as u64, ctx);
        let hi = private_key.allocate_and_encrypt_lwe(((input >> 4) & 0b1111) as u64, ctx);
        Self { lo, hi }
    }

    pub fn from_byte_trivially(input: u8, ctx: &Context, public_key: &PublicKey) -> Self {
        let lo = public_key.allocate_and_trivially_encrypt_lwe(((input >> 0) & 0b1111) as u64, ctx);
        let hi = public_key.allocate_and_trivially_encrypt_lwe(((input >> 4) & 0b1111) as u64, ctx);
        Self { lo, hi }
    }

    pub fn to_byte(&self, ctx: &Context, private_key: &PrivateKey) -> u8 {
        let lo = private_key.decrypt_lwe(&self.lo, &ctx);
        let hi = private_key.decrypt_lwe(&self.hi, &ctx);
        ((hi << 4) + lo) as u8
    }
}

/// Structure indexing a byte by a nybble
pub struct NyblByteLUT {
    pub lo: LUT,
    pub hi: LUT,
}

impl NyblByteLUT {
    #[allow(dead_code)]
    pub fn from_bytes(input: &[u8; 16], private_key: &PrivateKey, ctx: &mut Context) -> Self {
        let los = Vec::from_iter((0..16).map(|i| ((input[i] >> 0) & 0b1111) as u64));
        let his = Vec::from_iter((0..16).map(|i| ((input[i] >> 4) & 0b1111) as u64));
        Self {
            lo: LUT::from_vec(&los, private_key, ctx),
            hi: LUT::from_vec(&his, private_key, ctx),
        }
    }

    pub fn from_bytes_trivially(input: &[u8; 16], ctx: &Context) -> Self {
        let los = Vec::from_iter((0..16).map(|i| ((input[i] >> 0) & 0b1111) as u64));
        let his = Vec::from_iter((0..16).map(|i| ((input[i] >> 4) & 0b1111) as u64));
        Self {
            lo: LUT::from_vec_trivially(&los, ctx),
            hi: LUT::from_vec_trivially(&his, ctx),
        }
    }

    pub fn at(&self, index: u8, ctx: &Context, public_key: &PublicKey) -> ByteLWE {
        ByteLWE {
            lo: public_key.lut_extract(&self.lo, index as usize, ctx),
            hi: public_key.lut_extract(&self.hi, index as usize, ctx),
        }
    }

    /// fetch encrypted byte value at encrypted nybl index
    pub fn blind_array_access(
        &self,
        index: &LWE,
        ctx: &Context,
        public_key: &PublicKey,
    ) -> ByteLWE {
        ByteLWE {
            lo: public_key.blind_array_access(&index, &self.lo, ctx),
            hi: public_key.blind_array_access(&index, &self.hi, ctx),
        }
    }

    /// add encrypted byte value at encrypted nyble index
    pub fn blind_array_add(
        &mut self,
        index: &LWE,
        value: &ByteLWE,
        ctx: &Context,
        public_key: &PublicKey,
    ) {
        // 2 br
        let current = self.blind_array_access(index, ctx, public_key);
        // 1 bma (17 br)
        let new_value = public_key.byte_lwe_add(&current, &value, ctx);
        // 4 br
        self.blind_array_set(index, &new_value, ctx, public_key);
    }

    /// increment encrypted byte value at encrypted nybl index
    pub fn blind_array_inc(&mut self, index: &LWE, ctx: &Context, public_key: &PublicKey) {
        // 2 br
        let lo = public_key.blind_array_access(&index, &self.lo, ctx);
        let lut = LUT::from_function(|x| if x == 15 { 1 } else { 0 }, ctx);
        let carry = public_key.blind_array_access(&lo, &lut, ctx);

        // 2 br
        let one = public_key.allocate_and_trivially_encrypt_lwe(1, ctx);
        public_key.blind_array_increment(&mut self.lo, &index, &one, ctx);
        public_key.blind_array_increment(&mut self.hi, &index, &carry, ctx);
    }

    /// decrement encrypted byte value at encrypted nybl index
    pub fn blind_array_dec(&mut self, index: &LWE, ctx: &Context, public_key: &PublicKey) {
        // 2 br
        let lo = public_key.blind_array_access(&index, &self.lo, ctx);
        let lut = LUT::from_function(|x| if x == 0 { 1 } else { 0 }, ctx);
        let carry = public_key.blind_array_access(&lo, &lut, ctx);
        let carry = public_key.neg_lwe(&carry, ctx);

        // 2 br
        let one = public_key.allocate_and_trivially_encrypt_lwe(1, ctx);
        let minus_one = public_key.neg_lwe(&one, ctx);
        public_key.blind_array_increment(&mut self.lo, &index, &minus_one, ctx);
        public_key.blind_array_increment(&mut self.hi, &index, &carry, ctx);
    }

    /// replaces encrypted byte value at encrypted nybl index
    pub fn blind_array_set(
        &mut self,
        index: &LWE,
        value: &ByteLWE,
        ctx: &Context,
        public_key: &PublicKey,
    ) {
        // 2 br
        public_key.blind_array_set(&mut self.lo, &index, &value.lo, ctx);
        // 2 br
        public_key.blind_array_set(&mut self.hi, &index, &value.hi, ctx);
    }

    fn print(&self, private_key: &PrivateKey, ctx: &Context) {
        self.lo.print(private_key, ctx);
        self.hi.print(private_key, ctx);
    }
}

/// Structure indexing a byte by a byte
#[derive(Clone)]
pub struct ByteByteLUT {
    pub lo: [LUT; 16],
    pub hi: [LUT; 16],
}

impl ByteByteLUT {
    pub fn from_bytes(input: &[u8; 256], private_key: &PrivateKey, ctx: &mut Context) -> Self {
        // matrix of all the low nibbles
        let lo: [LUT; 16] = std::array::from_fn(|l| {
            LUT::from_vec(
                &Vec::from_iter((0..16).map(|c| (input[(l << 4) + c] % 16) as u64)),
                private_key,
                ctx,
            )
        });
        // matrix of all the high nibbles
        let hi: [LUT; 16] = std::array::from_fn(|l| {
            LUT::from_vec(
                &Vec::from_iter((0..16).map(|c| ((input[(l << 4) + c] >> 4) % 16) as u64)),
                private_key,
                ctx,
            )
        });
        Self { lo, hi }
    }

    pub fn from_bytes_trivially(input: &[u8; 256], ctx: &Context) -> Self {
        // matrix of all the low nibbles
        let lo: [LUT; 16] = std::array::from_fn(|l| {
            LUT::from_vec_trivially(
                &Vec::from_iter((0..16).map(|c| (input[(l << 4) + c] % 16) as u64)),
                ctx,
            )
        });
        // matrix of all the high nibbles
        let hi: [LUT; 16] = std::array::from_fn(|l| {
            LUT::from_vec_trivially(
                &Vec::from_iter((0..16).map(|c| ((input[(l << 4) + c] >> 4) % 16) as u64)),
                ctx,
            )
        });
        Self { lo, hi }
    }

    pub fn print(&self, public_key: &PublicKey, private_key: &PrivateKey, ctx: &Context) {
        let mut result = vec![];
        for i in 0x00..=0xff {
            let blwe = self.at(i, public_key, ctx);
            let byte = blwe.to_byte(ctx, private_key);
            result.push(byte);
        }
        println!("{:02X?}", result);
    }

    pub fn at(&self, index: u8, public_key: &PublicKey, ctx: &Context) -> ByteLWE {
        let hi = (index >> 4) % 16;
        let lo = (index >> 0) % 16;
        ByteLWE {
            lo: public_key.lut_extract(&self.lo[hi as usize], lo as usize, ctx),
            hi: public_key.lut_extract(&self.hi[hi as usize], lo as usize, ctx),
        }
    }

    /// fetch at encrypted index
    pub fn blind_array_access(
        &self,
        index: &ByteLWE,
        ctx: &Context,
        public_key: &PublicKey,
    ) -> ByteLWE {
        ByteLWE {
            lo: public_key.blind_matrix_access(&self.lo, &index.hi, &index.lo, ctx),
            hi: public_key.blind_matrix_access(&self.hi, &index.hi, &index.lo, ctx),
        }
    }

    /// adds encrypted value at encrypted index
    pub fn blind_array_add(
        &mut self,
        index: &ByteLWE,
        value: &ByteLWE,
        ctx: &Context,
        public_key: &PublicKey,
    ) {
        // 3 BMA + 1 BMA_mv
        let old_lo = public_key.blind_matrix_access(&self.lo, &index.hi, &index.lo, ctx);
        let mut carry = public_key.nybl_carry(&old_lo, &value.lo, ctx);
        lwe_ciphertext_add_assign(&mut carry, &value.hi);
        public_key.blind_matrix_add(&mut self.lo, &index.hi, &index.lo, &value.lo, ctx);
        public_key.blind_matrix_add(&mut self.hi, &index.hi, &index.lo, &carry, ctx);
    }

    /// replace encrypted value at encrypted index by new encrypted value
    pub fn blind_array_set(
        &mut self,
        index: &ByteLWE,
        value: &ByteLWE,
        ctx: &Context,
        public_key: &PublicKey,
    ) {
        // 2 bma
        public_key.blind_matrix_set(&mut self.lo, &index.hi, &index.lo, &value.lo, ctx);
        // 2 bma
        public_key.blind_matrix_set(&mut self.hi, &index.hi, &index.lo, &value.hi, ctx);
    }

    /// initialize encrypted value at encrypted index (assuming it was previously encrypted zero)
    pub fn blind_array_init(
        &mut self,
        index: &ByteLWE,
        value: &ByteLWE,
        ctx: &Context,
        public_key: &PublicKey,
    ) {
        // 1 bma
        public_key.blind_matrix_add(&mut self.lo, &index.hi, &index.lo, &value.lo, ctx);
        // 1 bma
        public_key.blind_matrix_add(&mut self.hi, &index.hi, &index.lo, &value.hi, ctx);
    }
}

impl PublicKey {
    /// Compute encrypted carry as the result of adding two encrypted nybles
    pub fn nybl_carry(&self, a: &LWE, b: &LWE, ctx: &Context) -> LWE {
        // let carry_matrix = Vec::from_iter((0..16).map(|lin| {
        //     LUT::from_vec_trivially(
        //         &Vec::from_iter((0..16).map(|col| if lin + col >= 16 { 1 } else { 0 })),
        //         ctx,
        //     )
        // }));
        let carry_matrix = Vec::from_iter(
            (0..16)
                .map(|lin| Vec::from_iter((0..16).map(|col| if lin + col >= 16 { 1 } else { 0 }))),
        );
        let twice_bit = self.blind_matrix_access_mv(&carry_matrix, &a, &b, ctx);
        let lut = LUT::from_vec_trivially(&vec![0, 0, 1], ctx);
        // let mut hi = self.blind_matrix_access(&carry_matrix, &a.lo, &b.lo, ctx);
        self.blind_array_access(&twice_bit, &lut, &ctx)
    }

    pub fn byte_lwe_add(&self, a: &ByteLWE, b: &ByteLWE, ctx: &Context) -> ByteLWE {
        let mut lo = self.allocate_and_trivially_encrypt_lwe(0, ctx);
        lwe_ciphertext_add_assign(&mut lo, &a.lo);
        lwe_ciphertext_add_assign(&mut lo, &b.lo);
        let mut hi = self.nybl_carry(&a.lo, &b.lo, ctx);
        lwe_ciphertext_add_assign(&mut hi, &a.hi);
        lwe_ciphertext_add_assign(&mut hi, &b.hi);
        ByteLWE { lo, hi }
    }

    pub fn keyed_blind_counting_sort(
        &self,
        bblut: &ByteByteLUT,
        f: fn(&ByteLWE) -> LWE,
        ctx: &Context,
    ) -> ByteByteLUT {
        let private_key = key(ctx.parameters);
        let mut count = NyblByteLUT::from_bytes_trivially(&[0; 16], ctx);
        // count values (~17s)
        let start = Instant::now();
        for i in 0x00..=0xff {
            let blwe = bblut.at(i, self, ctx);
            let byte = blwe.to_byte(ctx, private_key);
            println!("{byte:02X}");
            let digit = f(&blwe);
            count.blind_array_inc(&digit, ctx, self);
            count.lo.print(private_key, ctx);
            count.hi.print(private_key, ctx);
        }
        println!("elapsed {:?}", Instant::now() - start);
        count.lo.print(private_key, ctx);
        count.hi.print(private_key, ctx);

        // prefix sum (~2s)
        let start = Instant::now();
        for i in 0x01..=0x0f {
            let blwe = count.at(i - 1, ctx, self);
            // TODO: surely this part can be optimized
            let index = self.allocate_and_trivially_encrypt_lwe(i as u64, ctx);
            count.blind_array_add(&index, &blwe, ctx, self);
            // bootstrap count nblut
            if i % 4 == 0 {
                let start = Instant::now();
                count.lo = count.lo.bootstrap_lut(self, ctx);
                count.hi = count.hi.bootstrap_lut(self, ctx);
                println!("bootstrap elapsed {:?}", Instant::now() - start);
            }
        }
        println!("prefix sum elapsed: {:?}", Instant::now() - start);
        count.lo.print(private_key, ctx);
        count.hi.print(private_key, ctx);

        // rebuild sorted LUT
        let mut result = ByteByteLUT::from_bytes_trivially(&[0; 256], ctx);
        let start = Instant::now();
        for i in (0x00..=0xff).rev() {
            let blwe = bblut.at(i, self, ctx);
            let digit = f(&blwe);
            let byte = blwe.to_byte(ctx, private_key);
            let d = private_key.decrypt_lwe(&digit, ctx);
            println!("{byte:02X}: {d:X}");
            // TODO: could be hacked to output value post-dec in less than two extra br?
            count.blind_array_dec(&digit, ctx, self);
            count.print(private_key, ctx);
            let index = count.blind_array_access(&digit, ctx, self);
            result.blind_array_init(&index, &blwe, ctx, self);
            result.print(self, private_key, ctx);
        }
        println!("rebuild elapsed: {:?}", Instant::now() - start);

        result
    }

    pub fn blind_radix_sort(&self, bblut: &ByteByteLUT, ctx: &Context) -> ByteByteLUT {
        let partial = self.keyed_blind_counting_sort(bblut, |blwe| blwe.lo.clone(), ctx);
        self.keyed_blind_counting_sort(&partial, |blwe| blwe.hi.clone(), ctx)
    }
}

#[cfg(test)]
mod test {
    use std::{time::Instant, u8};

    use quickcheck::TestResult;
    use tfhe::shortint::parameters::PARAM_MESSAGE_4_CARRY_0;

    use crate::key;

    use super::*;

    #[test]
    fn test_byte_lut_blind_array_access() {
        let mut ctx = Context::from(PARAM_MESSAGE_4_CARRY_0);
        let private_key = key(ctx.parameters);
        let public_key = &private_key.public_key;

        let bytes: [u8; 256] = std::array::from_fn(|i| i as u8);
        let byte_lut = ByteByteLUT::from_bytes(&bytes, &private_key, &mut ctx);

        for i in 0..=0xFF {
            let byte_lwe = ByteLWE::from_byte(i, &mut ctx, private_key);
            let j = byte_lwe.to_byte(&ctx, private_key);
            assert_eq!(j, i);

            let start = Instant::now();
            let output = byte_lut.blind_array_access(&byte_lwe, &ctx, public_key);
            println!("elapsed {:?}", Instant::now() - start);
            let actual = output.to_byte(&ctx, private_key);
            assert_eq!(actual, i);
        }
    }

    #[quickcheck]
    fn test_byte_lwe_add_qc(a: u8, b: u8) -> TestResult {
        let mut ctx = Context::from(PARAM_MESSAGE_4_CARRY_0);
        let private_key = key(ctx.parameters);
        let public_key = &private_key.public_key;

        let enc_a = ByteLWE::from_byte(a, &mut ctx, private_key);
        let enc_b = ByteLWE::from_byte(b, &mut ctx, private_key);
        let start = Instant::now();
        let enc_c = public_key.byte_lwe_add(&enc_a, &enc_b, &ctx);
        println!("elapsed {:?}", Instant::now() - start);
        let c = enc_c.to_byte(&ctx, private_key);

        TestResult::from_bool(c == a + b)
    }

    #[test]
    fn test_byte_byte_lut_blind_array_add() {
        let mut ctx = Context::from(PARAM_MESSAGE_4_CARRY_0);
        let private_key = key(ctx.parameters);
        let public_key = &private_key.public_key;

        let mut bblut = ByteByteLUT::from_bytes(&[0; 256], private_key, &mut ctx);
        let index = ByteLWE::from_byte(0, &mut ctx, private_key);
        let value = ByteLWE::from_byte(1, &mut ctx, private_key);

        let start = Instant::now();
        bblut.blind_array_add(&index, &value, &ctx, public_key);
        println!("elapsed: {:?}", Instant::now() - start);

        let ct = bblut.blind_array_access(&index, &ctx, public_key);
        let actual = ct.to_byte(&ctx, private_key);

        assert_eq!(actual, 1);
    }

    // #[test]
    // fn test_nybl_byte_lut_blind_array_inc() {
    //     let mut ctx = Context::from(PARAM_MESSAGE_4_CARRY_0);
    //     let private_key = key(ctx.parameters);
    //     let public_key = &private_key.public_key;

    //     let items: [u8; 256] = std::array::from_fn(|i| i as u8);
    //     let bblut = ByteByteLUT::from_bytes(&items, private_key, &mut ctx);

    //     let mut count = NyblByteLUT::from_bytes_trivially(&[0; 16], &ctx);
    //     count.print(private_key, &ctx);
    //     for i in 0..=255 {
    //         let blwe = bblut.at(i, public_key, &ctx);
    //         count.blind_array_inc(&blwe.hi, &ctx, public_key);
    //         count.print(private_key, &ctx);
    //         println!("=====");
    //     }
    // }

    #[test]
    fn test_nybl_byte_lut_blind_array_dec() {
        let mut ctx = Context::from(PARAM_MESSAGE_4_CARRY_0);
        let private_key = key(ctx.parameters);
        let public_key = &private_key.public_key;

        // let items: [u8; 256] = std::array::from_fn(|i| i as u8);
        // let bblut = ByteByteLUT::from_bytes(&items, private_key, &mut ctx);

        let items: [u8; 16] = std::array::from_fn(|i| (((i + 1) % 16) << 4) as u8);
        let mut count = NyblByteLUT::from_bytes_trivially(&items, &ctx);
        count.print(private_key, &ctx);
        println!("==============");
        for i in (0..=0xff).rev() {
            // let blwe = bblut.at(i, public_key, &ctx);
            println!("{:02X}", i >> 4);
            let index = private_key.allocate_and_encrypt_lwe(i >> 4, &mut ctx);
            count.blind_array_dec(&index, &ctx, public_key);
            count.print(private_key, &ctx);
            println!("=====");
        }
    }

    #[test]
    fn test_keyed_blind_counting_sort() {
        let mut ctx = Context::from(PARAM_MESSAGE_4_CARRY_0);
        let private_key = key(ctx.parameters);
        let public_key = &private_key.public_key;

        let items: [u8; 256] = std::array::from_fn(|i| i as u8);
        let bblut = ByteByteLUT::from_bytes(&items, private_key, &mut ctx);
        for lut in &bblut.lo {
            lut.print(private_key, &ctx);
        }
        for lut in &bblut.hi {
            lut.print(private_key, &ctx);
        }

        let start = Instant::now();
        public_key.keyed_blind_counting_sort(&bblut, |blwe| blwe.hi.clone(), &ctx);
        println!("total time elapsed: {:?}", Instant::now() - start);
    }

    #[test]
    fn test_byte_byte_lut_blind_array_init() {
        let mut ctx = Context::from(PARAM_MESSAGE_4_CARRY_0);
        let private_key = key(ctx.parameters);
        let public_key = &private_key.public_key;

        let items = std::array::from_fn(|i| i as u8);
        let bblut = ByteByteLUT::from_bytes(&items, private_key, &mut ctx);

        let mut result = ByteByteLUT::from_bytes_trivially(&[0; 256], &ctx);

        let index = ByteLWE::from_byte(0xff, &mut ctx, private_key);
        // let value = ByteLWE::from_byte(0xff, &mut ctx, private_key);
        let value = bblut.at(0xff, public_key, &ctx);
        result.blind_array_init(&index, &value, &ctx, public_key);

        result.print(public_key, private_key, &ctx);
    }

    #[test]
    fn test_blind_radix_sort() {
        let mut ctx = Context::from(PARAM_MESSAGE_4_CARRY_0);
        let private_key = key(ctx.parameters);
        let public_key = &private_key.public_key;

        let items: [u8; 256] = std::array::from_fn(|i| i as u8);
        let bblut = ByteByteLUT::from_bytes(&items, private_key, &mut ctx);

        let start = Instant::now();
        public_key.keyed_blind_counting_sort(&bblut, |blwe| blwe.hi.clone(), &ctx);
        println!("total time elapsed: {:?}", Instant::now() - start);
    }
}
