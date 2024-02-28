pub mod context;
pub mod lut;
pub mod private_key;
pub mod public_key;

mod blind_sort;

#[cfg(test)]

mod test {
    use crate::context::Context;
    use crate::lut::{LUTStack, LUT};
    use crate::private_key::PrivateKey;
    use tfhe::{
        core_crypto::entities::LweCiphertext, shortint::parameters::PARAM_MESSAGE_4_CARRY_0,
    };

    #[test]
    fn test_lwe_enc() {
        let mut ctx = Context::from(PARAM_MESSAGE_4_CARRY_0);
        let private_key = PrivateKey::new(&mut ctx);
        let input: u64 = 3;
        let lwe = private_key.allocate_and_encrypt_lwe(input, &mut ctx);
        let clear = private_key.decrypt_lwe(&lwe, &mut ctx);
        println!("Test encryption-decryption");
        assert_eq!(input, clear);
    }

    #[test]
    fn test_lut_enc() {
        let mut ctx = Context::from(PARAM_MESSAGE_4_CARRY_0);
        let private_key = PrivateKey::new(&mut ctx);
        let array = vec![0, 1, 2, 3, 4];
        let _lut = LUT::from_vec(&array, &private_key, &mut ctx);
    }

    #[test]
    fn test_neg_lwe() {
        let mut ctx = Context::from(PARAM_MESSAGE_4_CARRY_0);
        let private_key = PrivateKey::new(&mut ctx);
        let public_key = &private_key.public_key;
        let input: u64 = 3;
        let mut lwe = private_key.allocate_and_encrypt_lwe(input, &mut ctx);
        public_key.wrapping_neg_lwe(&mut lwe);
        let clear = private_key.decrypt_lwe(&lwe, &mut ctx);
        println!("Test encryption-decryption");
        println!("neg_lwe = {}", clear);
        // assert_eq!(input,16-clear);
    }

    #[test]
    fn test_neg_lwe_assign() {
        let mut ctx = Context::from(PARAM_MESSAGE_4_CARRY_0);
        let private_key = PrivateKey::new(&mut ctx);
        let public_key = &private_key.public_key;
        let input: u64 = 3;
        let mut lwe = private_key.allocate_and_encrypt_lwe(input, &mut ctx);
        let neg_lwe = public_key.neg_lwe(&mut lwe, &ctx);
        let clear = private_key.decrypt_lwe(&neg_lwe, &mut ctx);
        println!("Test encryption-decryption");
        println!("neg_lwe = {}", clear);
        // assert_eq!(input,16-clear);
    }

    #[test]
    fn test_many_lwe_to_glwe() {
        let mut ctx = Context::from(PARAM_MESSAGE_4_CARRY_0);
        let private_key = PrivateKey::new(&mut ctx);
        let public_key = &private_key.public_key;
        let our_input: Vec<u64> = vec![1, 2, 3, 15];
        let mut many_lwe: Vec<LweCiphertext<Vec<u64>>> = vec![];
        for input in our_input {
            let lwe = private_key.allocate_and_encrypt_lwe(input, &mut ctx);
            many_lwe.push(lwe);
        }
        let lut = LUT::from_vec_of_lwe(many_lwe, public_key, &ctx);
        let output_pt = private_key.decrypt_and_decode_glwe(&lut.0, &ctx);
        println!("Test many LWE to one GLWE");
        println!("{:?}", output_pt);
    }

    #[test]
    fn test_lwe_to_lut() {
        let mut ctx = Context::from(PARAM_MESSAGE_4_CARRY_0);
        let private_key = PrivateKey::new(&mut ctx);
        let public_key = &private_key.public_key;
        let our_input = 8u64;
        let lwe = private_key.allocate_and_encrypt_lwe(our_input, &mut ctx);
        let lut = LUT::from_lwe(&lwe, public_key, &ctx);
        let output_pt = private_key.decrypt_and_decode_glwe(&lut.0, &ctx);
        println!("Test LWE to LUT");
        println!("{:?}", output_pt);
    }

    #[test]

    fn test_eq_scalar() {
        let mut ctx = Context::from(PARAM_MESSAGE_4_CARRY_0);
        let private_key = PrivateKey::new(&mut ctx);
        let public_key = &private_key.public_key;
        let our_input = 0u64;
        let lwe = private_key.allocate_and_encrypt_lwe(our_input, &mut ctx);

        for i in 0..16 {
            let cp = public_key.eq_scalar(&lwe, i, &ctx);
            let res = private_key.decrypt_lwe(&cp, &ctx);
            println!("{} == {} : {}", our_input, i, res);
        }
    }

    #[test]
    fn test_lut_stack_from_lut() {
        let mut ctx = Context::from(PARAM_MESSAGE_4_CARRY_0);
        let private_key = PrivateKey::new(&mut ctx);
        let public_key = &private_key.public_key;
        let array = vec![2, 1, 2, 3, 4];
        let lut = LUT::from_vec(&array, &private_key, &mut ctx);

        let lut_stack = LUTStack::from_lut(lut, public_key, &ctx);

        lut_stack.print(&private_key, &ctx);
    }

    #[test]
    fn test_blind_permutation() {
        let mut ctx = Context::from(PARAM_MESSAGE_4_CARRY_0);
        let private_key = PrivateKey::from_file("PrivateKey");

        let cipher_array = vec![1, 2, 3, 4];
        let lut = LUT::from_vec(&cipher_array, &private_key, &mut ctx);

        // blind_permutation
        let cipher_perm = private_key.encrypt_permutation(vec![1, 0, 3, 2], &mut ctx);
        let cipher_permuted_array =
            private_key
                .public_key
                .blind_permutation(lut, cipher_perm, &ctx);

        assert!(private_key
            .decrypt_lut(&cipher_permuted_array, &ctx)
            .starts_with(&[2, 1, 4, 3]));
    }
}
