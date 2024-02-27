// TODO: impl LWE_leq: LWE(int) x LWE(int) -> LWE(int 0 ou 1) => BMA(lower_triangle, x, y)
#[cfg(test)]
mod tests {
    use std::time::Instant;
    use tfhe::{core_crypto::algorithms::blind_rotate_assign, shortint::parameters::*};

    use crate::{context::Context, lut::LUT, private_key::PrivateKey};

    #[test]
    fn test_blind_rotation() {
        let start_time = Instant::now();
        println!("generating context and loading keys");
        let mut ctx = Context::from(PARAM_MESSAGE_4_CARRY_0);
        let private_key = PrivateKey::from_file("PrivateKey4");
        println!("{:?}", Instant::now() - start_time);

        let cipher_array = LUT::from_vec(&vec![1, 2, 3, 4], &private_key, &mut ctx);
        private_key.print_lut(&cipher_array, &ctx);
        println!("{:?}", Instant::now() - start_time);

        // rotation
        println!("performing blind rotation");
        let MessageModulus(n) = ctx.parameters.message_modulus;
        for i in 0..2 * n {
            println!("rotating {}", i);
            let mut glwe = cipher_array.0.clone();
            let cipher_rotation =
                private_key.allocate_and_encrypt_lwe(2 * (n as u64) - (i as u64), &mut ctx);
            blind_rotate_assign(
                &cipher_rotation,
                &mut glwe,
                &private_key.public_key.fourier_bsk,
            );
            private_key.print_lut(&LUT(glwe), &ctx);
        }
        println!("{:?}", Instant::now() - start_time);
    }
}
