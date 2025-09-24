use revolut::*;
use revolut::params::{param_4};

fn main() {
    // Initialize the context
    let mut ctx = Context::from(param_4());

    // Generate the keys (or read them from the file PrivateKey4 if they already exist)
    let private_key = key(param_4());

    // Extract the public key from the private key
    let public_key = &private_key.public_key;

    // Initialize the array, the index and the increment to add
    let array = vec![0, 1, 2, 3, 4];
    let index = 2;
    let increment = 1;

    // Encrypt the array as a mutable LUT ciphertext and the index and increment as LWE ciphertexts
    let mut lut = LUT::from_vec(&array, &private_key, &mut ctx);
    let lwe_index = private_key.allocate_and_encrypt_lwe(index, &mut ctx);
    let lwe_increment = private_key.allocate_and_encrypt_lwe(increment, &mut ctx);

    // Blindly access the array
    public_key.blind_array_increment(&mut lut, &lwe_index, &lwe_increment, &mut ctx);

    // Decrypt the result
    let lut_res = lut.to_array(&private_key, &mut ctx);

    println!("Array after increment: {:?}", lut_res);
}
