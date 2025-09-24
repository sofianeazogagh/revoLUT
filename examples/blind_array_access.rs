use revolut::*;
use revolut::params::{param_1, param_2, param_3, param_4};


fn main() {
    // Initialize the context
    let mut ctx = Context::from(param_4());

    // Generate the keys (or read them from the file PrivateKey4 if they already exist)
    let private_key = key(param_4());

    // Extract the public key from the private key
    let public_key = &private_key.public_key;

    // Initialize the array and the index to access
    let array = vec![1, 2, 3, 4, 5];
    let index = 2;

    // Encrypt the array as a LUT ciphertext and the index as a LWE ciphertext
    let lut = LUT::from_vec(&array, &private_key, &mut ctx);
    let lwe = private_key.allocate_and_encrypt_lwe(index, &mut ctx);

    // Blindly access the array
    let lwe_res = public_key.blind_array_access(&lwe, &lut, &mut ctx);

    // Decrypt the result
    let value = private_key.decrypt_lwe(&lwe_res, &ctx);

    println!("Value at index {}: {}", index, value);
}
