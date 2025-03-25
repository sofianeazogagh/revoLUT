use revolut::*;
use tfhe::shortint::parameters::PARAM_MESSAGE_4_CARRY_0;

fn main() {
    // Initialize the context
    let mut ctx = Context::from(PARAM_MESSAGE_4_CARRY_0);

    // Generate the keys (or read them from the file PrivateKey4 if they already exist)
    let private_key = key(PARAM_MESSAGE_4_CARRY_0);

    // Extract the public key from the private key
    let public_key = &private_key.public_key;

    // Initialize the array to sort
    let array = vec![15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0];

    // Encrypt the array as a LUT ciphertext
    let lut = LUT::from_vec(&array, &private_key, &mut ctx);

    // Blindly sort the array
    let encrypted_sorted_array = public_key.blind_counting_sort(&lut, &mut ctx);

    // Decrypt the result
    let sorted_array = encrypted_sorted_array.to_array(&private_key, &mut ctx);

    println!("Sorted array: {:?}", sorted_array);
}
