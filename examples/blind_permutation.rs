use revolut::*;
use tfhe::shortint::parameters::PARAM_MESSAGE_4_CARRY_0;

fn main() {
    // Initialize the context
    let mut ctx = Context::from(PARAM_MESSAGE_4_CARRY_0);

    // Generate the keys (or read them from the file PrivateKey4 if they already exist)
    let private_key = key(PARAM_MESSAGE_4_CARRY_0);

    // Extract the public key from the private key
    let public_key = &private_key.public_key;

    // Initialize the array and the permutation indices
    let array = vec![0, 1, 3, 2, 5, 4];
    let permutation = vec![0, 1, 3, 2, 5, 4];

    // Encrypt the array as a LUT ciphertext and the permutation as LWE ciphertexts
    let lut = LUT::from_vec(&array, &private_key, &mut ctx);
    let lwes_permutation = permutation
        .iter()
        .map(|&i| private_key.allocate_and_encrypt_lwe(i, &mut ctx))
        .collect::<Vec<_>>();

    // Blindly permute the array
    let lut_res = public_key.blind_permutation(&lut, &lwes_permutation, &mut ctx);

    // Decrypt the result
    let array_res = lut_res.to_array(&private_key, &mut ctx);

    // The result should be [array[permutation[0]], array[permutation[1]], ...] with some zeros if the size of the array is < 16
    println!("Permuted array: {:?}", array_res);
}
