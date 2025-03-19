use revolut::*;
use tfhe::shortint::parameters::PARAM_MESSAGE_4_CARRY_0;

fn main() {
    // Initialize the context
    let mut ctx = Context::from(PARAM_MESSAGE_4_CARRY_0);

    // Generate the keys (or read them from the file PrivateKey4 if they already exist)
    let private_key = key(PARAM_MESSAGE_4_CARRY_0);

    // Extract the public key from the private key
    let public_key = &private_key.public_key;

    // Initialize the matrix
    let matrix = vec![
        vec![1, 2, 3, 4, 5],
        vec![2, 3, 4, 5, 6],
        vec![3, 4, 5, 6, 7],
        vec![4, 5, 6, 7, 8],
        vec![5, 6, 7, 8, 9],
    ];

    // Initialize the indices (row, column)
    let row = 2;
    let column = 3;

    // Encrypt the matrix as a vector of LUT ciphertexts
    // Two ways to do it:
    // - With row-padding: the matrix is encrypted with padding
    // - Without row-padding: the matrix is encrypted without padding revealing the number of rows
    #[cfg(feature = "row-padding")]
    let encrypted_matrix = private_key.encrypt_matrix_with_padding(&mut ctx, &matrix);
    #[cfg(not(feature = "row-padding"))]
    let encrypted_matrix = private_key.encrypt_matrix(&mut ctx, &matrix);

    // Encrypt the indices
    let lwe_row = private_key.allocate_and_encrypt_lwe(row, &mut ctx);
    let lwe_column = private_key.allocate_and_encrypt_lwe(column, &mut ctx);

    // Blindly access the matrix
    let lwe_res =
        public_key.blind_matrix_access(&encrypted_matrix, &lwe_row, &lwe_column, &mut ctx);

    // Decrypt the result
    let value = private_key.decrypt_lwe(&lwe_res, &ctx);

    println!("Value at index ({},{}): {}", row, column, value);
}
