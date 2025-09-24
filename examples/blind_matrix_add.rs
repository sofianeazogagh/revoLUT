use revolut::*;
use revolut::params::{param_4};

fn main() {
    // Initialize the context
    let mut ctx = Context::from(param_4());

    // Generate the keys (or read them from the file PrivateKey4 if they already exist)
    let private_key = key(param_4());

    // Extract the public key from the private key
    let public_key = &private_key.public_key;

    // Initialize the matrix
    let matrix = vec![
        vec![1, 1, 1, 1, 1],
        vec![1, 1, 1, 1, 1],
        vec![1, 1, 1, 1, 1],
        vec![1, 1, 1, 1, 1],
        vec![1, 1, 1, 1, 1],
    ];

    // Initialize the indices (row, column)
    let row = 2;
    let column = 2;

    // Initialize the increment
    let increment = 2;

    // Encrypt the matrix as a vector of LUT ciphertexts
    let mut encrypted_matrix = private_key.encrypt_matrix(&mut ctx, &matrix);

    // Encrypt the indices
    let lwe_row = private_key.allocate_and_encrypt_lwe(row, &mut ctx);
    let lwe_column = private_key.allocate_and_encrypt_lwe(column, &mut ctx);

    // Encrypt the increment
    let lwe_increment = private_key.allocate_and_encrypt_lwe(increment, &mut ctx);

    // Blindly access the matrix
    public_key.blind_matrix_add(
        &mut encrypted_matrix,
        &lwe_row,
        &lwe_column,
        &lwe_increment,
        &mut ctx,
    );

    // Decrypt the result
    encrypted_matrix.iter().for_each(|lut| {
        let array = lut.to_array(&private_key, &mut ctx);
        println!("{:?}", &array[0..6]);
    });
}
