use revolut::{Context, Poly, PublicKey, GLWE, LWE};
use tfhe::core_crypto::prelude::lwe_ciphertext_add_assign;

/// Encode a row
pub fn encode_row(row: &Vec<u64>, ctx: &Context) -> Poly {
    let n = ctx.polynomial_size().0;
    let p = ctx.full_message_modulus() as u64;

    // resize row to n with 0s if needed
    let mut new_row = row.clone();
    if row.len() < n {
        new_row.extend(vec![0; n - row.len()]);
    }
    // encode row
    let first = new_row[0];
    new_row[1..].reverse();
    for x in &mut new_row[1..] {
        *x = x.wrapping_neg() % p;
    }
    new_row[0] = first;
    Poly::from_container(new_row)
}

/// Encode a small matrix where each row is a polynomial
#[allow(dead_code)]
pub fn encode_matrix(matrix: &Vec<Vec<u64>>, ctx: &Context) -> Vec<Poly> {
    let mut result: Vec<Poly> = vec![];

    for row in matrix {
        result.push(encode_row(row, ctx));
    }
    result
}

#[allow(dead_code)]
/// Encode a big matrix where each row is a vector of polynomials
pub fn encode_big_matrix(matrix: &Vec<Vec<u64>>, ctx: &Context) -> Vec<Vec<Poly>> {
    let mut result: Vec<Vec<Poly>> = vec![];
    for row in matrix {
        let chunks = row
            .chunks(ctx.polynomial_size().0)
            .map(|chunk| encode_row(&chunk.to_vec(), ctx))
            .collect::<Vec<_>>();
        result.push(chunks);
    }

    result
}

/// (Small) Matrix-vector multiplication (to use when the matrix has less than N columns (e.g 2048 when p=16))
#[allow(dead_code)]
pub fn mat_vec_mul(
    matrix: &Vec<Vec<u64>>,
    ct_vec: &GLWE,
    ctx: &Context,
    public_key: &PublicKey,
) -> Vec<LWE> {
    let mut result = vec![];

    // Encode the rows of the matrix as polynomials
    let encoded_matrix = encode_matrix(matrix, ctx);

    // absorption rows x glwe
    for row in encoded_matrix {
        let r = public_key.glwe_absorption_polynomial_with_fft(ct_vec, &row);

        result.push(public_key.glwe_extract(&r, 0, ctx));
    }

    result
}

#[allow(dead_code)]
/// (Big) Matrix-vector multiplication (to use when the matrix has more than N columns (e.g 2048 when p=16))
pub fn mat_vec_mul_big(
    matrix: &Vec<Vec<u64>>,
    cts_vec: &Vec<GLWE>,
    ctx: &Context,
    public_key: &PublicKey,
) -> Vec<LWE> {
    let mut result = vec![];

    // Encode the rows of the matrix as polynomials
    let encoded_matrix = encode_big_matrix(matrix, ctx);

    // absorption rows x glwe
    let mut rows_results = vec![];
    for (_i, row) in encoded_matrix.iter().enumerate() {
        let mut r_vec = vec![];
        // let start = Instant::now();
        for (j, ct) in cts_vec.iter().enumerate() {
            let r = public_key.glwe_absorption_polynomial_with_fft(ct, &row[j]);
            r_vec.push(public_key.glwe_extract(&r, 0, ctx));
        }
        // let end = Instant::now();
        // println!("Time for row {} : {:?}", i, end.duration_since(start));
        rows_results.push(r_vec);
    }

    // sum rows
    for row in rows_results {
        let mut sum = row[0].clone();
        for ct in row[1..].iter() {
            lwe_ciphertext_add_assign(&mut sum, ct);
        }
        result.push(sum);
    }

    result
}

#[cfg(test)]
mod tests {
    use std::time::Instant;

    use super::*;
    use revolut::key;
    use tfhe::shortint::parameters::PARAM_MESSAGE_4_CARRY_0;

    use rand::Rng;

    #[test]
    fn test_mat_vec_mul() {
        // Setup context and public key
        let mut ctx = Context::from(PARAM_MESSAGE_4_CARRY_0);
        let private_key = key(PARAM_MESSAGE_4_CARRY_0);
        let public_key = &private_key.public_key;

        // Define a simple 3x3 matrix and a GLWE ciphertext vector
        // let matrix = vec![vec![1, 0, 0], vec![0, 1, 0], vec![0, 0, 1]];

        let p = ctx.full_message_modulus();
        let n = ctx.polynomial_size().0;

        // Define a random matrix of size t*n with elements modulo 16
        let mat_size = n - 1 as usize;
        let mut rng = rand::thread_rng();
        let mut matrix = vec![vec![0; mat_size]; mat_size];
        for i in 0..mat_size {
            for j in 0..mat_size {
                matrix[i][j] = rng.gen_range(0..p) as u64;
            }
        }

        // Define a GLWE ciphertext vector
        let v = vec![1; mat_size as usize];
        let ct_vec = private_key.allocate_and_encrypt_glwe_from_vec(&v, &mut ctx);

        // Call the mat_vec_mul function
        let start = Instant::now();
        let result = mat_vec_mul(&matrix, &ct_vec, &ctx, &public_key);
        let end = Instant::now();
        println!(
            "Time taken for mat_vec_mul (Small matrix): {:?}",
            end.duration_since(start)
        );

        // Decrypt the result
        let actual = result
            .iter()
            .map(|ct| private_key.decrypt_lwe(ct, &ctx))
            .collect::<Vec<_>>();

        // Calculate the expected result by performing matrix-vector multiplication
        let mut expected = vec![0; mat_size as usize];
        for i in 0..mat_size as usize {
            for j in 0..mat_size as usize {
                expected[i] += matrix[i][j] * v[j] as u64;
            }
        }
        expected = expected.iter().map(|x| x % p as u64).collect::<Vec<_>>();

        // Assert the result is as expected
        assert_eq!(actual, expected);
    }

    #[test]
    fn test_mat_vec_mul_big() {
        // Setup context and public key
        let mut ctx = Context::from(PARAM_MESSAGE_4_CARRY_0);
        let private_key = key(PARAM_MESSAGE_4_CARRY_0);
        let public_key = &private_key.public_key;

        let n = ctx.polynomial_size().0;

        println!("n: {}", n);

        let t = 1;
        println!("t: {}", t);
        // // Define identity matrix of size 2n x 2n
        // let mut matrix = vec![vec![0; t * n]; t * n];
        // for i in 0..t * n {
        //     matrix[i][i] = 1;
        // }

        let p = ctx.full_message_modulus() as u64;

        // Define a random matrix of size t*n with elements modulo 16
        let mut rng = rand::thread_rng();
        let mut matrix = vec![vec![0; t * n]; t * n];
        for i in 0..t * n {
            for j in 0..t * n {
                matrix[i][j] = rng.gen_range(0..p);
            }
        }

        // Define a vector of size t*n
        let big_vec = vec![1; t * n];
        let cts_vec = big_vec
            .chunks(n)
            .map(|chunk| private_key.allocate_and_encrypt_glwe_from_vec(&chunk.to_vec(), &mut ctx))
            .collect::<Vec<_>>();

        // Call the mat_vec_mul_big function
        let start = Instant::now();
        let result = mat_vec_mul_big(&matrix, &cts_vec, &ctx, &public_key);
        let end = Instant::now();
        println!(
            "Time taken for mat_vec_mul_big: {:?}",
            end.duration_since(start)
        );

        // Decrypt the result
        let actual = result
            .iter()
            .map(|ct| private_key.decrypt_lwe(ct, &ctx))
            .collect::<Vec<_>>();

        // Calculate the expected result by performing matrix-vector multiplication
        let mut expected = vec![0; t * n];
        for i in 0..t * n {
            for j in 0..t * n {
                expected[i] += matrix[i][j] * big_vec[j];
            }
            expected[i] = expected[i] % p;
        }
        assert_eq!(actual, expected);
    }
}
