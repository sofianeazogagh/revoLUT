// Imports and library uses needed for encryption, random generation, I/O, and timing
use revolut::{radix::ByteLWE, *};
use serde::de::value;
use tfhe::core_crypto::prelude::{lwe_ciphertext_cleartext_mul, Plaintext};
use tfhe::{
    boolean::public_key,
    core_crypto::prelude::{
        allocate_and_encrypt_new_lwe_ciphertext, allocate_and_trivially_encrypt_new_lwe_ciphertext,
        blind_rotate_assign, lwe_ciphertext_add, lwe_ciphertext_sub, lwe_keyswitch,
    },
    shortint::parameters::PARAM_MESSAGE_4_CARRY_0,
};
use std::fs::File;
use std::io::{BufWriter, Write};
use std::time::Instant;
use rand::Rng;
use tfhe::core_crypto::prelude::Cleartext;

// Definition of the BloomFilter struct, holding encrypted tables, the (public) encryption key, and hash matrices
pub struct BloomFilter {
    pub tables: Vec<LUT>,
    pub public_key: PublicKey,
    pub hash_matrices: Vec<Vec<Vec<u64>>>,
}

impl BloomFilter {
    /// Creates a new BloomFilter with `num_tables` hash tables using the provided private key
    pub fn new(private_key: &PrivateKey, num_tables: usize) -> Self {
        println!("[INFO] Initializing Bloom Filter");
        let mut ctx = Context::from(PARAM_MESSAGE_4_CARRY_0);
        let public_key = &private_key.public_key;

        // Initialize tables for each hash function
        let mut tables = Vec::new();
        for _ in 0..num_tables {
            tables.push(LUT::new(&mut ctx));
        }

        println!("[INFO] Bloom Filter initialized");

        // Fixed example coefficients for hash functions (could be randomized in real system for better security)
        let mut coefficients = [
            (1, 3, 2), (5, 7, 1), (11, 7, 5), (2, 2, 2),
            (3, 5, 7), (2, 3, 5), (2, 5, 2), (2, 7, 7),
            (2, 11, 2), (2, 13, 2)
        ];

        // Generate hash matrices for all hash tables
        let mut hash_matrices = Vec::new();
        for l in 0..num_tables {
            let mut matrix = Vec::new();
            for i in 0..ctx.full_message_modulus() {
                let mut row = Vec::new();

                // Each matrix row is a hash function: h(x, y) = a * x + b * y + c (mod modulus)
                for j in 0..ctx.full_message_modulus() {
                    row.push(
                        (coefficients[l].0 * i as u64 + 
                         coefficients[l].1 * j as u64 + 
                         coefficients[l].2 as u64) % ctx.full_message_modulus() as u64
                    );
                }

                matrix.push(row);
            }
            hash_matrices.push(matrix);

        }

        // Construct the BloomFilter instance
        Self {
            tables,
            public_key: public_key.clone(),
            hash_matrices,
        }
    }

    /// Hashes the input (a ByteLWE) into a LWE index using the num-th hash function and the context
    pub fn hash(&self, input: ByteLWE, num: usize, ctx: &mut Context) -> LWE {
        // Use the precomputed hash matrix for this hash function
        let hash_matrix = &self.hash_matrices[num - 1];
        // Perform the blind matrix access using FHE to hide the input
        let result = self.public_key.blind_matrix_access_clear(&hash_matrix, &input.lo, &input.hi, ctx);
        result
    }

    /// Inserts an input into the Bloom filter, homomorphically setting its bit in all tables
    pub fn insert(&mut self, input: ByteLWE, ctx: &mut Context, private_key: &PrivateKey) {
        println!("[INSERT]");

        // Encrypt constant 1 as an LWE ciphertext for incrementing table positions
        let lwe_one = self.public_key.allocate_and_trivially_encrypt_lwe(1, ctx);

        // For each table (i.e., each hash function), perform homomorphic increment at the hash position
        for i in 0..self.tables.len() {
            let hash = self.hash(input.clone(), i + 1, ctx);

            // Retrieve current value under encryption, then increment it by 1 
            let mut current_value = self.public_key.blind_array_access(&hash, &self.tables[i], ctx);
            let mut current_value_clone = current_value.clone();
            // current_value_clone = current_value + 1
            lwe_ciphertext_sub(&mut current_value_clone, &lwe_one, &current_value);
            // Write incremented value back homomorphically
            self.public_key.blind_array_increment(&mut self.tables[i], &hash, &current_value_clone, ctx);
        }
    }

    /// Checks if an input is in the Bloom filter, returning an encrypted 1 if present, 0 otherwise
    pub fn contains(&self, input: ByteLWE, ctx: &mut Context, private_key: &PrivateKey) -> LWE {
        println!("[LOOKUP]");

        let mut values = Vec::new();

        // For each table, check the bit for the input's hash and collect the encrypted values
        for i in 0..self.tables.len() {
            let mut hash = self.hash(input.clone(), i + 1, ctx);
            let mut value = self.public_key.blind_array_access(&hash, &self.tables[i], ctx);
            values.push(value);
        }

        // Homomorphically sum the bits: result = values[0] + values[1] + ... + values[n]
        let mut result = allocate_and_trivially_encrypt_new_lwe_ciphertext(
            ctx.big_lwe_dimension().to_lwe_size(),
            Plaintext(0),
            ctx.ciphertext_modulus(),
        );

        for i in 0..values.len() {
            let copy = result.clone();
            lwe_ciphertext_add(&mut result, &copy, &values[i]);
        }

        // Now, check if the number of hits equals the number of hash tables.
        // Create LUT with a 1 at position n (n = number of hash tables), 0 elsewhere.
        let mut comp_vec = vec![0_u64; ctx.full_message_modulus() as usize];
        comp_vec[self.tables.len()] = 1_u64;
        // Build encrypted LUT to compare the sum
        let comp_lut = LUT::from_vec(&comp_vec, private_key, ctx);
        // Use a blind array access to get a 1 if result == n (present), else 0 (not present)
        result = self.public_key.blind_array_access(&result, &comp_lut, ctx);

        result
    }
}


fn main() {
    // Setup encryption parameters and secret key
    let mut ctx = Context::from(PARAM_MESSAGE_4_CARRY_0);
    let private_key: &'static PrivateKey = key(PARAM_MESSAGE_4_CARRY_0);

    // Set up random number generator
    use rand::Rng;
    let mut rng = rand::thread_rng();

    // Experiment configuration: different numbers of elements to insert, and number of test trials
    let nums_elements = [10, 20, 30, 40, 50, 60, 70, 80, 90, 100];
    let num_trials = 10;

    // Open CSV output file for append (for results logging)
    let file = File::options().append(true).open("blind_bloom_filter.txt").unwrap();
    let mut writer = BufWriter::new(file);

    // Repeat experiment for each trial (to take averages)
    for _ in 0..num_trials {
        // Loop over different cardinalities for the Bloom filter
        for num_elements in nums_elements {
            let mut test_elements = Vec::new();

            // Generate a set of random distinct elements in 0..255 (as u8)
            (0..num_elements).for_each(|_| {
                let mut element = rng.gen_range(0..=255) as u8;
                // Ensure uniqueness in this set for a fair test
                while test_elements.contains(&element) {
                    element = rng.gen_range(0..=255) as u8;
                }
                test_elements.push(element);
            });

            // Split elements: half for positive testing (inserted), half for negative (not inserted)
            let positive_test_elements = test_elements[0..(test_elements.len() / 2)].to_vec();
            let negative_test_elements = test_elements[(test_elements.len() / 2)..].to_vec();

            let test_elements_len = test_elements.len();

            // Try different table counts per filter (number of hash functions)
            for num_tables in 1..=10 {
                let mut total_insert_time = 0;
                let mut total_lookup_time = 0;
                let mut avg_insert_time = 0f64;
                let mut avg_lookup_time = 0f64;
                let mut fp_count = 0;
                let mut fn_count = 0;

                // Construct the Bloom filter with the given table count
                let mut bloom_filter = BloomFilter::new(private_key, num_tables);

                // Insert positive set into the Bloom filter, timing each insertion
                let mut i = 0;
                for element in &positive_test_elements {
                    println!("Inserting element: {:?}", element);
                    let input = ByteLWE::from_byte(*element, &mut ctx, private_key);

                    // Start timer, insert, measure time
                    let start = Instant::now();
                    bloom_filter.insert(input.clone(), &mut ctx, private_key);
                    total_insert_time += start.elapsed().as_millis() as u64;
                }

                // For all test elements (positives and negatives), check membership and timing
                for element in &test_elements {
                    let input = ByteLWE::from_byte(*element, &mut ctx, private_key);
                    let start = Instant::now();
                    let contains = bloom_filter.contains(input, &mut ctx, private_key);
                    total_lookup_time += start.elapsed().as_millis() as u64;

                    // Decrypt for evaluation (in a real scenario, only statistics or threshold output is published)
                    let dec_contains = private_key.decrypt_lwe(&contains, &ctx);
                    println!("Dec contains: {:?}", dec_contains);

                    // If inserted but answer is 0: false negative
                    if (positive_test_elements.contains(element)) && dec_contains == 0 {
                        println!("False negative: {:?}", element);
                        fn_count += 1;
                    }
                    // If not-inserted but answer is 1: false positive
                    if (negative_test_elements.contains(element)) && dec_contains == 1 {
                        println!("False positive: {:?}", element);
                        fp_count += 1;
                    }
                }

                // Average times per insertion and membership check
                avg_insert_time += total_insert_time as f64 / (test_elements_len / 2) as f64;
                avg_lookup_time += total_lookup_time as f64 / test_elements_len as f64;

                // Calculate observed false positive/negative rates
                let fprate = fp_count as f64 / positive_test_elements.len() as f64;
                let fnrate = fn_count as f64 / negative_test_elements.len() as f64;

                // Output statistics for this trial to the console
                println!("False positive count: {:?}", fp_count);
                println!("False negative count: {:?}", fn_count);
                println!("False positive rate: {:?}", fprate);
                println!("False negative rate: {:?}", fnrate);
                println!("Average insert time: {:?} ms", avg_insert_time);
                println!("Average lookup time: {:?} ms", avg_lookup_time);

                // Write results as a CSV row to the output file
                writeln!(writer, "{},{},{},{},{},{},{},{}",
                    num_elements, num_tables, fp_count, fn_count,
                    fprate, fnrate, avg_insert_time, avg_lookup_time
                );

                // Make sure every result is flushed
                writer.flush().unwrap();
            }
        }
    }
}

