use revolut::{radix::ByteLWE, *};
use tfhe::{
    core_crypto::prelude::{
        allocate_and_trivially_encrypt_new_lwe_ciphertext,
        lwe_ciphertext_add, lwe_ciphertext_sub,
    },
    shortint::parameters::PARAM_MESSAGE_4_CARRY_0,
};
use std::time::Instant;

pub struct BloomFilter {
    pub tables: Vec<LUT>,
    pub public_key: PublicKey,
    pub hash_matrices: Vec<Vec<Vec<u64>>>,
}

impl BloomFilter {
    pub fn new(private_key: &PrivateKey, num_tables: usize) -> Self {
        println!("[INFO] Initializing Bloom Filter with {} hash functions", num_tables);
        let mut ctx = Context::from(PARAM_MESSAGE_4_CARRY_0);
        let public_key = &private_key.public_key;

        let mut tables = Vec::new();
        for _ in 0..num_tables {
            tables.push(LUT::new(&mut ctx));
        }

        // Generate hash coefficients for different hash functions
        let mut coefficients = Vec::new();
        for i in 0..num_tables {
            coefficients.push(((i + 1) as u64, (i * 2 + 3) as u64));
        }

        let mut hash_matrices = Vec::new();
        for l in 0..num_tables {
            let mut matrix = Vec::new();
            for i in 0..ctx.full_message_modulus() {
                let mut row = Vec::new();
                for j in 0..ctx.full_message_modulus() {
                    row.push((coefficients[l].0 * i as u64 + coefficients[l].1 * j as u64) % ctx.full_message_modulus() as u64);
                }
                matrix.push(row);
            }
            hash_matrices.push(matrix);
        }

        Self {
            tables,
            public_key: public_key.clone(),
            hash_matrices,
        }
    }

    pub fn hash(&self, input: ByteLWE, num: usize, ctx: &mut Context) -> LWE {
        let hash_matrix = &self.hash_matrices[num - 1];
        let result = self.public_key.blind_matrix_access_clear(&hash_matrix, &input.lo, &input.hi, ctx);
        result
    }

    pub fn insert(&mut self, input: ByteLWE, ctx: &mut Context, _private_key: &PrivateKey) {
        for i in 0..self.tables.len() {
            let hash = self.hash(input.clone(), i + 1, ctx);
            let lwe_one = self.public_key.allocate_and_trivially_encrypt_lwe(1, ctx);
            let current_value = self.public_key.blind_array_access(&hash, &self.tables[i], ctx);
            let mut current_value_clone = current_value.clone();
            lwe_ciphertext_sub(&mut current_value_clone, &lwe_one, &current_value);
            self.public_key.blind_array_increment(&mut self.tables[i], &hash, &current_value_clone, ctx);
        }
    }

    pub fn contains(&self, input: ByteLWE, ctx: &mut Context, private_key: &PrivateKey) -> LWE {
        let mut values = Vec::new();

        for i in 0..self.tables.len() {
            let hash = self.hash(input.clone(), i + 1, ctx);
            let value = self.public_key.blind_array_access(&hash, &self.tables[i], ctx);
            values.push(value);
        }

        let mut result = allocate_and_trivially_encrypt_new_lwe_ciphertext(
            ctx.big_lwe_dimension().to_lwe_size(),
            tfhe::core_crypto::prelude::Plaintext(0),
            ctx.ciphertext_modulus(),
        );

        for i in 0..values.len() {
            let copy = result.clone();
            lwe_ciphertext_add(&mut result, &copy, &values[i]);
        }

        let mut comp_vec = vec![0_u64; ctx.full_message_modulus() as usize];
        comp_vec[self.tables.len()] = 1_u64;
        let comp_lut = LUT::from_vec(&comp_vec, private_key, ctx);
    
        result = self.public_key.blind_array_access(&result, &comp_lut, ctx);
        result
    }
}

#[derive(Debug)]
pub struct ExperimentResults {
    pub num_hash_functions: usize,
    pub false_positives: usize,
    pub false_negatives: usize,
    pub false_positive_rate: f64,
    pub false_negative_rate: f64,
    pub avg_insert_time_ms: f64,
    pub avg_lookup_time_ms: f64,
    pub total_experiment_time_ms: u64,
}

fn run_experiment(num_hash_functions: usize, num_elements: usize) -> ExperimentResults {
    println!("\n=== Running experiment with {} hash functions ===", num_hash_functions);
    
    let start_experiment = Instant::now();
    let mut ctx = Context::from(PARAM_MESSAGE_4_CARRY_0);
    let private_key: &'static PrivateKey = key(PARAM_MESSAGE_4_CARRY_0);
    let mut bloom_filter = BloomFilter::new(private_key, num_hash_functions);
    
    // Generate test elements
    let test_elements: Vec<u8> = (0..num_elements as u8).collect();
    
    // Split elements: first half for insertion, second half for false positive testing
    let insert_count = num_elements / 2;
    let elements_to_insert: Vec<u8> = test_elements[0..insert_count].to_vec();
    let elements_not_inserted: Vec<u8> = test_elements[insert_count..].to_vec();
    
    println!("Inserting {} elements", insert_count);
    println!("Testing {} elements for false positives", elements_not_inserted.len());
    
    // Measure insert times
    let mut total_insert_time = 0u64;
    for element in &elements_to_insert {
        let input = ByteLWE::from_byte(*element, &mut ctx, private_key);
        let start = Instant::now();
        bloom_filter.insert(input, &mut ctx, private_key);
        total_insert_time += start.elapsed().as_millis() as u64;
    }
    
    // Measure lookup times and count errors
    let mut total_lookup_time = 0u64;
    let mut false_positives = 0usize;
    let mut false_negatives = 0usize;
    
    // Test inserted elements (should return true - check for false negatives)
    for element in &elements_to_insert {
        let input = ByteLWE::from_byte(*element, &mut ctx, private_key);
        let start = Instant::now();
        let contains = bloom_filter.contains(input, &mut ctx, private_key);
        total_lookup_time += start.elapsed().as_millis() as u64;
        let dec_contains = private_key.decrypt_lwe(&contains, &ctx);
        
        if dec_contains == 0 {
            false_negatives += 1;
        }
    }
    
    // Test non-inserted elements (should return false - check for false positives)
    for element in &elements_not_inserted {
        let input = ByteLWE::from_byte(*element, &mut ctx, private_key);
        let start = Instant::now();
        let contains = bloom_filter.contains(input, &mut ctx, private_key);
        total_lookup_time += start.elapsed().as_millis() as u64;
        let dec_contains = private_key.decrypt_lwe(&contains, &ctx);
        
        if dec_contains == 1 {
            false_positives += 1;
        }
    }
    
    let total_experiment_time = start_experiment.elapsed().as_millis() as u64;
    
    let avg_insert_time = total_insert_time as f64 / insert_count as f64;
    let avg_lookup_time = total_lookup_time as f64 / num_elements as f64;
    let false_positive_rate = false_positives as f64 / elements_not_inserted.len() as f64;
    let false_negative_rate = false_negatives as f64 / insert_count as f64;
    
    ExperimentResults {
        num_hash_functions,
        false_positives,
        false_negatives,
        false_positive_rate,
        false_negative_rate,
        avg_insert_time_ms: avg_insert_time,
        avg_lookup_time_ms: avg_lookup_time,
        total_experiment_time_ms: total_experiment_time,
    }
}

fn main() {
    println!("Bloom Filter Hash Function Experiment");
    println!("=====================================");
    
    let num_elements = 100;
    let hash_function_counts = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10];
    
    let mut results = Vec::new();
    
    for num_hash_functions in hash_function_counts {
        let result = run_experiment(num_hash_functions, num_elements);
        results.push(result);
    }
    
    // Print results table
    println!("\nResults Summary:");
    println!("================");
    println!("{:<4} | {:<4} | {:<4} | {:<8} | {:<8} | {:<12} | {:<12} | {:<12}", 
             "Hash", "FP", "FN", "FP Rate", "FN Rate", "Avg Insert", "Avg Lookup", "Total Time");
    println!("{:<4} | {:<4} | {:<4} | {:<8} | {:<8} | {:<12} | {:<12} | {:<12}", 
             "----", "--", "--", "--------", "--------", "------------", "------------", "------------");
    
    for result in &results {
        println!("{:<4} | {:<4} | {:<4} | {:<8.4} | {:<8.4} | {:<12.2} | {:<12.2} | {:<12}", 
                 result.num_hash_functions,
                 result.false_positives,
                 result.false_negatives,
                 result.false_positive_rate,
                 result.false_negative_rate,
                 result.avg_insert_time_ms,
                 result.avg_lookup_time_ms,
                 result.total_experiment_time_ms);
    }
    
    // Find optimal configurations
    println!("\nAnalysis:");
    println!("=========");
    
    // Find configuration with lowest false positive rate
    let min_fp_result = results.iter().min_by(|a, b| a.false_positive_rate.partial_cmp(&b.false_positive_rate).unwrap()).unwrap();
    println!("Lowest false positive rate: {} hash functions (FP rate: {:.4})", 
             min_fp_result.num_hash_functions, min_fp_result.false_positive_rate);
    
    // Find configuration with lowest false negative rate
    let min_fn_result = results.iter().min_by(|a, b| a.false_negative_rate.partial_cmp(&b.false_negative_rate).unwrap()).unwrap();
    println!("Lowest false negative rate: {} hash functions (FN rate: {:.4})", 
             min_fn_result.num_hash_functions, min_fn_result.false_negative_rate);
    
    // Find configuration with fastest insert time
    let fastest_insert = results.iter().min_by(|a, b| a.avg_insert_time_ms.partial_cmp(&b.avg_insert_time_ms).unwrap()).unwrap();
    println!("Fastest insert time: {} hash functions ({:.2} ms)", 
             fastest_insert.num_hash_functions, fastest_insert.avg_insert_time_ms);
    
    // Find configuration with fastest lookup time
    let fastest_lookup = results.iter().min_by(|a, b| a.avg_lookup_time_ms.partial_cmp(&b.avg_lookup_time_ms).unwrap()).unwrap();
    println!("Fastest lookup time: {} hash functions ({:.2} ms)", 
             fastest_lookup.num_hash_functions, fastest_lookup.avg_lookup_time_ms);
    
    // Generate CSV output for plotting
    println!("\nGenerating CSV data for plotting...");
    let mut csv_content = String::from("Hash Functions,False Positives,False Negatives,False Positive Rate,False Negative Rate,Avg Insert Time (ms),Avg Lookup Time (ms),Total Time (ms)\n");
    
    for result in &results {
        csv_content.push_str(&format!("{},{},{},{:.6},{:.6},{:.2},{:.2},{}\n",
            result.num_hash_functions,
            result.false_positives,
            result.false_negatives,
            result.false_positive_rate,
            result.false_negative_rate,
            result.avg_insert_time_ms,
            result.avg_lookup_time_ms,
            result.total_experiment_time_ms));
    }
    
    std::fs::write("bloom_filter_results.csv", csv_content).expect("Failed to write CSV file");
    println!("Results saved to bloom_filter_results.csv");
    
    println!("\nExperiment completed!");
}
