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


pub struct BloomFilter {
    pub tables: Vec<LUT>,
    pub public_key: PublicKey,
    pub hash_matrices: Vec<Vec<Vec<u64>>>,
}

impl BloomFilter {
    pub fn new(private_key: &PrivateKey, num_tables: usize) -> Self {
        println!("[INFO] Initializing Bloom Filter");
        let mut ctx = Context::from(PARAM_MESSAGE_4_CARRY_0);
        let public_key = &private_key.public_key;

        let mut tables = Vec::new();
        for _ in 0..num_tables {
            tables.push(LUT::new(&mut ctx));
        }

        println!("[INFO] Bloom Filter initialized");

        let mut coefficients = [(1, 3, 2), (5, 7, 1), (11, 7, 5), (2, 2, 2), (3, 5, 7), (2, 3, 5), (2, 5, 2), (2, 7, 7), (2, 11, 2), (2, 13, 2)];

        let mut hash_matrices = Vec::new();
        for l in 0..num_tables {
            let mut matrix = Vec::new();
            for i in 0..ctx.full_message_modulus() {
                let mut row = Vec::new();

                // h(x) = a * x + b * y + c 
                for j in 0..ctx.full_message_modulus() {
                    row.push((coefficients[l].0 * i as u64 + coefficients[l].1 * j as u64 + coefficients[l].2  as u64) % ctx.full_message_modulus() as u64);
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

    pub fn insert(&mut self, input: ByteLWE, ctx: &mut Context, private_key: &PrivateKey) {
        println!("[INSERT]");

        let lwe_one = self.public_key.allocate_and_trivially_encrypt_lwe(1, ctx);
     
        for i in 0..self.tables.len() {
            let hash = self.hash(input.clone(), i + 1, ctx);
            let mut current_value = self.public_key.blind_array_access(&hash, &self.tables[i], ctx); //
            let mut current_value_clone = current_value.clone();
            lwe_ciphertext_sub(&mut current_value_clone, &lwe_one, &current_value);
            self.public_key.blind_array_increment(&mut self.tables[i], &hash, &current_value_clone, ctx);
        }
    }

    

    pub fn contains(&self, input: ByteLWE, ctx: &mut Context, private_key: &PrivateKey) -> LWE {

        println!("[LOOKUP]");

        let mut values = Vec::new();

        for i in 0..self.tables.len() {
            let mut hash = self.hash(input.clone(), i + 1, ctx);
            
            let mut value = self.public_key.blind_array_access(&hash, &self.tables[i], ctx);

            values.push(value);
        }

        let mut result = allocate_and_trivially_encrypt_new_lwe_ciphertext(
            ctx.big_lwe_dimension().to_lwe_size(),
            Plaintext(0),
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


fn main() {


    let mut ctx = Context::from(PARAM_MESSAGE_4_CARRY_0);
    let private_key: &'static PrivateKey = key(PARAM_MESSAGE_4_CARRY_0);
    
    use rand::Rng;
    let mut rng = rand::thread_rng();


    let nums_elements = [10, 20, 30, 40, 50, 60, 70, 80, 90, 100];
    let num_trials = 10;
    

    let file = File::options().append(true).open("blind_bloom_filter.txt").unwrap();
    let mut writer = BufWriter::new(file);
    

    for _ in 0..num_trials {

        for num_elements in nums_elements {
            let mut test_elements = Vec::new();
           
            (0..num_elements).for_each(|_| {
            let mut element = rng.gen_range(0..=255) as u8;
            while test_elements.contains(&element) {
                element = rng.gen_range(0..=255) as u8;
            }
            test_elements.push(element);
            });
            let positive_test_elements = test_elements[0..(test_elements.len() / 2)].to_vec();
            let negative_test_elements = test_elements[(test_elements.len() / 2)..].to_vec();
        
            let test_elements_len = test_elements.len();


            for num_tables in 1..=10 {
                let mut total_insert_time = 0;
                let mut total_lookup_time = 0;
                let mut avg_insert_time = 0f64;
                let mut avg_lookup_time = 0f64;
                let mut fp_count = 0;
                let mut fn_count = 0;

                let mut bloom_filter = BloomFilter::new(private_key, num_tables);

                let mut i = 0;
                for element in &positive_test_elements {
                    println!("Inserting element: {:?}", element);
                    let input = ByteLWE::from_byte(*element, &mut ctx, private_key);
                    let start = Instant::now();
                    bloom_filter.insert(input.clone(), &mut ctx, private_key);
                    total_insert_time += start.elapsed().as_millis() as u64;
                }

                for element in &test_elements {
                    let input = ByteLWE::from_byte(*element, &mut ctx, private_key);
                    let start = Instant::now();
                    let contains = bloom_filter.contains(input, &mut ctx, private_key);
                    total_lookup_time += start.elapsed().as_millis() as u64;
                    let dec_contains = private_key.decrypt_lwe(&contains, &ctx);
                    println!("Dec contains: {:?}", dec_contains);

                    if (positive_test_elements.contains(element)) && dec_contains == 0 {
                        println!("False negative: {:?}", element);
                        fn_count += 1;
                    }
                    if (negative_test_elements.contains(element)) && dec_contains == 1 {
                        println!("False positive: {:?}", element);
                        fp_count += 1;
                    }
                }

                avg_insert_time += total_insert_time as f64 / (test_elements_len / 2) as f64;
                avg_lookup_time += total_lookup_time as f64 / test_elements_len as f64;

                let fprate = fp_count as f64 / positive_test_elements.len() as f64;
                let fnrate = fn_count as f64 / negative_test_elements.len() as f64;

                println!("False positive count: {:?}", fp_count);
                println!("False negative count: {:?}", fn_count);
                println!("False positive rate: {:?}", fprate);
                println!("False negative rate: {:?}", fnrate);
                println!("Average insert time: {:?} ms", avg_insert_time);
                println!("Average lookup time: {:?} ms", avg_lookup_time);

                writeln!(writer, "{},{},{},{},{},{},{},{}", num_elements, num_tables, fp_count, fn_count, fprate, fnrate, avg_insert_time, avg_lookup_time);

                writer.flush().unwrap();
            }
    }
}


    

    

}
