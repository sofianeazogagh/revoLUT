// use rayon::prelude::*;
use csv::ReaderBuilder;
use std::fs::File;
use std::fs::OpenOptions;
use std::io::BufReader;
use std::io::Write;

use revolut::*;
use tfhe::core_crypto::prelude::*;
use tfhe::shortint::parameters::*;

use std::time::{Duration, Instant};

const PRINT_HEADERS_IN_CSV: bool = true;
const PRINT_CSV: bool = true;

const PRINT_BENCHMARK: bool = true;

// Fonction générique pour exécuter et mesurer la performance
pub fn benchmark<F>(
    description: &str,
    param_name: &str,
    variant: &str,
    mut f: F,
    file: &mut std::fs::File,
) where
    F: FnMut() -> (),
{
    let mut total_time = Duration::default();
    for _ in 0..100 {
        let start = Instant::now();
        f();
        total_time += start.elapsed();
    }
    let average_time = total_time / 100;

    if PRINT_BENCHMARK {
        println!(
            "{} {:?} {:?} {:?}",
            description, variant, param_name, average_time
        );
    }
    let average_time_ms = average_time.as_secs_f64() * 1000.0;
    // Écriture des résultats sous format CSV
    if PRINT_CSV {
        writeln!(
            file,
            "{},{},{:?},{:?}",
            description, variant, param_name, average_time_ms
        )
        .expect("Error while writing in the file");
    }
}

#[allow(dead_code)]
pub fn test_primitives(primitive_name: Option<&str>, path: &str) {
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .expect("Impossible to open the file");

    if PRINT_HEADERS_IN_CSV {
        writeln!(file, "Primitive,Variants,Parameters,Time (ms)")
            .expect("Error while writing in the file");
    }

    let params = vec![
        ("PARAM_MESSAGE_2_CARRY_0", PARAM_MESSAGE_2_CARRY_0),
        ("PARAM_MESSAGE_3_CARRY_0", PARAM_MESSAGE_3_CARRY_0),
        ("PARAM_MESSAGE_4_CARRY_0", PARAM_MESSAGE_4_CARRY_0),
        ("PARAM_MESSAGE_5_CARRY_0", PARAM_MESSAGE_5_CARRY_0),
        ("PARAM_MESSAGE_6_CARRY_0", PARAM_MESSAGE_6_CARRY_0),
        ("PARAM_MESSAGE_7_CARRY_0", PARAM_MESSAGE_7_CARRY_0),
        // ("PARAM_MESSAGE_8_CARRY_0", PARAM_MESSAGE_8_CARRY_0),
    ];

    for (param_name, param) in &params {
        // Création du contexte et génération des clés
        let mut ctx = Context::from(*param);
        let private_key = PrivateKey::new(&mut ctx);
        let public_key = private_key.get_public_key();

        // Vérifie si le nom de la primitive correspond ou si aucun nom n'est donné
        if primitive_name.is_none() || primitive_name == Some("blind_rotate") {
            // Test pour blind_rotate_assign avec LUT classique
            let input = 1;
            let lwe_input = private_key.allocate_and_encrypt_lwe(input, &mut ctx);
            let array = (0..ctx.full_message_modulus() as u64).collect();
            let mut lut = LUT::from_vec(&array, &private_key, &mut ctx);

            benchmark(
                "blind_rotate",
                param_name,
                "xLWE_xLUT",
                || {
                    blind_rotate_assign(&lwe_input, &mut lut.0, &public_key.fourier_bsk);
                },
                &mut file,
            );

            // Test pour blind_rotate_assign avec LUT trivial
            let lwe_trivial = private_key.allocate_and_trivially_encrypt_lwe(input, &mut ctx);
            benchmark(
                "blind_rotate",
                param_name,
                "tLWE_xLUT",
                || {
                    blind_rotate_assign(&lwe_trivial, &mut lut.0, &public_key.fourier_bsk);
                },
                &mut file,
            );

            // Test pour blind_rotate_assign avec LUT trivial
            let mut lut_trivial = LUT::from_vec_trivially(&vec![1; array.len()], &mut ctx); // LUT trivial

            benchmark(
                "blind_rotate",
                param_name,
                "xLWE_tLUT",
                || {
                    blind_rotate_assign(&lwe_input, &mut lut_trivial.0, &public_key.fourier_bsk);
                },
                &mut file,
            );

            // Test pour blind_rotate_assign avec LUT trivial
            let mut lut_trivial = LUT::from_vec_trivially(&vec![1; array.len()], &mut ctx); // LUT trivial
            let lwe_trivial = private_key.allocate_and_trivially_encrypt_lwe(input, &mut ctx);

            benchmark(
                "blind_rotate",
                param_name,
                "tLWE_tLUT",
                || {
                    blind_rotate_assign(&lwe_trivial, &mut lut_trivial.0, &public_key.fourier_bsk);
                },
                &mut file,
            );
        }

        if primitive_name.is_none() || primitive_name == Some("packing_lwe_to_glwe") {
            // Test pour par_private_functional_keyswitch_lwe_ciphertext_list_and_pack_in_glwe_ciphertext avec LWE classique
            let array = (0..ctx.polynomial_size().0 as u64).collect::<Vec<u64>>();
            let many_lwe: Vec<LweCiphertext<Vec<u64>>> = array
                .iter()
                .map(|&a| private_key.allocate_and_encrypt_lwe(a, &mut ctx))
                .collect();
            let many_lwe_container: Vec<u64> = many_lwe
                .into_iter()
                .map(|ct| ct.into_container())
                .flatten()
                .collect();

            let lwe_list = LweCiphertextList::from_container(
                many_lwe_container,
                ctx.small_lwe_dimension().to_lwe_size(),
                ctx.ciphertext_modulus(),
            );

            benchmark(
                "packing_lwe_to_glwe",
                param_name,
                "xLWE",
                || {
                    let mut packed_glwe = GlweCiphertext::new(
                        0_u64,
                        ctx.glwe_dimension().to_glwe_size(),
                        ctx.polynomial_size(),
                        ctx.ciphertext_modulus(),
                    );
                    par_private_functional_keyswitch_lwe_ciphertext_list_and_pack_in_glwe_ciphertext(
                        &public_key.pfpksk,
                        &mut packed_glwe,
                        &lwe_list,
                    );
                },
                &mut file,
            );

            // Test pour par_private_functional_keyswitch_lwe_ciphertext_list_and_pack_in_glwe_ciphertext avec LWE trivial
            let many_lwe_trivial: Vec<LweCiphertext<Vec<u64>>> = array
                .iter()
                .map(|&a| private_key.allocate_and_trivially_encrypt_lwe(a, &mut ctx))
                .collect();

            let many_lwe_trivial_container: Vec<u64> = many_lwe_trivial
                .into_iter()
                .map(|ct| ct.into_container())
                .flatten()
                .collect();

            let lwe_list_trivial = LweCiphertextList::from_container(
                many_lwe_trivial_container,
                ctx.small_lwe_dimension().to_lwe_size(),
                ctx.ciphertext_modulus(),
            );

            benchmark(
                "packing_lwe_to_glwe",
                param_name,
                "tLWE",
                || {
                    let mut packed_glwe = GlweCiphertext::new(
                        0_u64,
                        ctx.glwe_dimension().to_glwe_size(),
                        ctx.polynomial_size(),
                        ctx.ciphertext_modulus(),
                    );
                    par_private_functional_keyswitch_lwe_ciphertext_list_and_pack_in_glwe_ciphertext(
                        &public_key.pfpksk,
                        &mut packed_glwe,
                        &lwe_list_trivial,
                    );
                },
                &mut file,
            );
        }

        if primitive_name.is_none() || primitive_name == Some("packing_one_lwe_to_glwe") {
            // Test pour par_private_functional_keyswitch_lwe_ciphertext_into_glwe_ciphertext
            let input = 1;
            let lwe_input = private_key.allocate_and_encrypt_lwe(input, &mut ctx);

            benchmark(
                "packing_one_lwe_to_glwe",
                param_name,
                "xLWE",
                || {
                    let mut glwe = GlweCiphertext::new(
                        0_u64,
                        ctx.glwe_dimension().to_glwe_size(),
                        ctx.polynomial_size(),
                        ctx.ciphertext_modulus(),
                    );
                    par_private_functional_keyswitch_lwe_ciphertext_into_glwe_ciphertext(
                        &public_key.pfpksk,
                        &mut glwe,
                        &lwe_input,
                    );
                },
                &mut file,
            );

            // Test pour par_private_functional_keyswitch_lwe_ciphertext_into_glwe_ciphertext

            let lwe_input_trivial = private_key.allocate_and_trivially_encrypt_lwe(input, &mut ctx);
            benchmark(
                "packing_one_lwe_to_glwe",
                param_name,
                "tLWE",
                || {
                    let mut glwe = GlweCiphertext::new(
                        0_u64,
                        ctx.glwe_dimension().to_glwe_size(),
                        ctx.polynomial_size(),
                        ctx.ciphertext_modulus(),
                    );
                    par_private_functional_keyswitch_lwe_ciphertext_into_glwe_ciphertext(
                        &public_key.pfpksk,
                        &mut glwe,
                        &lwe_input_trivial,
                    );
                },
                &mut file,
            );
        }

        if primitive_name.is_none()
            || primitive_name == Some("extract_lwe_sample_from_glwe_ciphertext")
        {
            // Test pour extract_lwe_sample_from_glwe_ciphertext
            let array = (0..ctx.full_message_modulus() as u64).collect::<Vec<u64>>();
            let mut big_lwe = LweCiphertext::new(
                0_u64,
                ctx.big_lwe_dimension().to_lwe_size(),
                ctx.ciphertext_modulus(),
            );
            let lut_glwe = LUT::from_vec(&array, &private_key, &mut ctx).0;

            benchmark(
                "extract_lwe_sample_from_glwe_ciphertext",
                param_name,
                "xGLWE",
                || {
                    extract_lwe_sample_from_glwe_ciphertext(
                        &lut_glwe,
                        &mut big_lwe,
                        MonomialDegree(0),
                    );
                },
                &mut file,
            );
        }

        if primitive_name.is_none() || primitive_name == Some("keyswitch_lwe_ciphertext") {
            // Test pour keyswitch_lwe_ciphertext
            let big_lwe = LweCiphertext::new(
                0_u64,
                ctx.big_lwe_dimension().to_lwe_size(),
                ctx.ciphertext_modulus(),
            );
            let mut lwe_output = LweCiphertext::new(
                0_u64,
                ctx.small_lwe_dimension().to_lwe_size(),
                ctx.ciphertext_modulus(),
            );

            benchmark(
                "keyswitch_lwe_ciphertext",
                param_name,
                "xLWE",
                || {
                    keyswitch_lwe_ciphertext(&public_key.lwe_ksk, &big_lwe, &mut lwe_output);
                },
                &mut file,
            );
        }
    }
}

// Fonction qui lit le fichier CSV et affiche les résultats en fonction des critères
// #[allow(dead_code)]
pub fn show_performance(filename: &str, primitive_name: &str, parameter: &str, variant: &str) {
    let file = File::open(filename).expect("Impossible to open the file");
    let reader = BufReader::new(file);

    let mut csv_reader = ReaderBuilder::new().has_headers(true).from_reader(reader);

    for result in csv_reader.records() {
        let record = result.expect("Error while reading the file");

        // Extraire les données depuis la ligne du CSV
        let primitive = record[0].to_string();
        let variant_type = record[1].to_string();
        let param = record[2].to_string();
        let time_ms: f64 = record[3].parse().expect("Error while parsing the time");

        // Vérifier si la ligne correspond aux critères spécifiés
        if primitive == primitive_name && variant_type == variant && param == parameter {
            println!("{},{},{:?},{:?}ms", primitive, variant_type, param, time_ms);
        }
    }
}
