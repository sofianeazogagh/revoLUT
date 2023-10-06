
use std::fs::OpenOptions;
use std::time::Duration;
use std::time::Instant;
use rand::Rng;

use revolut::*;
use tfhe::{shortint::parameters::*, core_crypto::prelude::{lwe_ciphertext_sub_assign, lwe_ciphertext_cleartext_mul, LweCiphertext, Cleartext}};

use std::fs::File;
use std::io::{Write};






pub fn compare_performance_bma_bta() {


    let mut ctx = Context::from(PARAM_MESSAGE_2_CARRY_0);
    let private_key = PrivateKey::new(&mut ctx);
    let public_key = &private_key.public_key;


     // Our input message
     let index_line = private_key.allocate_and_encrypt_lwe(1, &mut ctx);
     let index_column = private_key.allocate_and_encrypt_lwe(2, &mut ctx);
     
 
 
     
     let channel_1 : Vec<Vec<u64>> = vec![
         vec![1,2,3], 
         vec![3,2,1],
     ];
     let channel_2 : Vec<Vec<u64>> = vec![
         vec![1,2,3], 
         vec![3,2,1],
     ];
    //  let channel_3 : Vec<Vec<u64>> = vec![
    //      vec![1,2,3], 
    //      vec![3,2,1],
    //  ];


    let ct_channel_0 = private_key.encrypt_matrix(&mut ctx, &channel_1);
    let ct_channel_1 = private_key.encrypt_matrix(&mut ctx, &channel_2);
    // let ct_channel_2 = private_key.encrypt_matrix(&mut ctx, &channel_3);



    // Mesurer le temps d'exécution de la deuxième fonction
    let mut channels : Vec<Vec<Vec<u64>>> = Vec::new();
     channels.push(channel_1);
     channels.push(channel_2);
    //  channels.push(channel_3);
    let tensor = encode_tensor_into_matrix(channels);
    let ct_tensor = private_key.encrypt_matrix(&mut ctx, &tensor);



    let num_iterations = 100;
    let mut total_time_bma = Duration::new(0, 0);
    let mut total_time_bta = Duration::new(0, 0);

    for _ in 0..num_iterations {
        // Temps d'exécution de la première fonction (BMA)
        let start_time_bma = Instant::now();
        let ct_0 = public_key.blind_matrix_access(&ct_channel_0, &index_line, &index_column, &ctx);
        let ct_1 = public_key.blind_matrix_access(&ct_channel_1, &index_line, &index_column, &ctx);
        // let ct_2 = public_key.blind_matrix_access(&ct_channel_2, &index_line, &index_column, &ctx);
        let elapsed_time_bma = start_time_bma.elapsed();
        total_time_bma += elapsed_time_bma;

        // Temps d'exécution de la deuxième fonction (BTA)
        let start_time_bta = Instant::now();
        let ct = public_key.blind_tensor_access(&ct_tensor, &index_line, &index_column, 2, &ctx);
        let elapsed_time_bta = start_time_bta.elapsed();
        total_time_bta += elapsed_time_bta;

        let m0 = private_key.decrypt_lwe(&ct_0, &ctx);
        let m1 = private_key.decrypt_lwe(&ct_1, &ctx);
        // let m2 = private_key.decrypt_lwe(&ct_2, &ctx);

        let mut t = vec![0;3];
        for i in 0..ct.len(){
            t[i] = private_key.decrypt_lwe(&ct[i], &ctx);
        }


    assert_eq!(t[0],m0);
    assert_eq!(t[1],m1);
    // assert_eq!(t[2],m2);
    }

    // Calculer les temps moyens
    let average_time_bma = total_time_bma / num_iterations;
    let average_time_bta = total_time_bta / num_iterations;



    

    // Afficher les temps d'exécution
    println!("Temps moyen d'exécution de 3 BMA : {:?}", average_time_bma);
    println!("Temps moyen d'exécution de 1 BTA : {:?}", average_time_bta);


}




pub fn compare_performance_bma_bmawp() {



    //Fichier resultat
    let mut output_file_bma = File::create("resultats_perf/resultats_bma.txt").expect("Impossible de créer le fichier");
    let mut output_file_bma = OpenOptions::new()
        .create(true)
        .append(true)
        .open("resultats_perf/resultats_bma.txt")
        .expect("Impossible d'ouvrir le fichier");
    // let mut output_file_bmawp = File::create("resultats_perf/resultats_bmawp.txt").expect("Impossible de créer le fichier");
    let mut output_file_bmawp = OpenOptions::new()
        .create(true)
        .append(true)
        .open("resultats_perf/resultats_bmawp.txt")
        .expect("Impossible d'ouvrir le fichier");
    // En tête
    writeln!(output_file_bma, "execution,matrix_size,params,time").expect("Impossible d'écrire dans le fichier");
    writeln!(output_file_bmawp, "execution,matrix_size,params,time").expect("Impossible d'écrire dans le fichier");



    let params_crypto = vec![PARAM_MESSAGE_2_CARRY_0,PARAM_MESSAGE_3_CARRY_0,PARAM_MESSAGE_4_CARRY_0,PARAM_MESSAGE_5_CARRY_0,PARAM_MESSAGE_6_CARRY_0];



    for params in params_crypto {
        
    

        let mut ctx = Context::from(params);
        let private_key = PrivateKey::new(&mut ctx);
        let public_key = &private_key.public_key;

        // Our input message
        let index_line = private_key.allocate_and_encrypt_lwe(0, &mut ctx);
        let index_column = private_key.allocate_and_encrypt_lwe(0, &mut ctx);


        
        let matrix_size = vec![(2,2),(3,3),(4,4),(5,5),(6,6),(7,7),(8,8)];
        

        for (n,m) in matrix_size{


            if params.message_modulus.0 >= n && params.message_modulus.0 >= m {

            let matrix = generate_matrix(n, m, ctx.full_message_modulus() as u64);

            let ct_matrix = private_key.encrypt_matrix(&mut ctx, &matrix);
            let ct_matrix_with_padding = private_key.encrypt_matrix_with_padding(&mut ctx, &matrix);
    

            let num_iterations = 100;
            for execution in 0..num_iterations {


                // Temps d'exécution de la première fonction (BMA)
                let start_time_bma = Instant::now();
                let ct_0 = public_key.blind_matrix_access(&ct_matrix, &index_line, &index_column, &ctx);
                let elapsed_time_bma = start_time_bma.elapsed();

                // Temps d'exécution de la deuxième fonction (BMA with Padding)
                let start_time_bmawp= Instant::now();
                let ct_1 = public_key.blind_matrix_access(&ct_matrix_with_padding, &index_line, &index_column, &ctx);
                let elapsed_time_bmawp = start_time_bmawp.elapsed();
                

                // Écrire les temps dans le fichier
                writeln!(output_file_bma, "{:?},{:?},{:?},{:?}",execution,n,params.message_modulus.0,elapsed_time_bma.as_millis()).expect("Impossible d'écrire dans le fichier");
                writeln!(output_file_bmawp, "{:?},{:?},{:?},{:?}",execution,n,params.message_modulus.0,elapsed_time_bmawp.as_millis()).expect("Impossible d'écrire dans le fichier");

            }
        }

        }   
    }


    


}





fn encode_tensor_into_matrix(channels : Vec<Vec<Vec<u64>>>)
-> Vec<Vec<u64>>
{


    let nb_of_channels = channels.len();

    let t_rows = channels[0].len()*nb_of_channels;
    let t_col = channels[0][0].len();

    let mut tensor = vec![vec![0; t_col]; t_rows];
    

    for i in 0.. channels[0].len(){
        for j in 0..t_col{
            for k in 0..channels.len(){
                tensor[i*nb_of_channels + k][j] = channels[k][i][j];
            }
        }
    
    }

    tensor
}



fn generate_matrix(n: usize, m: usize, p: u64) -> Vec<Vec<u64>> {
    let mut matrix = Vec::with_capacity(n);
    for _ in 0..n {
        let row = (0..m).map(|_| rand::random::<u64>() % (p + 1)).collect();
        matrix.push(row);
    }
    matrix
}



// Test
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    pub fn test_generate_matrix() {


        println!("test generate_matrix");
        let n = 3;
        let m = 4;
        let p = 5;

        let matrix = generate_matrix(n, m, p);

        // Vérifie que la taille de la matrice est correcte
        assert_eq!(matrix.len(), n);
        assert_eq!(matrix.iter().all(|row| row.len() == m), true);

        // Vérifie que les éléments sont inférieurs ou égaux à p
        assert!(matrix.iter().all(|row| row.iter().all(|&element| element <= p)));
    }
}






pub fn eval_perf() {



    //Fichier resultat
    let mut output_file = OpenOptions::new()
        .create(true)
        .append(true)
        .open("resultats_perf/resultats.txt")
        .expect("Impossible d'ouvrir le fichier");
    // En tête
    writeln!(output_file, "execution,matrix_size,params,time").expect("Impossible d'écrire dans le fichier");



    let params_crypto = vec![PARAM_MESSAGE_2_CARRY_0,PARAM_MESSAGE_3_CARRY_0,PARAM_MESSAGE_4_CARRY_0,PARAM_MESSAGE_5_CARRY_0,PARAM_MESSAGE_6_CARRY_0];
    for params in params_crypto {
        
    

        let mut ctx = Context::from(params);
        let private_key = PrivateKey::new(&mut ctx);
        let public_key = &private_key.public_key;

        // Our input message
        let index_line = private_key.allocate_and_encrypt_lwe(0, &mut ctx);
        let index_column = private_key.allocate_and_encrypt_lwe(0, &mut ctx);


        
        let matrix_size = vec![(2,2),(3,3),(4,4),(5,5),(6,6),(7,7),(8,8)];
        

        for (n,m) in matrix_size{


            if params.message_modulus.0 >= n && params.message_modulus.0 >= m 
            {

                let matrix = generate_matrix(n, m, ctx.full_message_modulus() as u64);

                let ct_matrix = private_key.encrypt_matrix(&mut ctx, &matrix);
                let ct_matrix_with_padding = private_key.encrypt_matrix_with_padding(&mut ctx, &matrix);
        

                let num_iterations = 100;
                for execution in 0..num_iterations {


                    // Temps d'exécution de ce qu'on veut évaluer
                    let start_time_bmawp= Instant::now();
                    let ct_1 = public_key.blind_matrix_access(&ct_matrix_with_padding, &index_line, &index_column, &ctx);
                    let elapsed_time_bmawp = start_time_bmawp.elapsed();
                    

                    // Écrire les temps dans le fichier
                    writeln!(output_file_bma, "{:?},{:?},{:?},{:?}",execution,n,params.message_modulus.0,elapsed_time_bma.as_millis()).expect("Impossible d'écrire dans le fichier");
                    writeln!(output_file_bmawp, "{:?},{:?},{:?},{:?}",execution,n,params.message_modulus.0,elapsed_time_bmawp.as_millis()).expect("Impossible d'écrire dans le fichier");

                }
        }

        }   
    }


    


}