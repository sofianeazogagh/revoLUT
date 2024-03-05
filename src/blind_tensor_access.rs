

use rayon::prelude::*;

use tfhe::shortint::parameters::*;
use tfhe::core_crypto::prelude::*;

// #[path = "./headers.rs"] mod headers;
// use self::headers::PrivateKey;
// use self::headers::PublicKey;
// use self::headers::Context;
// use self::headers::LUT;

use revolut::*;

pub fn test_blind_tensor_access() {

    // Create Context and generate key
    let mut ctx = Context::from(PARAM_MESSAGE_4_CARRY_0);
    let private_key = PrivateKey::new(&mut ctx);
    let public_key = private_key.get_public_key();


    // Our input message


    
    let column = 2;
    let line = 1;

    




    let lwe_column = private_key.allocate_and_encrypt_lwe(column, &mut ctx);
    let lwe_line = private_key.allocate_and_encrypt_lwe(line, &mut ctx);


    let mut tensor : Vec<Vec<Vec<u64>>> = Vec::new();
    let channel_1 : Vec<Vec<u64>> = vec![
        vec![1,2,3], 
        vec![4,5,6],
    ];
    tensor.push(channel_1);
    let channel_2 : Vec<Vec<u64>> = vec![
        vec![1,2,3], 
        vec![4,5,6],
    ];
    tensor.push(channel_2);
    let channel_3 : Vec<Vec<u64>> = vec![
        vec![1,2,3], 
        vec![4,5,6],
    ];
    tensor.push(channel_3);

    // Encoding the tensor
    let nb_of_channels = tensor.len();
    let tensor = encode_tensor_into_matrix(tensor);
    let ct_tensor = private_key.encrypt_matrix(&mut ctx, &tensor);


    let outputs = blind_tensor_access(public_key, &ct_tensor, &lwe_line, &lwe_column, nb_of_channels, &ctx);

    private_key.debug_lwe("Got for the first channel ", &outputs[0], &ctx);
    private_key.debug_lwe("Got for the second channel ", &outputs[1], &ctx);
    private_key.debug_lwe("Got for the third channel ", &outputs[2], &ctx);



    

}

fn blind_tensor_access(public_key: &PublicKey, ct_tensor: &Vec<LUT>, lwe_line: &LweCiphertext<Vec<u64>>, lwe_column: &LweCiphertext<Vec<u64>>,  nb_of_channels: usize, ctx: &Context)
->Vec<LweCiphertext<Vec<u64>>>
{
    let mut pbs_results: Vec<LweCiphertext<Vec<u64>>> = Vec::new();
    pbs_results.par_extend(
        ct_tensor
            .into_par_iter()
            .map(|acc| {
                let mut pbs_ct = LweCiphertext::new(0u64, ctx.big_lwe_dimension().to_lwe_size(),ctx.ciphertext_modulus());
                programmable_bootstrap_lwe_ciphertext(
                    &lwe_column,
                    &mut pbs_ct,
                    &acc.0,
                    &public_key.fourier_bsk,
                );
                let mut switched = LweCiphertext::new(0, ctx.small_lwe_dimension().to_lwe_size(),ctx.ciphertext_modulus());
                par_keyswitch_lwe_ciphertext(&public_key.lwe_ksk, &mut pbs_ct, &mut switched);
                switched
            }),
    );



    let mut lut_column = LUT::from_vec_of_lwe(pbs_results, public_key, &ctx);

    let index_line_encoded = public_key.lwe_ciphertext_plaintext_mul(&lwe_line, nb_of_channels as u64, &ctx);
    // line = line * nb_of_channel
    let index_line_encoded = public_key.lwe_ciphertext_plaintext_add(&index_line_encoded, ctx.full_message_modulus() as u64, &ctx);
    // line = msg_mod + line \in [16,32] for 4_0

    blind_rotate_assign(&index_line_encoded, &mut lut_column.0, &public_key.fourier_bsk);

    let mut outputs_channels: Vec<LweCiphertext<Vec<u64>>> = Vec::new();
    for channel in 0..nb_of_channels{

        let mut ct_res = LweCiphertext::new(0u64, ctx.big_lwe_dimension().to_lwe_size(),ctx.ciphertext_modulus());
        extract_lwe_sample_from_glwe_ciphertext(&lut_column.0, &mut ct_res, MonomialDegree(0  +channel*ctx.box_size() as usize));
        let mut switched = LweCiphertext::new(0, ctx.small_lwe_dimension().to_lwe_size(),ctx.ciphertext_modulus());
        par_keyswitch_lwe_ciphertext(&public_key.lwe_ksk, &mut ct_res, &mut switched);
        outputs_channels.push(switched);

    }

    outputs_channels
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





