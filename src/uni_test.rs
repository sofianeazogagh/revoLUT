
use revolut::*;
use tfhe::{shortint::parameters::*};






pub fn test_blind_retrieve(){
    let mut ctx = Context::from(PARAM_MESSAGE_4_CARRY_0);
    let private_key = PrivateKey::new(&mut ctx);
    let public_key = &private_key.public_key;


    let array = vec![2,4,6,8];
    let mut lut = LUT::from_vec(&array, &private_key, &mut ctx);
    let index = private_key.allocate_and_encrypt_lwe(1, &mut ctx);
    // let (element,new_lut) = public_key.blind_retrieve(lut, index, &ctx);
    let (element,new_lut) = public_key.blind_retrieve(&mut lut, index, &ctx);
    new_lut.print_in_glwe_format(&private_key, &ctx);
    let res = private_key.decrypt_lwe(&element, &ctx);
    println!("Got {}",res );
}




pub fn test_blind_insertion(){
    let mut ctx = Context::from(PARAM_MESSAGE_4_CARRY_0);
    let private_key = PrivateKey::new(&mut ctx);
    let public_key = &private_key.public_key;


    let array = vec![2,4,6];
    let lut = LUT::from_vec(&array, &private_key, &mut ctx);
    let index = private_key.allocate_and_encrypt_lwe(2, &mut ctx);
    let element = private_key.allocate_and_encrypt_lwe(8, &mut ctx);

    let new_lut = public_key.blind_insertion(lut, index, &element, &ctx, &private_key);
    new_lut.print(&private_key, &ctx);

}


pub fn test_blind_push(){
    let mut ctx = Context::from(PARAM_MESSAGE_4_CARRY_0);
    let private_key = PrivateKey::new(&mut ctx);
    let public_key = &private_key.public_key;
    let array = vec![2,1,2,3,4];
    let mut lut_stack = LUTStack::from_vec(&array, &private_key, &mut ctx);
    lut_stack.print(&private_key, &ctx);
    let lwe_push = private_key.allocate_and_encrypt_lwe(6, &mut ctx);
    public_key.blind_push(&mut lut_stack, &lwe_push , &ctx);
    lut_stack.print(&private_key, &ctx);

}



pub fn test_blind_pop(){
    let mut ctx = Context::from(PARAM_MESSAGE_4_CARRY_0);
    let private_key = PrivateKey::new(&mut ctx);
    let public_key = &private_key.public_key;
    let array = vec![2,1,2,3,4];
    let mut lut_stack = LUTStack::from_vec(&array, &private_key, &mut ctx);
    lut_stack.print(&private_key, &ctx);
    let pop = public_key.blind_pop(&mut lut_stack,&ctx);
    lut_stack.print(&private_key, &ctx);
    private_key.decrypt_lwe(&pop, &ctx);
}




pub fn test_blind_matrix_access(){
    let mut ctx = Context::from(PARAM_MESSAGE_4_CARRY_0);
    let private_key = PrivateKey::new(&mut ctx);
    let public_key = &private_key.public_key;
    
    let matrix : Vec<Vec<u64>> = vec![
        vec![0,1,2,3,0,1,2,3],
        vec![4,5,6,7,4,5,6,7],
        vec![8,9,10,11,8,9,10,11],
        vec![12,13,14,15,12,13,14,15],
        vec![0,1,2,3,0,1,2,3],
        vec![4,5,6,7,4,5,6,7],
        vec![8,9,10,11,8,9,10,11],
        vec![12,13,14,15,12,13,14,15]
    ];


    // let matrix : Vec<Vec<u64>> = vec![
    //     vec![0,1,2,3,0,1,2,3],
    //     vec![4,5,6,7,4,5,6,7],
    //     vec![8,9,10,11,8,9,10,11],
    //     vec![12,13,14,15,12,13,14,15],
    // ];

    let matrix_lut = private_key.encrypt_matrix(&mut ctx, &matrix);

    let column = 1;
    let line = 16;

    let index_column = private_key.allocate_and_encrypt_lwe(column, &mut ctx);
    let index_line = private_key.allocate_and_encrypt_lwe(line, &mut ctx);
    let ct_res = public_key.blind_matrix_access(&matrix_lut, &index_line, &index_column, &ctx);

    let res = private_key.decrypt_lwe(&ct_res, &ctx);
    println!("Got {}", res);
}




pub fn test_blind_array_access()
{
    // Create Context and generate key
    let mut ctx = Context::from(PARAM_MESSAGE_4_CARRY_0);
    let private_key =  PrivateKey::new(&mut ctx);
    let public_key = private_key.get_public_key();


    // Our input message
    let input = 9;
    
    let lwe_input = private_key.allocate_and_encrypt_lwe(input, &mut ctx);

    // let ct_16 = private_key.allocate_and_trivially_encrypt_lwe(16, &ctx);
    

    // // testing a solution to manage input > 16
    // let cp = public_key.geq_scalar(&lwe_input, 8, &ctx); // cp =[index > 16]
    // private_key.debug_lwe("cp ", &cp, &ctx);
    // let mut ct_16_or_0 = LweCiphertext::new(0_64, ctx.small_lwe_dimension().to_lwe_size(), ctx.ciphertext_modulus());
    // lwe_ciphertext_cleartext_mul(&mut ct_16_or_0, &cp, Cleartext(16));
    // private_key.debug_lwe("cp*16 ", &ct_16_or_0, &ctx);
    // lwe_ciphertext_sub_assign(&mut lwe_input, &ct_16_or_0);
    // private_key.debug_lwe("index - cp*16 ", &ct_16_or_0, &ctx);


    

    
    
    let array = vec![0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15];

    let lut = LUT::from_vec(&array, &private_key, &mut ctx);
    private_key.debug_lwe("index ", &lwe_input, &ctx);
    let res = public_key.blind_array_access(&lwe_input, &lut, &ctx);


    private_key.debug_lwe("Got ", &res, &ctx);
    println!("With input {} it should be {}",input, array[(input%16) as usize]);

}