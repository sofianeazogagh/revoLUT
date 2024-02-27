use std::fs;

use revolut::{context::Context, private_key::PrivateKey};
use tfhe::shortint::parameters::{PARAM_MESSAGE_2_CARRY_0, PARAM_MESSAGE_4_CARRY_0};

pub fn main() {
    println!("generating keys and saving them to disk");
    let mut ctx = Context::from(PARAM_MESSAGE_2_CARRY_0);

    let private_key = PrivateKey::new(&mut ctx); // this takes time
    let _ = fs::write("PrivateKey2", &bincode::serialize(&private_key).unwrap());
    let mut ctx = Context::from(PARAM_MESSAGE_4_CARRY_0);
    let private_key = PrivateKey::new(&mut ctx); // this takes time
    let _ = fs::write("PrivateKey4", &bincode::serialize(&private_key).unwrap());
}
