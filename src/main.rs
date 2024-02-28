use std::{fs, time::Instant};

use revolut::{context::Context, private_key::PrivateKey};
use tfhe::shortint::parameters::PARAM_MESSAGE_4_CARRY_0;

pub fn main() {
    let start_time = Instant::now();
    println!("generating context and keys");
    let mut ctx = Context::from(PARAM_MESSAGE_4_CARRY_0);
    let private_key = PrivateKey::new(&mut ctx); // this takes time
    println!("{:?}", Instant::now() - start_time);

    println!("writing keys to disk");
    let _ = fs::write("PrivateKey", &bincode::serialize(&private_key).unwrap());
    println!("{:?}", Instant::now() - start_time);
}
