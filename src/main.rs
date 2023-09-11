// #![allow(dead_code)]
// #![allow(unused_variables)]

mod blind_array_access;
use crate::blind_array_access::blind_array_access;

mod blind_array_access2d;
use crate::blind_array_access2d::blind_array_access2d;

mod blind_permutation;
use crate::blind_permutation::blind_permutation;

mod blind_insertion;
use crate::blind_insertion::blind_insertion;

mod blind_push;
use crate::blind_push::blind_push;

mod blind_pop;
use crate::blind_pop::blind_pop;

mod blind_retrieve;
use crate::blind_retrieve::blind_retrieve;

// mod private_insert;
// use crate::private_insert::private_insert;

// mod test_perf_basic_op;
// use crate::test_perf_basic_op::*;







// mod demultiplexer;
// use crate::demultiplexer::demultiplixer;

// mod gist;
// use crate::gist::*;


mod headers;

pub fn main() {

    blind_array_access(); // from blind_array_access

    // blind_array_access2d(); // from unitest_bacc2d

    // blind_permutation(); // from blind_permutation

    // blind_insertion(); // from blind_insertion

    // blind_retrieve(); // from blind_retrieve

    // blind_push(); // from blind_push

    // blind_pop(); // from blind_pop

    // private_insert(); // from private_insert

    // test_perf_comp();

    // test_comp_with_bmacc();

    // test_perf_blind_rotation();

    // test_perf_extract_switch();

    // test_perf_packing();

    // test_perf_glwe_sum();

    // test_perf_lwe_sum();


    // gist::packing_test();


}

