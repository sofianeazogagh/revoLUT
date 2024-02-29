// #![allow(dead_code)]
// #![allow(unused_variables)]

// mod blind_array_access;
// use crate::blind_array_access::blind_array_access;

// mod blind_array_access2d;
// use crate::blind_array_access2d::blind_array_access2d;

// mod blind_permutation;
// use crate::blind_permutation::blind_permutation;

// mod blind_insertion;
// use crate::blind_insertion::blind_insertion;

// mod blind_push;
// use crate::blind_push::blind_push;

// mod blind_pop;
// use crate::blind_pop::blind_pop;

// mod blind_retrieve;
// use crate::blind_retrieve::blind_retrieve;

// mod private_insert;
// use crate::private_insert::private_insert;

// mod test_perf_basic_op;
// use crate::test_perf_basic_op::*;

// mod blind_tensor_access;
// use blind_tensor_access::*;


mod uni_test;
use crate::uni_test::*;

// mod perf_test;
// use crate::perf_test::*;


// mod multi_cmp;
// use crate::multi_cmp::*;

// mod blind_sort;
// use crate::blind_sort::*;




// mod gist;
// use crate::gist::*;

pub fn main() {

    // test_blind_tensor_access();
    // gist::packing_test();


    // test_multi_cmp();


    /* From uni_test */ 
    // test_blind_push();
    // test_blind_pop();
    // test_blind_matrix_access();
    // test_blind_insertion();
    // test_blind_retrieve();
    // test_blind_array_access();
    test_blind_permutation();

    /* From perf_test */ 
    // compare_performance_bma_bmawp();


    // blind_permutation();



}

