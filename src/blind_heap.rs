use std::{
    rc::Rc,
    sync::{Arc, Mutex},
};

use crate::{nlwe::NLWE, Context, PublicKey};

pub struct BlindHeap {
    data: Vec<NLWE>,
    ctx: Arc<Mutex<Context>>,
    public_key: PublicKey,
}

impl BlindHeap {
    pub fn new(ctx: Arc<Mutex<Context>>, public_key: &PublicKey) -> Self {
        BlindHeap {
            data: Vec::new(),
            ctx: ctx.clone(),
            public_key: public_key.clone(),
        }
    }

    /// inserts value into the heap O(log n) blind_compare_and_swap
    pub fn insert(&mut self, value: &NLWE) {
        self.data.push(value.clone());
        let mut index = self.data.len() - 1;
        // heapify up
        while index > 0 {
            let parent = (index - 1) / 2;
            // TODO: compare and swap self.data[parent] and self.data[index]
            index = parent;
        }
    }

    /// extract root element restore the heap property O(log n)
    pub fn pop(&mut self) -> Option<NLWE> {
        if self.data.is_empty() {
            return None;
        }
        // extract root element and replace it by the last
        let res = self.data.swap_remove(0);
        // TODO heapify down
        Some(res)
    }

    pub fn decrease_key(&mut self, index: usize, new_value: &NLWE) {
        if index >= self.data.len() {
            return;
        }
        self.data[index] = new_value.clone();
        let mut index = index;
        // heapify up
        while index > 0 {
            let parent = (index - 1) / 2;
            // TODO: compare and swap self.data[parent] and self.data[index]
            index = parent;
        }
    }
}
