use crate::{lut::MNLUT, Context, PublicKey, LUT};
use ndarray::{Array, IxDyn};

/// Pre-packed array of LUT ciphertexts holding p^M values mod p^N
/// last coordinate is index within LUT
pub struct PackedMNLUT {
    /// A (M-1)-way array of N luts
    pub luts: Array<Vec<LUT>, IxDyn>,
}

impl PackedMNLUT {
    fn from_mnlut(mnlut: &MNLUT, ctx: &Context, public_key: &PublicKey) -> Self {
        let m = mnlut.m();
        let n = mnlut.n();
        let p = ctx.full_message_modulus();
        Self {
            luts: Array::from_shape_fn(IxDyn(&vec![p; m - 1]), |indices| -> Vec<LUT> {
                let nlwes = Vec::from_iter((0..p).map(|i| {
                    let mut idx = Vec::from_iter((0..m - 1).map(|i| indices[i]));
                    idx.push(i);
                    &mnlut.nlwes[&IxDyn(&idx)]
                }));

                Vec::from_iter((0..n).map(|i| {
                    let lwes = Vec::from_iter(nlwes.iter().map(|&nlwe| nlwe[i].clone()));
                    LUT::from_vec_of_lwe(&lwes, public_key, ctx)
                }))
            }),
        }
    }
}
