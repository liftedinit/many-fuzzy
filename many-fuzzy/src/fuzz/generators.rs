use crate::fuzz;
use num_traits::{Bounded, ToPrimitive};
use std::ops::{Bound, RangeInclusive};

const BSTR_LENGTH_MAX: usize = 1024;

pub enum Generator {
    Uint(u64, u64),
    BstrBounded(usize, usize, (u8, u8)),
}

impl Generator {
    pub fn new_uint_bounded(r: (Bound<u64>, Bound<u64>)) -> Self {
        let min = match r.0 {
            Bound::Unbounded => u64::MIN,
            Bound::Included(x) => x,
            Bound::Excluded(x) => x + 1,
        };
        let max = match r.1 {
            Bound::Unbounded => u64::MAX,
            Bound::Included(x) => x,
            Bound::Excluded(x) => x - 1,
        };
        Self::Uint(min, max)
    }

    pub fn new_uint<Ty: Bounded + ToPrimitive>() -> Self {
        Self::new_uint_bounded((
            Bound::Included(
                Ty::min_value()
                    .to_u64()
                    .expect("Could not convert primitive."),
            ),
            Bound::Included(
                Ty::max_value()
                    .to_u64()
                    .expect("Could not convert primitive."),
            ),
        ))
    }

    pub fn new_bstr(r: (Bound<usize>, Bound<usize>), p: (u8, u8)) -> Self {
        let min = match r.0 {
            Bound::Unbounded => usize::MIN,
            Bound::Included(x) => x,
            Bound::Excluded(x) => x + 1,
        };
        let max = match r.1 {
            Bound::Unbounded => usize::MAX,
            Bound::Included(x) => x,
            Bound::Excluded(x) => x - 1,
        };

        Self::BstrBounded(min, max, p)
    }

    fn gen_uint<Rng: rand::Rng>(rng: &mut Rng, min: u64, max: u64) -> u64 {
        rng.gen_range(RangeInclusive::new(min, max))
    }

    fn gen_bstr<Rng: rand::Rng>(
        rng: &mut Rng,
        min: usize,
        max: usize,
        (min_p, max_p): (u8, u8),
    ) -> String {
        let len = rng.gen_range(RangeInclusive::new(min, usize::min(max, BSTR_LENGTH_MAX)));
        let mut buff = vec![0u8; len as usize];

        if min_p == 0 && max_p == u8::MAX {
            rng.fill(buff.as_mut_slice());
        } else {
            buff.fill_with(|| rng.gen_range(RangeInclusive::new(min_p, max_p)));
        }

        hex::encode_upper(buff.as_slice())
    }
}

impl fuzz::FuzzGenerator for Generator {
    fn fuzz<Rng: rand::Rng>(&mut self, rng: &mut Rng) -> String {
        match self {
            Self::Uint(min, max) => Self::gen_uint(rng, *min, *max).to_string(),
            Self::BstrBounded(min, max, pattern) => {
                format!("h'{}'", Self::gen_bstr(rng, *min, *max, *pattern))
            }
        }
    }
}
