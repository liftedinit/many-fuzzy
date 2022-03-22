use crate::fuzz;
use std::ops::RangeInclusive;

pub struct UintGenerator {
    // The range of potential values, inclusive.
    pub min: u64,
    pub max: u64,
}

impl UintGenerator {
    fn gen<R>(&self, rng: &mut R) -> u64
    where
        R: rand::Rng,
    {
        rng.gen_range(RangeInclusive::new(self.min, self.max))
    }
}

impl fuzz::FuzzGenerator for UintGenerator {
    fn fuzz<Rng: rand::Rng>(&mut self, rng: &mut Rng) -> String {
        format!("{}", self.gen(rng))
    }
}
