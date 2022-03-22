pub mod generators;

pub trait FuzzGenerator {
    fn fuzz<Rng: rand::Rng>(&mut self, rng: &mut Rng) -> String;
}
