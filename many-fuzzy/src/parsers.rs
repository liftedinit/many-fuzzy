use crate::fuzz::generators::UintGenerator;
use crate::fuzz::FuzzGenerator;
use std::ops::Bound;

peg::parser! {
  pub grammar fuzz_string() for str {
    rule number() -> u64
        = n:$(['0'..='9']+) {? n.parse().or(Err("u32")) }
    rule _ = quiet!{[' ' | '\n' | '\t']+}

    rule range_u64() -> (Bound<u64>, Bound<u64>)
        = _ "in" _ n:(number()) ".." m:(number()) { (Bound::Included(n), Bound::Excluded(m)) }
        / _ "in" _ n:(number()) "..=" m:(number()) { (Bound::Included(n), Bound::Included(m)) }
        / _ "in" _ ".." m:(number()) { (Bound::Unbounded, Bound::Excluded(m)) }
        / _ "in" _ "..=" m:(number()) { (Bound::Unbounded, Bound::Included(m)) }
        / _ "in" _ n:(number()) ".." { (Bound::Included(n), Bound::Unbounded) }

    pub(crate) rule generator() -> Box<impl FuzzGenerator>
        = "uint" r:(range_u64())? {
            let r = r.unwrap_or((Bound::Unbounded, Bound::Unbounded));
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

            Box::new(UintGenerator { min, max })
        }
        / "u8" {
            Box::new(UintGenerator { min: 0, max: u8::MAX as u64 })
        }
        / "u16" {
            Box::new(UintGenerator { min: 0, max: u16::MAX as u64 })
        }
        / "u32" {
            Box::new(UintGenerator { min: 0, max: u32::MAX as u64 })
        }
        / "u64" {
            Box::new(UintGenerator { min: 0, max: u64::MAX })
        }
    }
}
