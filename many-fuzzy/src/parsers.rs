use crate::fuzz::generators::Generator;
use std::ops::Bound;

peg::parser! {
  pub grammar fuzz_string() for str {
    rule number() -> u64
        = "0x" n:$(['0'..='9' | 'A'..='F' | 'a'..='f']+) {? u64::from_str_radix(n, 16).or(Err("number")) }
        / "x" n:$(['0'..='9' | 'A'..='F' | 'a'..='f']+) {? u64::from_str_radix(n, 16).or(Err("number")) }
        / n:$(['0'..='9']+) {? n.parse().or(Err("number")) }
    rule number_u8() -> u8
        = "0x" n:$(['0'..='9' | 'A'..='F' | 'a'..='f']+) {? u8::from_str_radix(n, 16).or(Err("number")) }
        / "x" n:$(['0'..='9' | 'A'..='F' | 'a'..='f']+) {? u8::from_str_radix(n, 16).or(Err("number")) }
        / n:$(['0'..='9']+) {? n.parse().or(Err("number")) }
    rule _ = quiet!{[' ' | '\n' | '\t']*}

    rule range_u64() -> (Bound<u64>, Bound<u64>)
        = _ "in" _ n:(number()) ".." m:(number()) { (Bound::Included(n), Bound::Excluded(m)) }
        / _ "in" _ n:(number()) "..=" m:(number()) { (Bound::Included(n), Bound::Included(m)) }
        / _ "in" _ ".." m:(number()) { (Bound::Unbounded, Bound::Excluded(m)) }
        / _ "in" _ "..=" m:(number()) { (Bound::Unbounded, Bound::Included(m)) }
        / _ "in" _ n:(number()) ".." { (Bound::Included(n), Bound::Unbounded) }
        / _ "=" _ n:(number()) { (Bound::Included(n), Bound::Included(n)) }

    rule range_usize() -> (Bound<usize>, Bound<usize>)
        = r:range_u64() {
            use std::ops::Bound::*;
            let min = match r.0 {
                Unbounded => Unbounded,
                Included(x) => Included(x as usize),
                Excluded(x) => Excluded(x as usize),
            };
            let max = match r.1 {
                Unbounded => Unbounded,
                Included(x) => Included(x as usize),
                Excluded(x) => Excluded(x as usize),
            };
            (min, max)
        }

    rule length() -> (Bound<usize>, Bound<usize>)
        = "length" _ r:range_usize() { r }

    rule range_pattern() -> (u8, u8)
        = _ "[" _ n:(number_u8()) ".." m:(number_u8()) "]" { (n, m) }
        / _ "[" _ ".." m:(number_u8()) "]" { (u8::MIN, m) }
        / _ "[" _ n:(number_u8()) ".." "]" { (n, u8::MAX) }
        / _ "=" _ n:(number_u8()) { (n, n) }

    rule pattern() -> (u8, u8)
        = "pattern" _ r:range_pattern() { r }

    pub(crate) rule generator() -> Generator
        = "uint" r:(range_u64())? {
            Generator::new_uint_bounded(r.unwrap_or((Bound::Unbounded, Bound::Unbounded)))
        }
        / "u8" {
            Generator::new_uint::<u8>()
        }
        / "u16" {
            Generator::new_uint::<u16>()
        }
        / "u32" {
            Generator::new_uint::<u32>()
        }
        / "u64" {
            Generator::new_uint::<u64>()
        }
        / "bstr" _ arg_length:(length())? _ arg_pattern:(pattern())? {
            let length = arg_length.unwrap_or((Bound::Unbounded, Bound::Unbounded));
            let pattern = arg_pattern.unwrap_or((0, 0xFF));
            Generator::new_bstr(length, pattern)
        }
    }
}
