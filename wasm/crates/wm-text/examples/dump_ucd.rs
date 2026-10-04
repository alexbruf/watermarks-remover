fn main() {
    // dump "cp\tcat\tname" for all scalar values
    let mut s = String::new();
    for cp in 0..=0x10FFFFu32 {
        if let Some(c) = char::from_u32(cp) {
            let g = wm_text::__ucd_probe(c);
            s.push_str(&format!("{:X}\t{}\t{}\n", cp, g.0, g.1));
        }
    }
    print!("{s}");
}
