//! Pure presentation helpers for PostgreSQL-backed speaker identity.

/// Convert a zero-based stable speaker-slot ordinal to A..Z, AA..AZ, BA...
pub fn format_slot_ordinal(ordinal: i32) -> String {
    if ordinal < 0 {
        return "A".to_string();
    }
    let mut number = ordinal as u32;
    let mut result = Vec::new();
    loop {
        result.push((b'A' + (number % 26) as u8) as char);
        if number < 26 {
            break;
        }
        number = (number / 26) - 1;
    }
    result.into_iter().rev().collect()
}

#[cfg(test)]
mod tests {
    use super::format_slot_ordinal;

    #[test]
    fn slot_ordinals_are_stable_and_non_compacting() {
        assert_eq!(format_slot_ordinal(-1), "A");
        assert_eq!(format_slot_ordinal(0), "A");
        assert_eq!(format_slot_ordinal(25), "Z");
        assert_eq!(format_slot_ordinal(26), "AA");
        assert_eq!(format_slot_ordinal(51), "AZ");
        assert_eq!(format_slot_ordinal(52), "BA");
    }
}
