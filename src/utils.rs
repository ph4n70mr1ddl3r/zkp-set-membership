use anyhow::Result;

fn is_valid_hex_string(s: &str) -> bool {
    s.chars().all(|c| c.is_ascii_hexdigit())
}

pub fn validate_and_strip_hex(input: &str, expected_len: usize) -> Result<String> {
    let stripped = input
        .trim()
        .strip_prefix("0x")
        .or_else(|| input.trim().strip_prefix("0X"))
        .unwrap_or_else(|| input.trim());

    if stripped.len() != expected_len {
        return Err(anyhow::anyhow!(
            "Invalid hex string: must be {} characters (got {})",
            expected_len,
            stripped.len()
        ));
    }

    if !is_valid_hex_string(stripped) {
        return Err(anyhow::anyhow!(
            "Invalid hex string: contains non-hex characters"
        ));
    }

    Ok(stripped.to_string())
}

pub fn validate_hex_string(input: &str) -> Result<()> {
    let stripped = input
        .trim()
        .strip_prefix("0x")
        .or_else(|| input.trim().strip_prefix("0X"))
        .unwrap_or_else(|| input.trim());

    if !is_valid_hex_string(stripped) {
        return Err(anyhow::anyhow!(
            "Invalid hex string: contains non-hex characters"
        ));
    }

    Ok(())
}
