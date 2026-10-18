//! RFC 8785 serializer; must match server/src/smb/jcs.ts and vectors/jcs.json.
use serde_json::Value;

/// ECMAScript Number::toString decimal path (ECMA-262 7.1.12.1, including Note 2).
pub fn number(value: f64) -> Result<String, String> {
    if !value.is_finite() {
        return Err("SMB non-finite number".into());
    }
    if value == 0.0 {
        return Ok("0".into());
    }
    let magnitude = value.abs();
    // A binary64 round-trips in at most 17 significant decimal digits. Trying
    // increasing lengths selects the shortest n; Rust precision formatting
    // selects the nearest decimal, breaking exact ties toward an even n (Note 2).
    let mut shortest = None;
    'length: for precision in 1..=17 {
        let candidate = format!("{:.*e}", precision - 1, magnitude);
        let (mantissa, exponent) = candidate.split_once('e').ok_or("SMB number")?;
        let exponent: i32 = exponent.parse().map_err(|_| "SMB exponent")?;
        let coefficient: u64 = mantissa
            .replace('.', "")
            .parse()
            .map_err(|_| "SMB coefficient")?;
        let scale = exponent - (precision as i32 - 1);
        // At powers of two the rounding interval is asymmetric. The nearest
        // decimal can miss it while its adjacent coefficient round-trips;
        // ECMA's shortest-length rule takes that neighbor before adding digits.
        for coefficient in [coefficient, coefficient + 1, coefficient - 1] {
            if coefficient == 0 {
                continue;
            }
            let candidate = format!("{coefficient}e{scale}");
            if candidate.parse::<f64>().map_err(|_| "SMB number")? == magnitude {
                let digits = coefficient.to_string();
                let n = digits.len() as i32 + scale;
                shortest = Some((digits, n));
                break 'length;
            }
        }
    }
    let (mut digits, n) = shortest.ok_or("SMB number")?;
    while digits.len() > 1 && digits.ends_with('0') {
        digits.pop();
    }
    let k = digits.len() as i32;
    let exponent = n - 1;
    // ECMAScript's decimal/exponent thresholds are n=21 and n=-6, not Rust Display's.
    let out = if k <= n && n <= 21 {
        format!("{}{}", digits, "0".repeat((n - k) as usize))
    } else if 0 < n && n <= 21 {
        format!("{}.{}", &digits[..n as usize], &digits[n as usize..])
    } else if -6 < n && n <= 0 {
        format!("0.{}{}", "0".repeat((-n) as usize), digits)
    } else {
        let mantissa = if k == 1 {
            digits
        } else {
            format!("{}.{}", &digits[..1], &digits[1..])
        };
        format!(
            "{}e{}{exponent}",
            mantissa,
            if exponent >= 0 { "+" } else { "" }
        )
    };
    Ok(format!("{}{out}", if value < 0.0 { "-" } else { "" }))
}
/// Serialize a parsed JSON value, ordering keys by UTF-16 code units.
pub fn encode(value: &Value) -> Result<String, String> {
    encode_at(value, 0)
}
fn encode_at(value: &Value, depth: usize) -> Result<String, String> {
    // Only containers spend nesting budget; scalar leaves may follow the deepest container.
    // Must match jcs.ts and strict_json.rs: root container depth is zero.
    if (value.is_array() || value.is_object()) && depth > super::constants::bound("JSON_MAX_DEPTH")?
    {
        return Err("SMB JSON depth".into());
    }
    Ok(match value {
        Value::Null => "null".into(),
        Value::Bool(v) => v.to_string(),
        Value::Number(v) => {
            let n = v.as_f64().ok_or("SMB number")?;
            let max_safe = ((1_u64 << f64::MANTISSA_DIGITS) - 1) as f64;
            // Must match jcs.ts: signing accepts only the parser's safe numeric domain.
            if n.abs() > max_safe {
                return Err("SMB numeric domain".into());
            }
            number(n)?
        }
        Value::String(v) => serde_json::to_string(v).map_err(|_| "SMB string")?,
        Value::Array(values) => format!(
            "[{}]",
            values
                .iter()
                .map(|v| encode_at(v, depth + 1))
                .collect::<Result<Vec<_>, _>>()?
                .join(",")
        ),
        Value::Object(values) => {
            let mut keys: Vec<_> = values.keys().collect();
            // Unicode scalar order differs for non-BMP keys; signatures require UTF-16 order.
            keys.sort_by(|a, b| a.encode_utf16().cmp(b.encode_utf16()));
            let entries = keys
                .into_iter()
                .map(|key| {
                    Ok(format!(
                        "{}:{}",
                        serde_json::to_string(key).map_err(|_| "SMB string")?,
                        encode_at(&values[key], depth + 1)?
                    ))
                })
                .collect::<Result<Vec<_>, String>>()?;
            format!("{{{}}}", entries.join(","))
        }
    })
}
