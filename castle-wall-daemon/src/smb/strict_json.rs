//! Bounded duplicate-aware parser; must match parse-strict.ts and vectors/strict-json.json.
use serde_json::{Map, Number, Value};

/// Decode embedded schema data before the bounds used by the wire parser exist.
pub(super) fn embedded(source: &'static str) -> Result<Value, serde_json::Error> {
    // Static-only input prevents runtime wire bytes from bypassing duplicate and size checks.
    serde_json::from_str(source)
}

#[cfg(test)]
pub(super) fn fixture<T: serde::de::DeserializeOwned>(bytes: &[u8]) -> T {
    // Test transport includes deliberately invalid wire values, so it cannot use wire validation.
    serde_json::from_slice(bytes).expect("SMB fixture JSON")
}

/// Parse exactly one UTF-8 JSON value without losing duplicate-key evidence.
pub fn parse(bytes: &[u8], maximum: usize) -> Result<Value, String> {
    // Reject before UTF-8 decoding or allocating a value tree to bound untrusted work.
    if bytes.len() > maximum {
        return Err("SMB JSON size".into());
    }
    let text = std::str::from_utf8(bytes).map_err(|_| "SMB UTF-8")?;
    let mut parser = Parser { text, position: 0 };
    let value = parser.value(0)?;
    parser.space();
    if parser.position != text.len() {
        return Err("SMB trailing bytes".into());
    }
    Ok(value)
}
struct Parser<'a> {
    text: &'a str,
    position: usize,
}
impl Parser<'_> {
    fn peek(&self) -> Option<u8> {
        self.text.as_bytes().get(self.position).copied()
    }
    fn space(&mut self) {
        while matches!(self.peek(), Some(b' ' | b'\n' | b'\r' | b'\t')) {
            self.position += 1;
        }
    }
    fn consume(&mut self, expected: u8) -> Result<(), String> {
        if self.peek() != Some(expected) {
            return Err("SMB JSON syntax".into());
        }
        self.position += 1;
        Ok(())
    }
    fn string(&mut self) -> Result<String, String> {
        let start = self.position;
        self.consume(b'"')?;
        let mut escaped = false;
        while let Some(byte) = self.peek() {
            self.position += 1;
            if byte == b'"' && !escaped {
                // serde's string-only decoder rejects lone UTF-16 surrogates; it never sees an object or number.
                return serde_json::from_str(&self.text[start..self.position])
                    .map_err(|_| "SMB string".into());
            }
            escaped = byte == b'\\' && !escaped;
        }
        Err("SMB incomplete string".into())
    }
    fn number(&mut self) -> Result<Value, String> {
        let start = self.position;
        if self.peek() == Some(b'-') {
            self.position += 1;
        }
        if self.peek() == Some(b'0') {
            self.position += 1;
        } else {
            self.digits(true)?;
        }
        if self.peek() == Some(b'.') {
            self.position += 1;
            self.digits(false)?;
        }
        if matches!(self.peek(), Some(b'e' | b'E')) {
            self.position += 1;
            if matches!(self.peek(), Some(b'+' | b'-')) {
                self.position += 1;
            }
            self.digits(false)?;
        }
        // str::parse<f64> rounds the entire literal to binary64, matching ECMAScript Number.
        let number: f64 = self.text[start..self.position]
            .parse()
            .map_err(|_| "SMB number syntax")?;
        let max_safe = ((1_u64 << f64::MANTISSA_DIGITS) - 1) as f64;
        // A4's magnitude rule binds both parsers; a rounded out-of-domain value is never clamped.
        if !number.is_finite() || number.abs() > max_safe {
            return Err("SMB numeric domain".into());
        }
        Ok(Value::Number(
            Number::from_f64(number).ok_or("SMB numeric domain")?,
        ))
    }
    fn digits(&mut self, nonzero: bool) -> Result<(), String> {
        let first = self.peek().ok_or("SMB number syntax")?;
        if !first.is_ascii_digit() || (nonzero && first == b'0') {
            return Err("SMB number syntax".into());
        }
        while self.peek().is_some_and(|c| c.is_ascii_digit()) {
            self.position += 1;
        }
        Ok(())
    }
    fn value(&mut self, depth: usize) -> Result<Value, String> {
        self.space();
        match self.peek() {
            Some(b'{') | Some(b'[') => {
                // The depth budget must match parse-strict.ts, including primitive leaves.
                if depth > super::constants::bound("JSON_MAX_DEPTH") {
                    return Err("SMB JSON depth".into());
                }
                if self.peek() == Some(b'{') {
                    self.position += 1;
                    self.space();
                    let mut fields = Map::new();
                    if self.peek() == Some(b'}') {
                        self.position += 1;
                        return Ok(Value::Object(fields));
                    }
                    loop {
                        self.space();
                        let name = self.string()?;
                        self.space();
                        self.consume(b':')?;
                        // Decoded names, including escaped aliases, must remain unique before insertion.
                        if fields.contains_key(&name) {
                            return Err("SMB duplicate key".into());
                        }
                        fields.insert(name, self.value(depth + 1)?);
                        self.space();
                        if self.peek() == Some(b'}') {
                            self.position += 1;
                            break;
                        }
                        self.consume(b',')?;
                    }
                    Ok(Value::Object(fields))
                } else {
                    self.position += 1;
                    self.space();
                    let mut items = Vec::new();
                    if self.peek() == Some(b']') {
                        self.position += 1;
                        return Ok(Value::Array(items));
                    }
                    loop {
                        items.push(self.value(depth + 1)?);
                        self.space();
                        if self.peek() == Some(b']') {
                            self.position += 1;
                            break;
                        }
                        self.consume(b',')?;
                    }
                    Ok(Value::Array(items))
                }
            }
            Some(b'"') => Ok(Value::String(self.string()?)),
            Some(b'-' | b'0'..=b'9') => self.number(),
            Some(b't') => self.literal("true", Value::Bool(true)),
            Some(b'f') => self.literal("false", Value::Bool(false)),
            Some(b'n') => self.literal("null", Value::Null),
            _ => Err("SMB JSON syntax".into()),
        }
    }
    fn literal(&mut self, literal: &str, value: Value) -> Result<Value, String> {
        if !self.text[self.position..].starts_with(literal) {
            return Err("SMB JSON literal".into());
        }
        self.position += literal.len();
        Ok(value)
    }
}
