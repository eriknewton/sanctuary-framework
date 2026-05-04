//! LSP-style framing: `Content-Length: <n>\r\n\r\n<n bytes UTF-8 JSON>`.
//!
//! Mirrors `server/src/castle-wall/ipc/framing.ts` exactly so cross-language
//! vector tests in PR 6 can verify byte-for-byte equivalence. Pure framing
//! logic; no transport, no I/O.

use crate::constants::IPC_CONTENT_LENGTH_HEADER;

/// Encode a UTF-8 JSON body into an LSP-framed buffer.
pub fn frame(json_body: &str) -> Vec<u8> {
    let body_bytes = json_body.as_bytes();
    let header = format!(
        "{}: {}\r\n\r\n",
        IPC_CONTENT_LENGTH_HEADER,
        body_bytes.len()
    );
    let mut out = Vec::with_capacity(header.len() + body_bytes.len());
    out.extend_from_slice(header.as_bytes());
    out.extend_from_slice(body_bytes);
    out
}

/// Result of a single parse step.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParseStep {
    /// A full frame was decoded.
    Complete { body: String, consumed_bytes: usize },
    /// More bytes are needed before a frame can be decoded.
    NeedMore,
    /// Hard, non-recoverable framing error. Caller closes the connection.
    Error { reason: String },
}

const HEADER_END: &[u8] = b"\r\n\r\n";

/// Parse one frame from `buf`. Caller is responsible for accumulating bytes
/// across reads and slicing out `consumed_bytes` after a `Complete` result.
pub fn parse_frame(buf: &[u8]) -> ParseStep {
    let header_end = match find_subslice(buf, HEADER_END) {
        Some(idx) => idx,
        None => return ParseStep::NeedMore,
    };

    let header_text = match std::str::from_utf8(&buf[..header_end]) {
        Ok(s) => s,
        Err(_) => {
            return ParseStep::Error {
                reason: "header is not valid UTF-8".to_string(),
            }
        }
    };

    let mut content_length: Option<usize> = None;
    for line in header_text.split("\r\n").filter(|l| !l.is_empty()) {
        let colon = match line.find(':') {
            Some(c) => c,
            None => {
                return ParseStep::Error {
                    reason: format!("malformed header line: {}", line),
                }
            }
        };
        let name = line[..colon].trim();
        let value = line[colon + 1..].trim();
        if name.eq_ignore_ascii_case(IPC_CONTENT_LENGTH_HEADER) {
            content_length = match value.parse::<usize>() {
                Ok(n) => Some(n),
                Err(_) => {
                    return ParseStep::Error {
                        reason: format!("invalid Content-Length value: {}", value),
                    }
                }
            };
        }
    }

    let content_length = match content_length {
        Some(n) => n,
        None => {
            return ParseStep::Error {
                reason: "missing Content-Length header".to_string(),
            }
        }
    };

    let body_start = header_end + HEADER_END.len();
    let total_needed = body_start + content_length;
    if buf.len() < total_needed {
        return ParseStep::NeedMore;
    }

    let body_slice = &buf[body_start..total_needed];
    let body = match std::str::from_utf8(body_slice) {
        Ok(s) => s.to_string(),
        Err(_) => {
            return ParseStep::Error {
                reason: "body is not valid UTF-8".to_string(),
            }
        }
    };

    ParseStep::Complete {
        body,
        consumed_bytes: total_needed,
    }
}

/// Find the first occurrence of `needle` in `haystack`.
fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    haystack.windows(needle.len()).position(|w| w == needle)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frame_round_trips_simple_body() {
        let framed = frame("{\"x\":1}");
        match parse_frame(&framed) {
            ParseStep::Complete { body, consumed_bytes } => {
                assert_eq!(body, "{\"x\":1}");
                assert_eq!(consumed_bytes, framed.len());
            }
            other => panic!("expected complete, got {:?}", other),
        }
    }

    #[test]
    fn parse_signals_need_more_for_partial_header() {
        match parse_frame(b"Content-Length: 5\r\n") {
            ParseStep::NeedMore => {}
            other => panic!("expected NeedMore, got {:?}", other),
        }
    }

    #[test]
    fn parse_signals_need_more_for_partial_body() {
        match parse_frame(b"Content-Length: 10\r\n\r\nshort") {
            ParseStep::NeedMore => {}
            other => panic!("expected NeedMore, got {:?}", other),
        }
    }

    #[test]
    fn parse_rejects_negative_length() {
        match parse_frame(b"Content-Length: -1\r\n\r\n") {
            ParseStep::Error { reason } => {
                assert!(reason.contains("invalid Content-Length"));
            }
            other => panic!("expected Error, got {:?}", other),
        }
    }

    #[test]
    fn parse_rejects_missing_content_length() {
        match parse_frame(b"X-Other: 1\r\n\r\n") {
            ParseStep::Error { reason } => {
                assert!(reason.contains("missing Content-Length"));
            }
            other => panic!("expected Error, got {:?}", other),
        }
    }

    #[test]
    fn header_match_is_case_insensitive() {
        let body = "{\"x\":1}";
        let frame_bytes = format!("content-length: {}\r\n\r\n{}", body.len(), body);
        match parse_frame(frame_bytes.as_bytes()) {
            ParseStep::Complete { body: out, .. } => assert_eq!(out, body),
            other => panic!("expected Complete, got {:?}", other),
        }
    }

    #[test]
    fn extra_bytes_remain_after_complete() {
        let body = "{}";
        let mut buf = frame(body);
        buf.extend_from_slice(b"trailing");
        match parse_frame(&buf) {
            ParseStep::Complete { consumed_bytes, .. } => {
                assert!(consumed_bytes < buf.len());
                let remainder = &buf[consumed_bytes..];
                assert_eq!(remainder, b"trailing");
            }
            other => panic!("expected Complete, got {:?}", other),
        }
    }
}
