//! Big-endian framing; must match server/src/smb/frame.ts and vectors/frame.json.
use super::{constants, jcs, wire};
use serde_json::Value;
use std::io::Read;

/// Encode one schema-checked payload within its edge-specific bound.
pub fn encode(value: &Value, schema: &str, maximum: usize) -> Result<Vec<u8>, String> {
    if !wire::validate(schema, value) {
        return Err("SMB schema".into());
    }
    let body = jcs::encode(value)?;
    // Refuse oversize before allocating a framed copy; the caller closes without replying.
    if body.len() > maximum {
        return Err("SMB frame length".into());
    }
    let length = u32::try_from(body.len()).map_err(|_| "SMB frame length")?;
    let mut result = length.to_be_bytes().to_vec();
    result.extend_from_slice(body.as_bytes());
    Ok(result)
}
/// Read one frame from a stream, refusing a short EOF before any consumer sees the body.
fn read_payload(reader: &mut impl Read, schema: &str, maximum: usize) -> Result<Value, String> {
    // Four bytes are the u32 header; FRAME_HEADER must match constants.json.
    let mut header = [0_u8; std::mem::size_of::<u32>()];
    assert_eq!(header.len(), constants::bound("FRAME_HEADER")?);
    reader
        .read_exact(&mut header)
        .map_err(|_| "SMB short header")?;
    let length = u32::from_be_bytes(header) as usize;
    // Check before allocation and before reading any payload bytes.
    if length > maximum {
        return Err("SMB frame length".into());
    }
    let mut body = vec![0; length];
    reader.read_exact(&mut body).map_err(|_| "SMB short body")?;
    wire::validate_bytes(schema, &body, maximum)
}
/// Decode exactly one complete frame; surplus bytes are not silently discarded.
pub fn decode(bytes: &[u8], schema: &str, maximum: usize) -> Result<Value, String> {
    let mut cursor = std::io::Cursor::new(bytes);
    let value = read_payload(&mut cursor, schema, maximum)?;
    if cursor.position() as usize != bytes.len() {
        return Err("SMB trailing frame".into());
    }
    Ok(value)
}

/// Consume the connection on any framing or schema refusal, sending no reply.
#[cfg(unix)]
pub fn read(
    stream: &mut std::os::unix::net::UnixStream,
    schema: &str,
    maximum: usize,
) -> Result<Value, String> {
    let result = read_payload(stream, schema, maximum);
    // A partial or schema-invalid frame cannot leave a reusable authenticated connection.
    if result.is_err() {
        let _ = stream.shutdown(std::net::Shutdown::Both);
    }
    result
}

#[cfg(unix)]
#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        io::{Read, Write},
        net::Shutdown,
        os::unix::net::UnixStream,
    };
    const IO_DEADLINE_SECONDS: u64 = 1; // Bound each refusal probe to one second.
    #[test]
    fn frame_refusal_closes_without_reply() {
        let maximum = constants::bound("FRAME_MAX_SMALL").unwrap();
        for bytes in [
            vec![0, 0],
            vec![0, 0, 0, 3, b'{', b'}'],
            vec![0, 0, 0, 2, b'{', b'}'],
            ((maximum + 1) as u32).to_be_bytes().to_vec(),
        ] {
            // Socketpair is a framing fixture only; peer credentials use separate-uid connects in peer.rs.
            let (mut client, mut server) = UnixStream::pair().unwrap();
            client.write_all(&bytes).unwrap();
            client.shutdown(Shutdown::Write).unwrap();
            server
                .set_read_timeout(Some(std::time::Duration::from_secs(IO_DEADLINE_SECONDS)))
                .unwrap();
            client
                .set_read_timeout(Some(std::time::Duration::from_secs(IO_DEADLINE_SECONDS)))
                .unwrap();
            assert!(read(&mut server, "activate.prepare.request", maximum).is_err());
            let mut reply = Vec::new();
            client.read_to_end(&mut reply).unwrap();
            assert!(reply.is_empty());
        }
    }
}
