//! Canonical prefix mechanics shared by writer and drain, without operation authority.
use serde_json::Value;
pub const LENGTH_BYTES: usize = std::mem::size_of::<u32>();
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refusal {
    Length,
    Canonical,
}
/// Strict canonical JSON shared by frame headers and drain payloads.
/// The frozen signer helper remains the independent parity control.
pub fn canonical(bytes: &[u8], cap: usize) -> Result<Value, Refusal> {
    let value = crate::smb::strict_json::parse(bytes, cap).map_err(|_| Refusal::Canonical)?;
    // Preserve duplicate evidence and reject alternate encoding before normalization.
    if crate::smb::jcs::encode(&value)
        .map_err(|_| Refusal::Canonical)?
        .as_bytes()
        != bytes
    {
        return Err(Refusal::Canonical);
    }
    serde_json::from_slice(bytes).map_err(|_| Refusal::Canonical)
}
/// Must match writer_protocol::decode and the retained prefix in signer_service::decode.
pub fn split(
    packet: &[u8],
    header_max: usize,
    packet_max: usize,
) -> Result<(Value, &[u8]), Refusal> {
    if packet.len() < LENGTH_BYTES || packet.len() > packet_max {
        return Err(Refusal::Length);
    }
    let length = u32::from_be_bytes(
        packet[..LENGTH_BYTES]
            .try_into()
            .map_err(|_| Refusal::Length)?,
    ) as usize;
    let end = LENGTH_BYTES.checked_add(length).ok_or(Refusal::Length)?;
    if length > header_max || end > packet.len() {
        return Err(Refusal::Length);
    }
    let bytes = &packet[LENGTH_BYTES..end];
    Ok((canonical(bytes, header_max)?, &packet[end..]))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn retained_signer_canonical_prefix_parity() {
        for bytes in [
            b"{}".as_slice(),
            b"{\"a\":1}",
            b"{\"a\":1,\"a\":2}",
            b"{ \"a\":1}",
            b"null",
            b"[1]",
        ] {
            let packet = [&(bytes.len() as u32).to_be_bytes()[..], bytes, b"payload"].concat();
            let actual = split(
                &packet,
                super::super::signer_contract::SIGNER_HEADER_MAX_BYTES,
                super::super::signer_contract::SIGNER_FRAME_MAX_BYTES,
            );
            let retained = super::super::signer_service::canonical(
                bytes,
                super::super::signer_contract::SIGNER_HEADER_MAX_BYTES,
            );
            assert_eq!(actual.is_ok(), retained.is_ok());
            if let (Ok((value, payload)), Ok(expected)) = (actual, retained) {
                assert_eq!(value, expected);
                assert_eq!(payload, b"payload");
            }
        }
    }
}
