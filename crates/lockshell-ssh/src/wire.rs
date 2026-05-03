// SPDX-License-Identifier: Apache-2.0

//! SSH wire-format primitives per RFC 4251 §5.
//!
//! All multi-byte integers are network byte order (big endian). Strings are
//! length-prefixed by a `uint32`. `mpint` is a signed multi-precision integer
//! encoded as a string with a leading `0x00` byte when the high bit of the
//! magnitude would otherwise be set (so the value is unambiguously positive).

use anyhow::{anyhow, bail, Result};

/// Append a `uint32` to `out` in big-endian order.
pub fn encode_uint32(out: &mut Vec<u8>, v: u32) {
    out.extend_from_slice(&v.to_be_bytes());
}

/// Append a length-prefixed `string` to `out`.
pub fn encode_string(out: &mut Vec<u8>, data: &[u8]) {
    encode_uint32(out, data.len() as u32);
    out.extend_from_slice(data);
}

/// Append `n` as an `mpint`. `n` is the big-endian magnitude of a non-negative
/// integer. Leading zero bytes are stripped, then a single `0x00` byte is
/// prepended if the next byte's high bit is set (RFC 4251 §5).
///
/// Negative numbers are not supported by lockshell and panic in debug builds;
/// in release they encode as if positive. Callers must validate sign upstream.
pub fn encode_mpint(out: &mut Vec<u8>, n: &[u8]) {
    let mut start = 0;
    while start < n.len() && n[start] == 0 {
        start += 1;
    }
    let trimmed = &n[start..];

    if trimmed.is_empty() {
        encode_uint32(out, 0);
        return;
    }

    let needs_pad = trimmed[0] & 0x80 != 0;
    let len = trimmed.len() + usize::from(needs_pad);
    encode_uint32(out, len as u32);
    if needs_pad {
        out.push(0x00);
    }
    out.extend_from_slice(trimmed);
}

/// Append a list of length-prefixed strings, then wrap the whole list as a
/// single length-prefixed string. This matches the OpenSSH cert encoding for
/// `valid principals` — an outer string field whose body is a sequence of
/// length-prefixed string entries.
pub fn encode_string_list(out: &mut Vec<u8>, items: &[&[u8]]) {
    let mut body = Vec::new();
    for item in items {
        encode_string(&mut body, item);
    }
    encode_string(out, &body);
}

/// Decode a length-prefixed string from the head of `buf`.
///
/// Returns `(value, rest)` where `rest` is the remainder of `buf` after the
/// length prefix and the string body. Errors if the buffer is short or the
/// declared length exceeds what's available.
pub fn decode_string(buf: &[u8]) -> Result<(&[u8], &[u8])> {
    if buf.len() < 4 {
        bail!("ssh wire: buffer too short for length prefix");
    }
    let len = u32::from_be_bytes(
        buf[..4]
            .try_into()
            .map_err(|_| anyhow!("ssh wire: length slice"))?,
    ) as usize;
    let rest = &buf[4..];
    if rest.len() < len {
        bail!(
            "ssh wire: declared length {len} exceeds available {avail}",
            avail = rest.len()
        );
    }
    Ok((&rest[..len], &rest[len..]))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_string_empty() {
        let mut out = Vec::new();
        encode_string(&mut out, b"");
        assert_eq!(out, vec![0, 0, 0, 0]);
    }

    #[test]
    fn encode_string_ascii() {
        let mut out = Vec::new();
        encode_string(&mut out, b"hi");
        assert_eq!(out, vec![0, 0, 0, 2, b'h', b'i']);
    }

    #[test]
    fn encode_string_binary_high_byte() {
        let mut out = Vec::new();
        encode_string(&mut out, &[0xff, 0x00, 0x80]);
        assert_eq!(out, vec![0, 0, 0, 3, 0xff, 0x00, 0x80]);
    }

    #[test]
    fn decode_string_roundtrip() {
        let payload: &[u8] = &[0xde, 0xad, 0xbe, 0xef];
        let mut buf = Vec::new();
        encode_string(&mut buf, payload);
        // append trailing bytes to confirm `rest` boundary
        buf.extend_from_slice(b"tail");
        let (val, rest) = decode_string(&buf).unwrap();
        assert_eq!(val, payload);
        assert_eq!(rest, b"tail");
    }

    #[test]
    fn decode_string_short_buffer() {
        assert!(decode_string(&[0, 0]).is_err());
        // length declares 5 but only 2 bytes follow
        assert!(decode_string(&[0, 0, 0, 5, 0xaa, 0xbb]).is_err());
    }

    #[test]
    fn encode_mpint_zero() {
        let mut out = Vec::new();
        encode_mpint(&mut out, &[]);
        assert_eq!(out, vec![0, 0, 0, 0]);

        let mut out = Vec::new();
        encode_mpint(&mut out, &[0x00, 0x00]);
        assert_eq!(out, vec![0, 0, 0, 0]);
    }

    #[test]
    fn encode_mpint_positive_high_bit_pads() {
        // 0x80 has the high bit set; encoder must prepend a 0x00 so the value
        // is interpreted as positive.
        let mut out = Vec::new();
        encode_mpint(&mut out, &[0x80]);
        assert_eq!(out, vec![0, 0, 0, 2, 0x00, 0x80]);
    }

    #[test]
    fn encode_mpint_strips_leading_zeros() {
        let mut out = Vec::new();
        encode_mpint(&mut out, &[0x00, 0x00, 0x01, 0x02]);
        assert_eq!(out, vec![0, 0, 0, 2, 0x01, 0x02]);
    }

    #[test]
    fn encode_mpint_no_pad_when_high_bit_clear() {
        let mut out = Vec::new();
        encode_mpint(&mut out, &[0x7f, 0xff]);
        assert_eq!(out, vec![0, 0, 0, 2, 0x7f, 0xff]);
    }
}
