# hmac-mbt

HMAC-SHA256 message authentication code library for MoonBit.

`hmac-mbt` provides a small, testable implementation of the HMAC construction
defined by RFC 2104, using SHA-256 as the underlying hash function.

## Features

- Compute HMAC-SHA256 tags as `Bytes`.
- Compute lowercase hexadecimal HMAC-SHA256 tags.
- Verify tags with a constant-time comparison helper.
- Handle short keys, block-sized keys, and keys longer than the SHA-256 block size.
- Include RFC 4231 test vectors and boundary tests.

## API

```moonbit
pub fn hmac_sha256(key : Bytes, message : Bytes) -> Bytes
pub fn hmac_sha256_hex(key : Bytes, message : Bytes) -> String
pub fn verify(key : Bytes, message : Bytes, tag : Bytes) -> Bool
pub fn constant_time_equal(left : Bytes, right : Bytes) -> Bool
pub fn to_hex(input : Bytes) -> String
```

## Example

```moonbit
test {
  let tag = hmac_sha256_hex(
    b"key",
    b"The quick brown fox jumps over the lazy dog",
  )
  inspect(
    tag,
    content="f7bc83f430538424b13298e6aa6fb143ef4d59a14946175997479dbc2d1a3cd8",
  )
}
```

## Verify Locally

```powershell
moon check
moon test
```

## Project Scope

This project currently focuses on HMAC-SHA256. It does not yet provide a
generic multi-hash HMAC interface or streaming incremental input API.

## Reference

- RFC 2104: HMAC: Keyed-Hashing for Message Authentication
- RFC 4231: Identifiers and Test Vectors for HMAC-SHA-224, HMAC-SHA-256,
  HMAC-SHA-384, and HMAC-SHA-512

## License

Apache-2.0
