/// SHA-256 digest size in bytes.
pub let sha256_digest_size : Int = 32

/// SHA-256 block size in bytes, used by HMAC key padding.
pub let sha256_block_size : Int = 64

fn sha256_digest_hex(input : Bytes) -> String {
  let digest = @sha256.Digest::new()
  for byte in input {
    digest.write(byte)
  }
  digest.check_sum()
}

/// Return a byte-wise XOR of two equal-length byte strings.
pub fn xor_bytes(left : Bytes, right : Bytes) -> Bytes {
  guard left.length() == right.length() else {
    abort("xor_bytes requires equal-length inputs")
  }
  Bytes::makei(left.length(), i => left[i] ^ right[i])
}

/// Right-pad a byte string with zero bytes until it reaches `size`.
pub fn zero_pad_to(input : Bytes, size : Int) -> Bytes {
  guard input.length() <= size else { abort("input is longer than target size") }
  input + Bytes::make(size - input.length(), b'\x00')
}

/// Normalize an HMAC key to exactly one SHA-256 block.
///
/// Long-key hashing will be added with the SHA-256 dependency.
pub fn normalize_key_for_sha256(key : Bytes) -> Bytes {
  guard key.length() <= sha256_block_size else {
    abort("long key normalization requires SHA-256")
  }
  zero_pad_to(key, sha256_block_size)
}

/// Compare two tags without early exit.
///
/// Length mismatches still scan the shared prefix before returning `false`.
pub fn constant_time_equal(left : Bytes, right : Bytes) -> Bool {
  let shared = if left.length() < right.length() {
    left.length()
  } else {
    right.length()
  }
  let mut diff = left.length() ^ right.length()
  for i in 0..<shared {
    diff = diff | (left[i].to_int() ^ right[i].to_int())
  }
  diff == 0
}

/// Compute an HMAC-SHA256 tag.
pub fn hmac_sha256(_key : Bytes, _message : Bytes) -> Bytes {
  abort("hmac_sha256 is not implemented yet")
}

/// Verify an HMAC-SHA256 tag.
pub fn verify(key : Bytes, message : Bytes, tag : Bytes) -> Bool {
  constant_time_equal(hmac_sha256(key, message), tag)
}

test "xor_bytes combines equal-length inputs" {
  inspect(
    xor_bytes(b"\x0f\xf0", b"\xf0\x0f"),
    content=(
      #|b"\xff\xff"
    ),
  )
}

test "sha256 dependency produces known digest" {
  inspect(
    sha256_digest_hex(b"abc"),
    content="ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
  )
}

test "zero_pad_to extends with zero bytes" {
  inspect(
    zero_pad_to(b"key", 5),
    content=(
      #|b"key\x00\x00"
    ),
  )
}

test "normalize_key_for_sha256 pads short keys to block size" {
  let normalized = normalize_key_for_sha256(b"key")
  inspect(normalized.length(), content="64")
  inspect(normalized[0], content="b'\\x6B'")
  inspect(normalized[1], content="b'\\x65'")
  inspect(normalized[2], content="b'\\x79'")
  inspect(normalized[3], content="b'\\x00'")
}

test "normalize_key_for_sha256 keeps block-sized keys" {
  let key = Bytes::make(sha256_block_size, b'\x01')
  let normalized = normalize_key_for_sha256(key)
  inspect(normalized.length(), content="64")
  inspect(normalized[0], content="b'\\x01'")
  inspect(normalized[63], content="b'\\x01'")
}

test "constant_time_equal compares tag bytes and lengths" {
  inspect(constant_time_equal(b"abc", b"abc"), content="true")
  inspect(constant_time_equal(b"abc", b"abd"), content="false")
  inspect(constant_time_equal(b"abc", b"abcd"), content="false")
}
