/// SHA-256 digest size in bytes.
pub let sha256_digest_size : Int = 32

/// SHA-256 block size in bytes, used by HMAC key padding.
pub let sha256_block_size : Int = 64

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
