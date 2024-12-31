use sha2::{Digest, Sha256};
use sha3::Keccak256;

/// SHA-256 hash result size = 32 bytes
pub const SHA256_HASH_SIZE: usize = 32;

/// Keccak-256 hash result size = 32 bytes
pub const KECCAK256_HASH_SIZE: usize = 32;

/// Returns [u8; SHA256_HASH_SIZE]
/// 
/// Computes SHA-256 hash of the input
/// 
/// * `data` - bytes to be hashed
pub fn sha_256(data: &[u8]) -> [u8; SHA256_HASH_SIZE] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    let hash = hasher.finalize();

    let mut result = [0u8; 32];
    result.copy_from_slice(hash.as_slice());
    result
}

/// Returns [u8; KECCAK_HASH_SIZE]
/// 
/// Computes Keccak-256 hash of the data
/// 
/// * `data` - bytes to be hashed
pub fn keccak_256(
    data: &[u8],
) -> [u8; KECCAK256_HASH_SIZE] {
    // Init a new Keccak-256 hasher
    let mut hasher = Keccak256::new();

    // Update the hasher digest with the public key after stripping the first byte
    hasher.update(data);

    // Finalize the hasher, to get the hash result
    let hash = hasher.finalize();

    // Return the result as a [u8; KECCAK256_HASH_SIZE]
    let mut result = [0u8; KECCAK256_HASH_SIZE];
    result.copy_from_slice(hash.as_slice());
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sha_256() {
        let r = sha_256(b"test");
        let r_expected: [u8; SHA256_HASH_SIZE] = [
            159, 134, 208, 129, 136, 76, 125, 101, 154, 47, 234, 160, 197, 90, 208, 21, 163, 191,
            79, 27, 43, 11, 130, 44, 209, 93, 108, 21, 176, 240, 10, 8,
        ];
        assert_eq!(r, r_expected);

        let r = sha_256(b"random_string_123");
        let r_expected: [u8; SHA256_HASH_SIZE] = [
            167, 75, 46, 161, 27, 233, 254, 146, 245, 218, 2, 19, 171, 56, 78, 166, 42, 211, 88, 7,
            205, 191, 2, 6, 226, 158, 43, 144, 8, 149, 170, 164,
        ];
        assert_eq!(r, r_expected);
    }

    #[test]
    fn test_keccak_256() {
        let input = "cephalopod";
        let hash = keccak_256(input.as_bytes());

        // https://emn178.github.io/online-tools/keccak_256.html?input=cephalopod&input_type=utf-8&output_type=hex
        assert_eq!(
            hash,
            [
                0xe5, 0xcc, 0x22, 0xf9, 0x4b, 0xfe, 0x86, 0x4d,
                0xa8, 0xf6, 0xeb, 0x41, 0x83, 0x83, 0xe4, 0xb3,
                0x1d, 0xee, 0x12, 0x06, 0x01, 0xfd, 0x33, 0x53,
                0xd2, 0x72, 0xb3, 0x14, 0x04, 0xee, 0x13, 0xd1
            ],
        );
    }
}
