//! Hashing for merkletree

use tiny_keccak::{Hasher, Keccak};

/// Allows the use of a custom hashing algorithm
pub trait MerkleHasher: Clone {
    /// type produced by hasher
    type MerkleHash: PartialEq + Clone + Copy + AsRef<[u8]>;

    /// data -> hash
    fn hash<T: AsRef<[u8]>>(data: T) -> Self::MerkleHash;
}

/// Default hasher for merkletree
#[derive(Debug, Clone, PartialEq)]
pub struct DefaultMerkleHasher;

impl MerkleHasher for DefaultMerkleHasher {
    type MerkleHash = [u8; 32];

    fn hash<T: AsRef<[u8]>>(data: T) -> Self::MerkleHash {
        let mut output = [0u8; 32];
        let mut hasher = Keccak::v256();
        hasher.update(data.as_ref());
        hasher.finalize(&mut output);
        output
    }
}