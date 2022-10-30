//! Hashing for merkletree

use tiny_keccak::{Hasher, Keccak};

/// Allows the use of a custom hashing algorithm
/// 
/// # Examples
/// ```
/// use merkletree::{MerkleTree, MerkleHasher};
/// 
/// struct MyHasher;
/// 
/// impl MerkleHasher for MyHasher {
///     type MerkleHash = [u8; 32];
/// 
///     fn hash<T: AsRef<[u8]>>(data: &T) -> Self::MerkleHash {
///         // do hashing and return
///         return [0; 32]
///     }
/// }
/// 
/// let elements = vec!["foo", "bar"];
/// let tree = MerkleTree::<MyHasher>::new_with_hasher(&elements);
/// ```
pub trait MerkleHasher {
    /// type produced by hasher
    type MerkleHash: PartialEq + Clone + Copy + AsRef<[u8]>;

    /// data -> hash
    fn hash<T: AsRef<[u8]>>(data: &T) -> Self::MerkleHash;
}

/// Default hasher for merkletree
#[derive(Debug, PartialEq, Eq)]
pub struct DefaultMerkleHasher;

impl MerkleHasher for DefaultMerkleHasher {
    type MerkleHash = [u8; 32];

    fn hash<T: AsRef<[u8]>>(data: &T) -> Self::MerkleHash {
        let mut output = [0u8; 32];
        let mut hasher = Keccak::v256();
        hasher.update(data.as_ref());
        hasher.finalize(&mut output);
        output
    }
}
