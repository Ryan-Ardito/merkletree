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
///     type Hash = [u8; 32];
/// 
///     fn hash<T: AsRef<[u8]>>(data: &T) -> Self::Hash {
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
    type Hash: PartialEq + Clone + Copy + AsRef<[u8]>;

    /// data -> hash
    fn hash<T: AsRef<[u8]>>(data: &T) -> Self::Hash;
}

/// Default hasher for merkletree
#[derive(Debug, PartialEq)]
pub struct Sha256;

impl MerkleHasher for Sha256 {
    type Hash = [u8; 32];

    fn hash<T: AsRef<[u8]>>(data: &T) -> Self::Hash {
        let mut output = [0u8; 32];
        let mut hasher = Keccak::v256();
        hasher.update(data.as_ref());
        hasher.finalize(&mut output);
        output
    }
}
