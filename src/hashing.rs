//! Hashing data types and algorithms for merkletree

use std::hash::Hasher as RustHasher;

use tiny_keccak::{Hasher as TinyHasher, Keccak};

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

/*****************************************************************************
 *                                ALGORITHMS                                 *
 *****************************************************************************/

/// Default Keccack256 hasher for merkletree
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

/// Rust DefaultHasher used in HashMap and HashSet
/// 64bit, not cryptographically secure, but much faster than SHA3
#[derive(Debug, PartialEq)]
pub struct SipHasher;

impl MerkleHasher for SipHasher {
    type Hash = [u8; 8];

    fn hash<T: AsRef<[u8]>>(data: &T) -> Self::Hash {
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        hasher.write(data.as_ref());
        hasher.finish().to_le_bytes()
    }
}
