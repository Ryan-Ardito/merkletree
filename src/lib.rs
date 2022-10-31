//! A Merkle Tree is a hashed datastructure that can construct proofs.
//! Merkle proofs allow proving membership in a tree to a party that only knows the root hash.
//! 
//! This implementation of Merkle Tree has an API for data, but does not store any
//! data beyond the hashes.
//! 
//! Merkletree is a Vector of Vectors where inner Vectors represent layers in the tree.
//! Each layer contains hashes representing nodes in the tree.
//! 
//! A parent node's hash is the concatenation of it's children in *ascending order.*
//! ```text
//! parent hash = hash(lower_child, higher_child)
//! ```

#![warn(missing_docs, rust_2018_idioms, missing_debug_implementations)]

pub mod hashing;
pub use hashing::MerkleHasher;
pub mod mtree;
pub use mtree::MerkleTree;
