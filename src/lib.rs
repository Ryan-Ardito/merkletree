//! Merkle Tree is a hashed datastructure that can construct proofs, which allows
//! proving membership in the tree to a party that only knows the its root hash.
#![warn(missing_docs, rust_2018_idioms, missing_debug_implementations)]

pub mod mtree;
pub use mtree::MerkleTree;