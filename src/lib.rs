//! A Merkle Tree is a hashed datastructure that can store the hashes of data and construct proofs.
//! Merkle proofs allow proving membership in a tree to a party that only knows the root hash.
//!
//! This implementation of Merkle Tree has an API for data, but does not store any
//! data beyond the hashes.
//!
//! Merkletree is stored as a flat Vector of hashes.
//!
//! A parent node's hash is the concatenation of it's children in *ascending order.*
//! ```text
//! parent hash = hash(lower_child, higher_child)
//! ```
//!
//! # Examples
//!
//! ```
//! use merkletree::MerkleTree;
//!
//! // instantiate an empty tree
//! let empty_tree = MerkleTree::new();
//!
//! // instantiate a tree from a sequence of elements
//! let elements = vec!["foo", "bar"];
//! let mut tree = MerkleTree::from_array(&elements);
//!
//! // insert new elements into the tree
//! tree.insert(&"baz");
//!
//! // generate proofs
//! let proof = tree.gen_proof(&"baz").expect("data not in tree");
//!
//! // verify proofs
//! let root = tree.root().expect("tree is empty");
//! assert!(tree.verify(&proof, &"baz", root,));
//!
//! // use a custom hasher
//! # use merkletree::MerkleHasher;
//! #
//! let tree = MerkleTree::<MyHasher>::with_hasher();
//! #
//! # struct MyHasher;
//! #
//! # impl MerkleHasher for MyHasher {
//! #     type Hash = [u8; 32];
//! #
//! #     fn hash<T: AsRef<[u8]>>(data: &T) -> Self::Hash {
//! #         // do hashing and return result
//! #         [0; 32]
//! #     }
//! # }
//! ```

#![warn(missing_docs, rust_2018_idioms, missing_debug_implementations)]

pub mod hashing;
pub use hashing::MerkleHasher;
pub mod mtree;
pub use mtree::MerkleTree;
