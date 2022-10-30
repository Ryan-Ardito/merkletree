//! Data types for merkle proofs

use crate::hashing::MerkleHasher;

/// Chain of siblings up to the root
pub type MerkleProof<H> = Vec<ProofNode<H>>;

/// element hash and side of node
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub struct ProofNode<H: MerkleHasher> {
    /// The nodes hash
    pub hash: H::Hash,
    /// Left of Right child of parent node
    pub side: Side,
}

/// Left or Right child of a parent
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum Side {
    /// Left sibling
    Left,
    /// Right sibling
    Right,
}
