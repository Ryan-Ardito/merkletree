//! A Merkle Tree is a hashed datastructure that allows the contruction of proofs.
//! a proof allows proving membership in the tree to a party that only knows the root hash.

#![allow(type_alias_bounds)]

use crate::hashing::{DefaultMerkleHasher, MerkleHasher};
use crate::proof::{MerkleProof, ProofNode, Side};

/******************************************************************************

API design decisions:
  - Should gen_proof return Result or Option?
  - Should the new() constructor create an empty tree,
    or always from a vec of elems?
  - More getter functions?

Implementation improvements:
  - Root hash and proof should match other implementations for given data.
  - Second preimage attack resistance
  - More efficient storage
  - Better runtime speed

******************************************************************************/

/// Build merkle trees, get proofs, and verify proofs from hashabe data
///
/// # Examples
///
/// ```
/// use merkletree::MerkleTree;
///
/// let data = vec!["foo", "bar"];
/// let tree = MerkleTree::new(&data);
/// let root = tree.root().unwrap();
/// let proof = tree.gen_proof(&"foo").unwrap();
/// assert!(tree.verify(&proof, &"foo", root));
/// ```
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct MerkleTree<H: MerkleHasher = DefaultMerkleHasher> {
    layers: Vec<Vec<H::MerkleHash>>,
}

/// Layer in tree
type Layer<H: MerkleHasher> = Vec<H::MerkleHash>;

impl MerkleTree {
    /// Construct a MerkleTree from a sequence of elements
    pub fn new<T: AsRef<[u8]>>(elements: &[T]) -> Self {
        let leaves: Vec<<DefaultMerkleHasher as MerkleHasher>::MerkleHash> =
            elements.iter().map(DefaultMerkleHasher::hash).collect();
        MerkleTree::from_leaves(leaves)
    }
}

impl<H: MerkleHasher> MerkleTree<H> {
    /// Use a custom hasher
    pub fn new_with_hasher<T: AsRef<[u8]>>(elements: &[T]) -> Self {
        let leaves: Vec<H::MerkleHash> = elements.iter().map(H::hash).collect();
        MerkleTree::from_leaves(leaves)
    }

    /// return the root hash
    pub fn root(&self) -> Option<H::MerkleHash> {
        Some(self.layers.last()?[0])
    }

    /// Return true if data is in the tree
    pub fn contains<T: AsRef<[u8]>>(&self, data: &T) -> bool {
        let hash = H::hash(data);
        match self.layers.first() {
            None => false,
            Some(layer) => layer.iter().find(|elem| &hash == *elem).is_some(),
        }
    }

    /// Depth is the distance of the furthest node from the root
    /// ```text
    ///          0
    ///        /   \
    ///       1     1
    ///      / \   / \
    ///     2   2 2   2
    ///    / \
    ///   3   3
    /// ```
    /// 
    /// Returns None if tree is empty
    pub fn depth(&self) -> Option<usize> {
        match self.layers.len() {
            0 => None,
            n => Some(n - 1),
        }
    }

    /// Add data to the tree
    pub fn insert<T: AsRef<[u8]>>(&mut self, data: &T) {
        let hash = H::hash(data);
        self.insert_hash(hash);
    }

    /// Generate a merkle proof from hashable data.
    /// Return Err if hash of data not in tree
    pub fn gen_proof<T: AsRef<[u8]>>(&self, element: &T) -> Result<MerkleProof<H>, &str> {
        let hash = H::hash(element);
        self.proof(hash)
    }

    /// Verify that element is a member of the tree
    pub fn verify<T: AsRef<[u8]>>(
        &self,
        proof: &MerkleProof<H>,
        element: &T,
        root: H::MerkleHash,
    ) -> bool {
        let hash = H::hash(element);
        self.verify_proof(proof, hash, root)
    }

    /// Generate a merkle tree from a vec of leaf hashes
    fn build_layers(mut leaves: Layer<H>) -> Vec<Layer<H>> {
        // ensure leaves.len() is a power of 2 so tree is perfect
        Self::pad_layer(&mut leaves);
        let mut layers = Vec::new();
        layers.push(leaves);

        // build layers up to root
        while layers.last().unwrap().len() > 1 {
            let mut layer: Layer<H> = Vec::new();
            // iterate over hashes in pairs to generate parent hash
            for i in (0..layers.last().unwrap().len()).step_by(2) {
                let left = layers.last().unwrap()[i];
                let right = layers.last().unwrap()[i + 1];
                let parent = H::hash(&[left.as_ref(), right.as_ref()].concat());
                layer.push(parent);
            }
            layers.push(layer);
        }
        layers
    }

    /// Repeat last hash until leaves.len() is a power of 2
    fn pad_layer(layer: &mut Layer<H>) {
        if layer.is_empty() {
            return;
        }
        let mut target_len = 1;
        // find a power of 2 >= length of layer
        while target_len < layer.len() {
            target_len *= 2;
        }
        // repeat last hash to reach target len
        for _ in 0..(target_len - layer.len()) {
            // unwrap can be used here because we checked if layer is empty
            layer.push(*layer.last().unwrap());
        }
        debug_assert!(layer.len() & (layer.len() - 1) == 0);
    }

    fn from_leaves(leaves: Layer<H>) -> Self {
        let layers = Self::build_layers(leaves);
        MerkleTree { layers }
    }

    fn proof(&self, hash: H::MerkleHash) -> Result<MerkleProof<H>, &str> {
        // find index of leaf
        let mut idx = self.layers[0]
            .iter()
            .position(|&e| e == hash)
            .ok_or("element not in tree")?;
        let mut proof = Vec::new();
        for i in 0..(self.layers.len() - 1) {
            // determine if sibling node is left or right
            let (hash, side) = match idx % 2 == 0 {
                true => (self.layers[i][idx + 1], Side::Right),
                false => (self.layers[i][idx - 1], Side::Left),
            };
            let node = ProofNode { hash, side };
            proof.push(node);
            // integer halving gives the parent's index
            idx /= 2;
        }
        Ok(proof)
    }

    fn insert_hash(&mut self, hash: H::MerkleHash) {
        let leaves = &mut self.layers[0];
        // check for first repeated element
        for i in 1..leaves.len() {
            if leaves[i - 1] == leaves[i] {
                leaves[i] = hash;
                self.recalculate_branch(i);
                return;
            }
        }
        // if tree is full, add new element and rebuild tree
        self.layers[0].push(hash);
        *self = MerkleTree::from_leaves(self.layers[0].to_owned());
    }

    fn recalculate_branch(&mut self, leaf_idx: usize) {
        let mut node_idx = leaf_idx;
        for layer_idx in 0..self.layers.len() - 1 {
            let layer = &self.layers[layer_idx];
            // determine if new leaf is left or right child
            let (left, right) = match node_idx % 2 == 0 {
                true => (layer[node_idx], layer[node_idx + 1]),
                false => (layer[node_idx - 1], layer[node_idx]),
            };
            // rehash parent node
            let parent_idx = node_idx / 2;
            self.layers[layer_idx + 1][parent_idx] =
                H::hash(&[left.as_ref(), right.as_ref()].concat());
            node_idx = parent_idx;
        }
    }

    fn verify_proof(
        &self,
        proof: &MerkleProof<H>,
        hash: H::MerkleHash,
        root: H::MerkleHash,
    ) -> bool {
        // verify provided root matches tree root
        let tree_root = self.root();
        if Some(root) != tree_root || !self.layers[0].contains(&hash) {
            return false;
        }

        // hash proof nodes up to root
        let mut running_hash = hash;
        for node in proof {
            let (left, right) = match node.side {
                Side::Left => (node.hash, running_hash),
                Side::Right => (running_hash, node.hash),
            };
            running_hash = H::hash(&[left.as_ref(), right.as_ref()].concat());
        }
        Some(running_hash) == tree_root
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Clone, Copy)]
    struct DumbHasher;
    impl MerkleHasher for DumbHasher {
        type MerkleHash = [u8; 2];
        fn hash<T: AsRef<[u8]>>(_data: &T) -> Self::MerkleHash {
            [0, 0]
        }
    }

    #[test]
    fn new_tree_root() {
        let elements = vec!["foo", "bar"];
        let tree = MerkleTree::new(&elements);
        assert_eq!(
            tree.root(),
            Some(DefaultMerkleHasher::hash(
                &[
                    DefaultMerkleHasher::hash(&"foo"),
                    DefaultMerkleHasher::hash(&"bar")
                ]
                .concat()
            ))
        );
    }

    #[test]
    fn test_depth() {
        let elements = vec!["foo", "bar"];
        let mut tree = MerkleTree::new(&elements);
        assert_eq!(tree.depth(), Some(1));
        tree.insert(&"baz");
        assert_eq!(tree.depth(), Some(2));
    }

    #[test]
    fn test_contains() {
        let elements = vec!["foo", "bar"];
        let mut tree = MerkleTree::new(&elements);
        assert!(tree.contains(&"foo"));
        assert!(!tree.contains(&"baz"));
        tree.insert(&"baz");
        assert!(tree.contains(&"baz"));
    }

    #[test]
    fn generic_hasher() {
        let elements = vec!["foo", "bar"];
        let tree = MerkleTree::<DumbHasher>::new_with_hasher(&elements);
        let proof = tree.gen_proof(&"baz").unwrap();
        let element = "quoz";
        let root = [0, 0];
        assert!(tree.verify(&proof, &element, root));
    }

    #[test]
    fn empty_tree() {
        let empty_vec: Vec<&str> = vec![];
        let mut empty_tree = MerkleTree::new(&empty_vec);
        let prefill_tree = MerkleTree::new(&vec!["foo", "bar"]);
        empty_tree.insert(&"foo");
        assert_ne!(empty_tree, prefill_tree);
        empty_tree.insert(&"bar");
        assert_eq!(empty_tree, prefill_tree);
    }

    #[test]
    fn insert() {
        let elements = vec!["foo", "bar"];
        let mut tree = MerkleTree::new(&elements);
        assert!(tree.gen_proof(&"baz").is_err());
        tree.insert(&"baz");
        let proof = tree.gen_proof(&"baz");
        assert!(proof.is_ok());
        assert!(tree.verify(&proof.unwrap(), &"baz", tree.root().unwrap()));
        tree.insert(&"quox");
        let proof = tree.gen_proof(&"quox");
        assert!(proof.is_ok());
        assert!(tree.verify(&proof.unwrap(), &"quox", tree.root().unwrap()));
    }

    #[test]
    fn proof() {
        let elements = vec!["foo", "bar"];
        let tree = MerkleTree::new(&elements);
        let proof = tree.gen_proof(&"foo").unwrap();
        assert_eq!(proof.len(), 1);
        assert_eq!(proof[0].hash, DefaultMerkleHasher::hash(&"bar"));
        assert!(tree.gen_proof(&"baz").is_err());
    }

    #[test]
    fn verify() {
        let elements = vec!["foo", "bar"];
        let tree = MerkleTree::new(&elements);
        let root = tree.root().unwrap();
        let proof = tree.gen_proof(&"foo").unwrap();
        assert!(tree.verify(&proof, &"foo", root));
        let proof = tree.gen_proof(&"bar").unwrap();
        assert!(tree.verify(&proof, &"bar", root));
        assert!(!tree.verify(&proof, &"baz", root))
    }

    #[test]
    fn tree_should_be_perfect() {
        let elements = vec!["foo", "bar", "baz"];
        let tree = MerkleTree::new(&elements);

        let tree_height = tree.layers.len();
        let leaves = &tree.layers[0];
        // assert that leaves.len() is 2 ^ higher layers
        assert_eq!(leaves.len(), 1 << (tree_height - 1));
        // assert that all layers are half the length of their childrens' layers
        for i in 0..(tree_height - 1) {
            assert_eq!(tree.layers[i].len(), tree.layers[i + 1].len() * 2);
        }
    }
}
