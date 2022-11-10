//! Merkle Tree implementations and API.

#![allow(type_alias_bounds)]

use crate::hashing::{MerkleHasher, Sha256};

/********************************** TODO *************************************

API design decisions:
  - Iterator over leaves that return hashes?
  - Custom hasher passed as arg instead of generic? Hashbuilder?
  - Split Hasher trait into two methods, like write and finish?

Implementation improvements:
  - Root hash and proof should match other implementations for given data?
  - More efficient storage
  - Better runtime speed
  - Threading?

 *****************************************************************************/

/// Concatenate hashes prepended with a prefix. Leaf nodes and internal nodes are
/// prepended with a different prefix. This is done to prevent second pre-image attacks.
/// TODO: Make into a macro?
fn concat_hashes<T: AsRef<[u8]>>(left: T, right: T) -> Vec<u8> {
    let (left, right) = (left.as_ref(), right.as_ref());
    match left < right {
        true => [left, right].concat(),
        false => [right, left].concat(),
    }
}

fn log2_floor(num: f64) -> u32 {
    num.log2().floor() as u32
}

/// Build merkle trees, get proofs, and verify proofs from hashable data.
///
/// # Examples
///
/// ```
/// use merkletree::MerkleTree;
///
/// let data = vec!["foo", "bar"];
/// let tree = MerkleTree::from_array(&data);
/// let root = tree.root().unwrap();
/// let proof = tree.gen_proof(&"foo").unwrap();
/// assert!(tree.verify(&proof, &"foo", root));
/// ```
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct MerkleTree<H: MerkleHasher = Sha256> {
    tree: Vec<H::Hash>,
}

/// MerkleProof is a vector of hashes. No other data is needed,
/// as hashes are always concatenated in ascending order.
type MerkleProof<H: MerkleHasher> = Vec<H::Hash>;

impl Default for MerkleTree {
    fn default() -> Self {
        Self::new()
    }
}

impl MerkleTree {
    /// Construct empty merkle tree.
    pub fn new() -> Self {
        Self { tree: Vec::new() }
    }

    /// Construct a merkletree from an array of elements.
    pub fn from_array<T: AsRef<[u8]>>(elements: &[T]) -> Self {
        let leaves: Vec<<Sha256 as MerkleHasher>::Hash> =
            elements.iter().map(Sha256::hash).collect();
        MerkleTree::from_leaves(leaves)
    }
}

/// Data API
impl<H: MerkleHasher> MerkleTree<H> {
    /// Use a custom hasher.
    pub fn with_hasher() -> Self {
        Self { tree: Vec::new() }
    }

    /// Construct a MerkleTree from a sequence of elements.
    pub fn from_array_with_hasher<T: AsRef<[u8]>>(elements: &[T]) -> Self {
        let leaves: Vec<H::Hash> = elements.iter().map(H::hash).collect();
        MerkleTree::from_leaves(leaves)
    }

    /// Add data elements from a reference to an array.
    /// TODO: rewrite to be faster.
    pub fn add_elems<T: AsRef<[u8]>>(&mut self, elements: &[T]) {
        let new_leaves: Vec<H::Hash> = elements.iter().map(H::hash).collect();
        for hash in new_leaves {
            self.insert_hash(hash)
        }
    }

    /// Return true if data is in the tree
    pub fn contains<T: AsRef<[u8]>>(&self, data: &T) -> bool {
        let hash = H::hash(data);
        self.tree.iter().any(|elem| hash == *elem)
    }

    /// Add data to the tree
    ///
    /// # Examples
    ///
    /// ```
    /// use merkletree::MerkleTree;
    ///
    /// let elements = vec!["foo", "bar"];
    /// let mut tree = MerkleTree::from_array(&elements);
    /// tree.insert(&"baz");
    /// tree.insert(&"quox");
    /// ```
    pub fn insert<T: AsRef<[u8]>>(&mut self, data: &T) {
        let hash = H::hash(data);
        self.insert_hash(hash);
    }

    /// Generate a merkle proof from hashable data.
    /// Return Err if hash of data not in tree
    pub fn gen_proof<T: AsRef<[u8]>>(&self, element: &T) -> Result<Vec<H::Hash>, &str> {
        let hash = H::hash(element);
        self.proof(hash)
    }

    /// Verify that element is a member of the tree
    pub fn verify<T: AsRef<[u8]>>(
        &self,
        proof: &MerkleProof<H>,
        element: &T,
        root: H::Hash,
    ) -> bool {
        let hash = H::hash(element);
        self.verify_proof(proof, hash, root)
    }
}

/// Hash API
impl<H: MerkleHasher> MerkleTree<H> {
    /// return the root hash
    pub fn root(&self) -> Option<H::Hash> {
        self.tree.first().copied()
    }

    /// Depth is the distance of the furthest node from the root
    /// ```text
    ///          0
    ///        /   \
    ///       1     1
    ///      / \   / \
    ///     2   2 2   2
    /// ```
    ///
    /// Returns None if tree is empty
    pub fn depth(&self) -> Option<usize> {
        match self.tree.len() {
            0 => None,
            n => Some(log2_floor(n as f64) as usize),
        }
    }

    fn from_leaves(leaves: Vec<H::Hash>) -> Self {
        let layers = Self::build_layers(leaves);
        MerkleTree { tree: layers }
    }
}

/// business logic
impl<H: MerkleHasher> MerkleTree<H> {
    /// Generate a merkle tree from a vec of leaf hashes
    fn build_layers(leaves: Vec<H::Hash>) -> Vec<H::Hash> {
        if leaves.is_empty() {
            return leaves;
        }
        let mut layers = Vec::new();
        // if leaves.len() is not a power of 2, prepend ex_leaves' parent hashes to first perfect layer
        if leaves.len() & (leaves.len() - 1) != 0 {
            let num_ex_leaves = log2_floor(leaves.len() as f64) as usize * 2;
            let ex_leaves = &leaves[(leaves.len() - num_ex_leaves)..leaves.len()];
            let mut layer = Vec::new();
            for i in ((leaves.len() - num_ex_leaves)..leaves.len()).step_by(2) {
                let left = leaves[i];
                let right = leaves[i + 1];
                let parent = H::hash(&concat_hashes(left, right));
                layer.push(parent);
            }
            layer.extend(&leaves[..(leaves.len() - num_ex_leaves)]);
            layers.push(ex_leaves.into());
            layers.push(layer);
        } else {
            layers.push(leaves);
        }

        // build layers up to root
        while layers.last().unwrap().len() > 1 {
            let mut layer: Vec<H::Hash> = Vec::new();
            // iterate over hashes in pairs to generate parent hash
            for i in (0..layers.last().unwrap().len()).step_by(2) {
                let left = layers.last().unwrap()[i];
                let right = layers.last().unwrap()[i + 1];
                let parent = H::hash(&concat_hashes(left, right));
                layer.push(parent);
            }
            layers.push(layer);
        }
        layers.iter().rev().flatten().copied().collect()
    }

    fn proof(&self, hash: H::Hash) -> Result<MerkleProof<H>, &str> {
        // find index of leaf
        let mut idx = self
            .tree
            .iter()
            .position(|&e| e == hash)
            .ok_or("element not in tree")?;
        let mut proof = Vec::new();
        while idx > 0 {
            // determine if sibling node is left or right
            let hash = match idx % 2 == 0 {
                false => self.tree[idx + 1],
                true => self.tree[idx - 1],
            };
            let node = hash;
            proof.push(node);
            // integer halving gives the parent's index
            idx = (idx - 1) / 2;
        }
        Ok(proof)
    }

    fn verify_proof(&self, proof: &MerkleProof<H>, hash: H::Hash, root: H::Hash) -> bool {
        // verify provided root matches tree root
        let tree_root = self.root();
        if Some(root) != tree_root || !self.tree.contains(&hash) {
            return false;
        }

        // hash proof nodes up to root
        let mut running_hash = hash;
        for hash in proof {
            let (left, right) = match hash.as_ref() < running_hash.as_ref() {
                true => (*hash, running_hash),
                false => (running_hash, *hash),
            };
            running_hash = H::hash(&concat_hashes(left, right));
        }
        Some(running_hash) == tree_root
    }

    fn insert_hash(&mut self, hash: H::Hash) {
        if self.tree.is_empty() {
            self.tree.push(hash);
            return;
        }
        let size = self.tree.len();
        let num_ex_leaves = size - (std::cmp::max(1, 2usize.pow(log2_floor(size as f64))) - 1);
        let first_leaf_idx =
            (2usize.pow(log2_floor((size - num_ex_leaves) as f64)) - 1 + num_ex_leaves) >> 1;
        self.tree.push(self.tree[first_leaf_idx]);
        self.tree.push(hash);
        self.recalculate_branch(self.tree.len() - 1);
    }

    fn recalculate_branch(&mut self, leaf_idx: usize) {
        let mut node_idx = leaf_idx;
        while node_idx > 0 {
            // determine if new leaf is left or right child and find its sibling
            let (left, right) = match node_idx % 2 == 0 {
                false => (self.tree[node_idx], self.tree[node_idx + 1]),
                true => (self.tree[node_idx - 1], self.tree[node_idx]),
            };
            // rehash parent node
            let parent_idx = (node_idx - 1) / 2;
            self.tree[parent_idx] = H::hash(&concat_hashes(left, right));
            node_idx = parent_idx;
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::hashing::SipHasher;

    use super::*;

    #[derive(Clone, Copy)]
    struct DumbHasher;
    impl MerkleHasher for DumbHasher {
        type Hash = [u8; 2];
        fn hash<T: AsRef<[u8]>>(_data: &T) -> Self::Hash {
            [0, 0]
        }
    }

    #[test]
    fn new_tree_root() {
        let mut tree = MerkleTree::new();
        assert_eq!(tree.root(), None);
        let elements = vec!["foo", "bar"];
        tree.add_elems(&elements);
        assert_eq!(
            tree.root(),
            Some(Sha256::hash(&concat_hashes(
                Sha256::hash(&"foo"),
                Sha256::hash(&"bar"),
            )))
        );
    }

    #[test]
    fn test_siphasher() {
        let elements = vec!["foo", "bar"];
        let tree = MerkleTree::<SipHasher>::from_array_with_hasher(&elements);
        assert_eq!(
            tree.root(),
            Some(SipHasher::hash(&concat_hashes(
                SipHasher::hash(&"foo"),
                SipHasher::hash(&"bar"),
            )))
        );
    }

    #[test]
    fn test_depth() {
        let elements = vec!["foo", "bar"];
        let mut tree = MerkleTree::from_array(&elements);
        assert_eq!(tree.depth(), Some(1));
        tree.insert(&"baz");
        assert_eq!(tree.depth(), Some(2));
    }

    #[test]
    fn test_contains() {
        let elements = vec!["foo", "bar"];
        let mut tree = MerkleTree::from_array(&elements);
        assert!(tree.contains(&"foo"));
        assert!(!tree.contains(&"baz"));
        tree.insert(&"baz");
        assert!(tree.contains(&"baz"));
    }

    #[test]
    fn generic_hasher() {
        let elements = vec!["foo", "bar"];
        let tree = MerkleTree::<DumbHasher>::from_array_with_hasher(&elements);
        let proof = tree.gen_proof(&"baz").unwrap();
        let element = "quoz";
        let root = [0, 0];
        assert!(tree.verify(&proof, &element, root));
    }

    #[test]
    fn empty_tree() {
        let empty_vec: Vec<&str> = vec![];
        let mut empty_tree = MerkleTree::from_array(&empty_vec);
        let prefill_tree = MerkleTree::from_array(&vec!["foo", "bar"]);
        empty_tree.insert(&"foo");
        assert_ne!(empty_tree, prefill_tree);
        empty_tree.insert(&"bar");
        assert_eq!(empty_tree, prefill_tree);
    }

    #[test]
    fn insert() {
        let elements = vec!["foo", "bar"];
        let mut tree = MerkleTree::from_array(&elements);
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
        let tree = MerkleTree::from_array(&elements);
        let proof = tree.gen_proof(&"foo").unwrap();
        assert_eq!(proof.len(), 1);
        assert_eq!(proof[0], Sha256::hash(&"bar"));
        assert!(tree.gen_proof(&"baz").is_err());
    }

    #[test]
    fn verify() {
        let elements = vec!["foo", "bar"];
        let tree = MerkleTree::from_array(&elements);
        let root = tree.root().unwrap();
        let proof = tree.gen_proof(&"foo").unwrap();
        assert!(tree.verify(&proof, &"foo", root));
        let proof = tree.gen_proof(&"bar").unwrap();
        assert!(tree.verify(&proof, &"bar", root));
        assert!(!tree.verify(&proof, &"baz", root))
    }
}
