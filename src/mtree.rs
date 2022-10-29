//! A Merkle Tree hashed datastructure that allows the contruction of proofs,
//! which allow proving membership in the tree to a party that only knows the root hash
use tiny_keccak::{Hasher, Keccak};

/// Build merkle trees, get proofs, and verify proofs from hashabe data
/// ```
/// use merkletree::MerkleTree;
/// 
/// let data = vec!["foo", "bar"];
/// let tree = MerkleTree::new(&data);
/// let root = tree.root().unwrap();
/// let proof = tree.gen_proof("foo").unwrap();
/// assert!(tree.verify(&proof, "foo", root));
/// ```
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct MerkleTree {
    layers: Vec<Vec<MerkleHash>>,
}

/// Internal hash is an array of bytes
pub type MerkleHash = [u8; 32];
/// Chain of siblings up to the root
pub type MerkleProof = Vec<ProofNode>;

/// Left or Right child of a parent
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum Side {
    /// Left sibling
    Left,
    /// Right sibling
    Right,
}

/// element hash and side of node
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub struct ProofNode {
    hash: MerkleHash,
    side: Side,
}

impl MerkleTree {
    /// Construct a MerkleTree from a sequence of elements
    pub fn new<T: AsRef<[u8]>>(elements: &Vec<T>) -> Self {
        let leaves: Vec<MerkleHash> = elements
            .iter()
            .map(|elem| Self::hash(elem))
            .collect();
        MerkleTree::from_leaves(leaves)
    }

    /// Generate a merkle tree from a vec of leaf hashes
    fn build_merkletree(mut leaves: Vec<MerkleHash>) -> Vec<Vec<MerkleHash>> {
        // ensure leaves.len() is a power of 2 so tree is perfect
        Self::pad_layer(&mut leaves);
        let mut layers = Vec::new();
        layers.push(leaves);

        // build layers up to root
        while layers.last().unwrap().len() > 1 {
            let mut layer: Vec<MerkleHash> = Vec::new();
            // iterate over hashes in pairs to generate parent hash
            for i in (0..layers.last().unwrap().len()).step_by(2) {
                let left = layers.last().unwrap()[i];
                let right = layers.last().unwrap()[i+1];
                let parent = Self::hash(
                    [left, right].concat()
                );
                layer.push(parent);
            }
            layers.push(layer);
        }
        layers
    }

    fn hash<T: AsRef<[u8]>>(data: T) -> MerkleHash {
        let mut output = [0u8; 32];
        let mut hasher = Keccak::v256();
        hasher.update(data.as_ref());
        hasher.finalize(&mut output);
        output
    }

    /// Repeat last hash until leaves.len() is a power of 2
    fn pad_layer(layer: &mut Vec<MerkleHash>) {
        if layer.len() == 0 { return; }
        let mut target_len = 1;
        // find a power of 2 >= length of layer
        while target_len < layer.len() {
            target_len *= 2;
        }
        // repeat last hash to reach target len
        for _ in 0..(target_len - layer.len()) {
            layer.push(layer.last().unwrap().clone());
        }
        assert!(layer.len() & (layer.len() - 1) == 0);
    }


    /// add data to the tree
    pub fn insert<T: AsRef<[u8]>>(&mut self, data: T) {
        let hash = Self::hash(data);
        self.insert_hash(hash);
    }

    /// Generate a merkle proof from hashable data.
    /// Return Err if hash of data not in tree
    pub fn gen_proof<T: AsRef<[u8]>>(&self, element: T) -> Result<MerkleProof, &str> {
        let hash = Self::hash(element);
        self.proof(hash)
    }

    /// verify that element is a member of the tree
    pub fn verify<T: AsRef<[u8]>>(&self, proof: &MerkleProof, element: T, root: MerkleHash) -> bool {
        let hash = Self::hash(element);
        self.verify_hash(proof, hash, root)
    }
}

impl MerkleTree {
    fn from_leaves(leaves: Vec<MerkleHash>) -> Self {
        let layers = Self::build_merkletree(leaves);
        MerkleTree { layers }
    }

    /// return the root hash
    pub fn root(&self) -> Option<MerkleHash> {
        Some(self.layers.last()?[0])
    }

    fn proof(&self, hash: MerkleHash) -> Result<MerkleProof, &str> {
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
            idx /= 2;
        }

        Ok(proof)
    }

    fn insert_hash(&mut self, hash: MerkleHash) {
        let leaves = &mut self.layers[0];
        for i in 1..leaves.len() {
            if leaves[i-1] == leaves[i] {
                leaves[i] = hash;
                self.recalculate_branch(i);
                return
            }
        }
        // if tree is uniquely perfect, add new element and rebuild tree
        self.layers[0].push(hash);
        *self = MerkleTree::from_leaves(self.layers[0].to_owned());
    }

    fn recalculate_branch(&mut self, leaf_idx: usize) {
        let mut node_idx = leaf_idx;
        let mut layer_idx = 0;
        for _ in 0..self.layers.len() - 1 {
            let layer = &self.layers[layer_idx];
            let parent_idx = node_idx / 2;
            // determine if new leaf is left or right child
            let (left, right) = match node_idx % 2 == 0 {
                true => (layer[node_idx], layer[node_idx + 1]),
                false => (layer[node_idx - 1], layer[node_idx]),
            };
            // rehash parent node
            self.layers[layer_idx + 1][parent_idx] = Self::hash([left, right].concat());
            node_idx = parent_idx;
            layer_idx += 1;
        }
    }

    fn verify_hash(&self, proof: &MerkleProof, hash: MerkleHash, root: MerkleHash) -> bool {
        // verify provided root matches tree root
        let tree_root = self.root();
        if Some(root) != tree_root || !self.layers[0].contains(&hash) { return false }

        // hash proof nodes up to root
        let mut running_hash = hash;
        for node in proof {
            let (left, right) = match node.side {
                Side::Left => (node.hash, running_hash),
                Side::Right => (running_hash, node.hash),
            };
            running_hash = Self::hash([left, right].concat());
        }
        Some(running_hash) == tree_root
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_tree_root() {
        let elements = vec!["foo", "bar"];
        let tree = MerkleTree::new(&elements);
        assert_eq!(tree.root(), Some(MerkleTree::hash([MerkleTree::hash("foo"), MerkleTree::hash("bar")].concat())));
    }

    #[test]
    fn empty_tree() {
        let empty_vec: Vec<&str> = vec![];
        let mut empty_tree = MerkleTree::new(&empty_vec);
        let prefill_tree = MerkleTree::new(&vec!["foo", "bar"]);
        empty_tree.insert("foo");
        assert_ne!(empty_tree, prefill_tree);
        empty_tree.insert("bar");
        assert_eq!(empty_tree, prefill_tree);
    }

    #[test]
    fn insert() {
        let elements = vec!["foo", "bar"];
        let mut tree = MerkleTree::new(&elements);
        assert!(tree.gen_proof("baz").is_err());
        tree.insert("baz");
        let proof = tree.gen_proof("baz");
        assert!(proof.is_ok());
        assert!(tree.verify(&proof.unwrap(), "baz", tree.root().unwrap()));
        tree.insert("quox");
        let proof = tree.gen_proof("quox");
        assert!(proof.is_ok());
        assert!(tree.verify(&proof.unwrap(), "quox", tree.root().unwrap()));
    }

    #[test]
    fn proof() {
        let elements = vec!["foo", "bar"];
        let tree = MerkleTree::new(&elements);
        let proof = tree.gen_proof("foo").unwrap();
        assert_eq!(proof.len(), 1);
        assert_eq!(proof[0].hash, MerkleTree::hash("bar"));
        assert!(tree.gen_proof("baz").is_err());
    }

    #[test]
    fn verify() {
        let elements = vec!["foo", "bar"];
        let tree = MerkleTree::new(&elements);
        let root = tree.root().unwrap();
        let proof = tree.gen_proof("foo").unwrap();
        assert!(tree.verify(&proof, "foo", root));
        let proof = tree.gen_proof("bar").unwrap();
        assert!(tree.verify(&proof, "bar", root));
        assert!(!tree.verify(&proof, "baz", root))
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
