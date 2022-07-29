/// ```
/// use merkletree::MerkleTree;
/// 
/// let data = vec!["foo", "bar"];
/// let tree = MerkleTree::new(&data);
/// let root = tree.root();
/// let proof = tree.gen_proof("foo").unwrap();
/// assert!(tree.verify(&proof, "foo", root));
/// ```

use std::{hash::{Hash, Hasher}, collections::hash_map::DefaultHasher};

pub type MerkleHash = [u8; 8];

#[derive(Debug)]
pub enum Side {
    Left,
    Right,
}

#[derive(Debug)]
pub struct ProofNode {
    hash: MerkleHash,
    side: Side,
}

pub type MerkleProof = Vec<ProofNode>;

fn build_merkletree(mut leaves: Vec<MerkleHash>) -> Vec<Vec<MerkleHash>> {
    pad_layer(&mut leaves);
    let mut layers = Vec::new();
    layers.push(leaves);

    // build layers up to root
    while layers.last().unwrap().len() > 1 {
        let mut layer: Vec<MerkleHash> = Vec::new();
        // iterate over hashes in pairs to generate parent hash
        for i in (0..layers.last().unwrap().len()).step_by(2) {
            let node = _hash(
                [
                    layers.last().unwrap()[i],
                    layers.last().unwrap()[i+1]
                ].concat()
            );
            layer.push(node);
        }
        layers.push(layer);
    }
    layers
}

fn _hash<T: Hash>(data: T) -> MerkleHash {
    let mut hasher = DefaultHasher::new();
    data.hash(&mut hasher);
    hasher.finish().to_be_bytes()
}

/// ensure len of leaves is a power of 2 so that the tree is perfect
fn pad_layer(layer: &mut Vec<MerkleHash>) {
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

/// Build merkle trees, get proofs, and verify proofs from hashabe data
pub struct MerkleTree {
    layers: Vec<Vec<MerkleHash>>,
}

impl MerkleTree {
    pub fn new<T: Hash>(elements: &Vec<T>) -> Self {
        let leaves: Vec<MerkleHash> = elements
            .into_iter()
            .map(|e| _hash(e))
            .collect();
        MerkleTree::from_leaves(leaves)
    }

    fn from_leaves(leaves: Vec<MerkleHash>) -> Self {
        let layers = build_merkletree(leaves);
        MerkleTree { layers }
    }

    pub fn root(&self) -> MerkleHash {
        self.layers.last().unwrap()[0]
    }

    pub fn insert<T: Hash>(&mut self, data: T) {
        let hash = _hash(data);
        self.insert_hash(hash);
    }

    /// Generates a merkle proof from hashable data.
    /// Return Err if hash of data not in tree
    pub fn gen_proof<T: Hash>(&self, element: T) -> Result<MerkleProof, &str> {
        let hash = _hash(element);
        self.proof(hash)
    }

    pub fn verify<T: Hash>(&self, proof: &MerkleProof, element: T, root: MerkleHash) -> bool {
        let hash = _hash(element);
        self.verify_hash(proof, hash, root)
    }

    fn proof(&self, hash: MerkleHash) -> Result<MerkleProof, &str> {
        // find index of leaf
        let mut idx = match self.layers[0].iter().position(|&e| e == hash) {
            Some(h) => h,
            None => { return Err("element not in tree") },
        };
        let mut proof = Vec::new();
        for i in 0..(self.layers.len() - 1) {
            // determine if sibling node is left or right
            let node = match idx % 2 == 0 {
                true => ProofNode { hash: self.layers[i][idx + 1], side: Side::Right },
                false => ProofNode { hash: self.layers[i][idx - 1], side: Side::Left },
            };
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
        self.layers[0].push(hash);
        *self = MerkleTree::from_leaves(self.layers[0].to_owned());
    }

    fn recalculate_branch(&mut self, leaf_idx: usize) {
        let mut node_idx = leaf_idx;
        let mut layer_idx = 0;
        for _ in 0..self.layers.len() - 1 {
            let layer = &self.layers[layer_idx];
            let parent_idx = node_idx / 2;
            // determine if changed node is left or right child
            let (left, right) = match node_idx % 2 == 0 {
                true => (layer[node_idx], layer[node_idx + 1]),
                false => (layer[node_idx - 1], layer[node_idx]),
            };
            // rehash parent node
            self.layers[layer_idx + 1][parent_idx] = _hash([left, right].concat());
            node_idx = parent_idx;
            layer_idx += 1;
        }
    }

    fn verify_hash(&self, proof: &MerkleProof, hash: MerkleHash, root: MerkleHash) -> bool {
        // verify provided root matches tree root
        let tree_root = self.root();
        if root != tree_root || !self.layers[0].contains(&hash) { return false }

        // hash proof nodes up to root
        let mut running_hash = hash;
        for node in proof {
            let (left, right) = match node.side {
                Side::Left => (node.hash, running_hash),
                Side::Right => (running_hash, node.hash),
            };
            running_hash = _hash([left, right].concat());
        }
        running_hash == root
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn root() {
        let elements = vec!["foo", "bar"];
        let tree = MerkleTree::new(&elements);
        assert_eq!(tree.root(), _hash([_hash("foo"), _hash("bar")].concat()));
    }

    #[test]
    fn insert() {
        let elements = vec!["foo", "bar"];
        let mut tree = MerkleTree::new(&elements);
        assert!(tree.gen_proof("baz").is_err());
        tree.insert("baz");
        let proof = tree.gen_proof("baz");
        assert!(proof.is_ok());
        assert!(tree.verify(&proof.unwrap(), "baz", tree.root()));
        tree.insert("quox");
        let proof = tree.gen_proof("quox");
        assert!(proof.is_ok());
        assert!(tree.verify(&proof.unwrap(), "quox", tree.root()));
    }

    #[test]
    fn proof() {
        let elements = vec!["foo", "bar"];
        let tree = MerkleTree::new(&elements);
        let proof = tree.gen_proof("foo").unwrap();
        assert_eq!(proof.len(), 1);
        assert_eq!(proof[0].hash, _hash("bar"));
        assert!(tree.gen_proof("baz").is_err());
    }

    #[test]
    fn verify() {
        let elements = vec!["foo", "bar"];
        let tree = MerkleTree::new(&elements);
        let root = tree.root();
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