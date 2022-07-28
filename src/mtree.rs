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
        // iterate over hashes in pairs to generate parents
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
    let empty_leaf = _hash(0);
    let mut target_len = 1;
    // find a power of 2 >= length of layer
    while target_len < layer.len() {
        target_len *= 2;
    }
    // add dummy nodes to reach target
    for _ in 0..(target_len - layer.len()) {
        layer.push(empty_leaf);
    }
}

/// ```
/// use merkletree::MerkleTree;
/// 
/// let data = vec!["foo", "bar"];
/// let tree = MerkleTree::new(&data);
/// let root = tree.root();
/// let proof = tree.gen_proof("foo").unwrap();
/// assert!(tree.verify(&proof, "foo", root));
/// ```
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
}
