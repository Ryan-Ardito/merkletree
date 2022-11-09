# Merkle Tree

This Merkle Tree implementation aims to be an easy to use out-of-the-box tool for generating merkletrees and proofs
for smart contracts. A common usecase is NFT airdrop whitelists.

```rust
use merkletree::MerkleTree;

// instantiate an empty tree
let empty_tree = MerkleTree::new();

// instantiate a tree from a sequence of elements
let elements = vec!["foo", "bar"];
let mut tree = MerkleTree::from_array(&elements);

// insert new elements into the tree
tree.insert(&"baz");

// generate proofs
let proof = tree.gen_proof(&"baz").expect("data not in tree");

// verify proofs
let root = tree.root().expect("tree is empty");
assert!(tree.verify(&proof, &"baz", root,));

// use a custom hasher
let tree = MerkleTree::<MyHasher>::with_hasher();
```

TODO:
1. Out-of-the-box proofs should be verifiable with openzeppelin/MerkleProof.sol
1. Currently, the final leaf hash is repeated until the leaves layer is a power of 2.
This uses more memory than needed, and may present an attack surface. Change before release.
1. Stabilize API.