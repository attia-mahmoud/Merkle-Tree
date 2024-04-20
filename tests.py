import unittest
from merkle import *

class TestHashData(unittest.TestCase):
    def test_hash_data_string(self):
        # Test with a known string and its SHA-256 hash result
        test_string = "hello world"
        expected_hash = "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
        result = hash_data(test_string)
        self.assertEqual(result, expected_hash)

    def test_hash_data_bytes(self):
        # Test with byte input
        test_bytes = b"hello world"
        expected_hash = "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
        result = hash_data(test_bytes)
        self.assertEqual(result, expected_hash)

    def test_hash_data_empty_string(self):
        # Test with an empty string
        test_empty = ""
        expected_hash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        result = hash_data(test_empty)
        self.assertEqual(result, expected_hash)

class TestMerkleTree(unittest.TestCase):
    def test_add_single_data(self):
        tree = MerkleTree()
        tree.add_data(["hello"])
        tree.build_tree()
        self.assertEqual(len(tree.leaves), 1)
        self.assertEqual(tree.root, hash_data(hash_data("hello") + hash_data("hello")))

    def test_add_multiple_data(self):
        tree = MerkleTree()
        tree.add_data(["hello", "world"])
        tree.build_tree()
        self.assertEqual(len(tree.leaves), 2)
        self.assertTrue(hash_data("hello") in tree.leaves)
        self.assertTrue(hash_data("world") in tree.leaves)
        self.assertTrue(tree.root, hash_data(hash_data("hello") + hash_data("world")))

    def test_add_no_data(self):
        tree = MerkleTree()
        tree.add_data([])
        tree.build_tree()
        self.assertEqual(len(tree.leaves), 0)
        self.assertIsNone(tree.root)

    def test_odd_number_of_leaves(self):
        tree = MerkleTree()
        tree.add_data(["node1", "node2", "node3"])
        tree.build_tree()
        self.assertEqual(len(tree.tree[0]), 4)  # Check if last node is duplicated
        self.assertNotEqual(tree.root, None)

    def test_even_number_of_leaves(self):
        tree = MerkleTree()
        tree.add_data(["node1", "node2", "node3", "node4"])
        tree.build_tree()
        self.assertEqual(len(tree.tree[0]), 4)
        self.assertNotEqual(tree.root, None)

class TestMerkleTreeProof(unittest.TestCase):
    def test_proof_verification(self):
        # Initialize the tree and add some data
        tree = MerkleTree()
        data_blocks = ["block1", "block2", "block3", "block4"]
        tree.add_data(data_blocks)
        root = tree.build_tree()

        # Select a block to test
        test_block = "block3"

        # Generate the proof for the selected block
        proof = tree.get_proof(test_block)
        
        # Verify the proof using the Merkle root
        result = tree.verify_proof(test_block, proof, root)
        self.assertTrue(result)

class TestMerkleTreeSignature(unittest.TestCase):
    def test_signature_verification(self):
        # Initialize the tree and add some data
        tree = MerkleTree()
        data_blocks = ["block1", "block2", "block3", "block4"]
        tree.add_data(data_blocks)
        tree.build_tree()

        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )

        public_key = private_key.public_key()

        signature = tree.sign_tree(private_key)

        signature_valid = tree.verify_signature(signature, public_key)

        self.assertTrue(signature_valid)


# Run the test case
if __name__ == '__main__':
    unittest.main()
