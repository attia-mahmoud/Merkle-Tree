import hashlib
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat, NoEncryption
from cryptography.hazmat.primitives.asymmetric import padding, rsa

def hash_data(data):
    """
    Hash the input data using the SHA-256 algorithm.

    This function takes a single input argument, `data`, which can either be a string or bytes. 
    If the input is a string, it will be encoded into bytes using UTF-8 encoding. 
    The function then computes the SHA-256 hash of these bytes and returns the hexadecimal representation of the hash.

    Args:
        data (str or bytes): The data to hash. If a string is provided, it will be automatically converted to bytes.

    Returns:
        str: The hexadecimal string of the SHA-256 hash of the input data.
    """
    if isinstance(data, str):
        data = data.encode()  # Encode string to bytes using UTF-8 if necessary
    return hashlib.sha256(data).hexdigest()  # Compute and return the SHA-256 hash as a hex string


class MerkleTree:
    def __init__(self):
        """
        Attributes:
            leaves (list): A list of hashed leaves (data blocks).
            tree (list): A structured list containing all levels of the tree, including the root.
            root (str or None): The root hash of the Merkle Tree. It is None until the tree is computed.
        """
        self.leaves = []
        self.tree = []
        self.root = None

    def add_data(self, data):
        """
        Adds data blocks to the leaf list of the Merkle Tree.
        Each data block is individually hashed and added as a leaf.

        Args:
            data (iterable): a list of data blocks that are either strings or bytes. 
        """
        for block in data:
            self.leaves.append(hash_data(block))

    def insert_data_block(self, data_block):
        """
        Insert a new data block into the tree and rebuild the tree.
        
        Args:
            data_block (str or bytes): the data block to be added to the tree 
        """
        self.leaves.append(hash_data(data_block))
        self.build_tree()

    def delete_data_block(self, data_block):
        """
        Delete a data block from the tree and rebuild the tree.
        
        Args:
            data_block (str or bytes): the data block to be removed from the tree 
        """
        try:
            block_hash = hash_data(data_block)
            self.leaves.remove(block_hash)
            self.build_tree()
        except ValueError:
            print("Block not found in the leaves.")

    def build_tree(self):
        """
        Build the Merkle Tree from the current leaves.

        It starts from the leaves and constructs the tree layer by layer up to the root. 
        Each node in the tree is created by concatenating the hashes of two child nodes and then hashing the concatenated string.

        The Merkle Tree structure is stored in `self.tree`, where each level of the tree is a list of hashes,
        starting from the leaves up to the root.

        Attributes modified:
            self.tree (list): A list where each element is a list representing a level in the Merkle Tree.
            self.root (str or None): The root hash of the Merkle Tree, None if the tree is empty.

        Returns:
            self.root (str or None): The root hash of the Merkle Tree, None if the tree is empty.
        """
        current_level = self.leaves[:]

        if len(current_level) % 2 == 1:
            current_level.append(current_level[-1])  # Duplicate last element if odd number of leaves

        self.tree = [current_level]

        while len(current_level) > 1:
            next_level = []

            for i in range(0, len(current_level), 2): # Process pairs of nodes
                hashed_nodes = hash_data(current_level[i] + current_level[i + 1])  # Concatenate two consecutive node hashes, then hash the result
                next_level.append(hashed_nodes)

            if len(next_level) % 2 == 1 and len(next_level) > 1:
                next_level.append(next_level[-1])  # Ensure even number of nodes at each level

            self.tree.append(next_level)
            current_level = next_level

        self.root = current_level[0] if current_level else None

        return self.root

    def get_proof(self, data_block):
        """
        This method provides the sequence of hashes (Merkle Path), necessary to verify that a given data block is part of the tree.

        It returns a list of tuples, each containing a hash and a direction ('L' or 'R') indicating 
        whether to append this hash to the left or right of the current hash during verification.

        Args:
            data_block (str or bytes): The data block for which proof is required.

        Returns:
            list of tuples: Each tuple contains a hash and a direction ('L' or 'R'). The list represents the path
                            from the given data block to the root of the Merkle Tree.

        Raises:
            ValueError: If the data block is not found in the leaves of the tree.
        """
        block_hash = hash_data(data_block)
        index = self.leaves.index(block_hash)
        proof = []

        for level in self.tree[:-1]:  # Exclude the root level
            other_index = index ^ 1  # Get sibling index; bitwise XOR

            if other_index < len(level):
                proof.append((level[other_index], 'L' if other_index < index else 'R'))

            index //= 2 # Update the index to point to the parent node in the next level up
        return proof

    def verify_proof(self, data_block, proof, root):
        """
        This method checks whether the provided proof correctly leads from the given data block to the specified
        Merkle root. 

        Args:
            data_block (str or bytes): The data block for which the proof is provided.
            proof (list of tuples): A list of tuples where each tuple contains a hash and a direction ('L' or 'R').
                                    This list is the proof needed to verify the block's inclusion in the tree.
            root (str): The root hash of the Merkle Tree against which the proof will be verified.

        Returns:
            bool: True if the reconstructed hash from the proof matches the given root, False otherwise.
        """
        current_hash = hash_data(data_block)
        for node, position in proof:
            if position == 'L':
                current_hash = hash_data(node + current_hash)
            else:
                current_hash = hash_data(current_hash + node)
        return current_hash == root

    def sign_tree(self, private_key):
        """
        This method signs the Merkle root hash with a given private key using the RSA-PSS (Probabilistic Signature Scheme)
        signature scheme, which is more secure against chosen plaintext attacks compared to the older PKCS#1 v1.5 scheme.

        The hash function used for both the message digest and the mask generation function (MGF) in PSS is SHA-256.

        Args:
            private_key (RSAPrivateKey): The RSA private key used for signing the Merkle root.

        Returns:
            bytes: The digital signature of the Merkle root hash.

        Raises:
            ValueError: If the root is not set before signing.
        """
        return private_key.sign(
            self.root.encode(), # Convert the root hash to bytes
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()), # Use SHA-256 in MGF1 padding
                salt_length=padding.PSS.MAX_LENGTH # Use the maximum salt length allowed by PSS
            ),
            hashes.SHA256() # Use SHA-256 as the hash function
        )

    def verify_signature(self, signature, public_key):
        """
        This method checks if the provided digital signature of the Merkle root can be authenticated with the given public key,
        ensuring the integrity and authenticity of the Merkle root. 

        Args:
            signature (bytes): The digital signature of the Merkle root to be verified.
            public_key (RSAPublicKey): The RSA public key corresponding to the private key that was used to sign the root.

        Returns:
            bool: True if the signature is valid and authenticates the root correctly, False if the verification fails or an error occurs.

        Note:
            This method catches and handles all exceptions, returning False for any error encountered during verification.
        """
        try:
            public_key.verify(
                signature,
                self.root.encode(), 
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()), 
                    salt_length=padding.PSS.MAX_LENGTH 
                ),
                hashes.SHA256() 
            )
            return True
        except Exception:
            return False