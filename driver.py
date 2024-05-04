from merkle import MerkleTree
import cryptography.hazmat.primitives.serialization as serialization

# Initialize the MerkleTree and key pair
tree = MerkleTree()

# Start the input loop for data blocks
print("Enter data blocks. Submit empty block when finished:")
while True:
    data_block = input("Enter a data block: ")
    if data_block == '':
        break
    tree.add_data([data_block])

# Build the Merkle Tree
root, signature = tree.build_tree()

# Display the root and signature
print("\nMerkle Tree built successfully.")
print(f"Root hash: {root}")
print(f"Root signature: {signature}\n")
print(f"Public Key saved in pub.pem\n")

# Interactive menu
while True:
    print("Choose an option:")
    print("1. Generate proof for a data block")
    print("2. Verify a data block with a given proof")
    print("3. Verify the signature of the root")
    print("4. Exit")
    choice = input("Enter the number of your choice: ")
    
    if choice == '1':
        block_to_prove = input("Enter the data block to generate proof for: ")
        try:
            proof = tree.get_proof(block_to_prove)
            print(f"Proof: {proof}")
        except ValueError as e:
            print(f"Error: {e}")

    elif choice == '2':
        block_to_verify = input("Enter the data block to verify: ")
        proof_str = input("Enter the proof as a list of tuples (hash, direction), e.g., [(hash1, 'L'), (hash2, 'R')]: ")
        proof_eval = eval(proof_str)
        # root_to_verify = input("Enter the root hash to verify against: ")
        result = tree.verify_proof(block_to_verify, proof_eval, root)
        print(f"Verification result: {result}")

    elif choice == '3':
        sig = input("Provide the signature: ")
        key_path = input("Provide the public key file path: ")
        result = tree.verify_signature(sig, key_path)
        print(f"Signature verification result: {result}")

    elif choice == '4':
        print("Exiting...")
        break

    else:
        print("Invalid choice, please try again.")
