from eth_keys import keys
from eth_utils import decode_hex

def generate_ethereum_wallet():
    private_key = keys.PrivateKey(os.urandom(32))
    public_key_hex = private_key.public_key.to_hex()
    address = keys.PublicKey(decode_hex(public_key_hex)).to_address()
    private_key_hex = private_key.to_hex()
    return private_key_hex, address

if __name__ == "__main__":
    import os
    private_key, address = generate_ethereum_wallet()
    print("Private key:", private_key)
    print("Public address:", address)
