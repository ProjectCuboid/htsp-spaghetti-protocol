# HTSP Python E2EE Wrapper 
## ( Hypertext Spaghetti Protocol )

HTSP is a simple end-to-end encryption wrapper for Python.  
It provides **AES-GCM encryption** with automatic **Diffie-Hellman session key exchange**, so you can securely exchange messages without exposing your key to the server.

## Installation

```bash
pip install cryptography

Copy htsp.py into your project folder.
```

---

## Usage

```python
from htsp import htsp

# Create sessions for two parties
alice = htsp()
bob   = htsp()

# Exchange public keys over insecure channel
alice.receive_public(bob.get_public())
bob.receive_public(alice.get_public())

# Encrypt & decrypt messages
encrypted = alice.encrypt("hello world")
decrypted = bob.decrypt(encrypted)
print(decrypted)  # "hello world"
```

## API


- htsp(): Create a session object.

- get_public(): Returns your public key to send to the other party.

- receive_public(other_public): Computes the shared session key from the other party’s public key.

- encrypt(data): Encrypt a string using the shared key.

- decrypt(ciphertext): Decrypt a string using the shared key.

Security Notes

    Messages are protected with AES-GCM.

    The shared key is generated via Diffie-Hellman.

    Never hardcode private keys or send them over the server.

    This is safe for real messaging as long as the public key exchange isn’t tampered with.

---