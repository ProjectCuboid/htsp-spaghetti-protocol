# htsp.py
import secrets, os, base64
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# Diffie-Hellman constants (safe example primes)
P = 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1
G = 2

class Session:
    def __init__(self):
        self._private = secrets.randbelow(P - 2) + 1
        self._public = pow(G, self._private, P)
        self.shared_key = None

    def get_public(self) -> int:
        """Send this to the other party."""
        return self._public

    def receive_public(self, other_public: int):
        """Receive other party's public key and compute shared AES key."""
        shared = pow(other_public, self._private, P)
        # convert shared int to 32 bytes for AES-256
        self.shared_key = shared.to_bytes(32, 'big', signed=False)

    def encrypt(self, data: str) -> str:
        if not self.shared_key:
            raise ValueError("Shared key not established")
        aesgcm = AESGCM(self.shared_key)
        nonce = os.urandom(12)
        ct = aesgcm.encrypt(nonce, data.encode('utf-8'), None)
        return base64.urlsafe_b64encode(nonce + ct).decode('ascii')

    def decrypt(self, ciphertext: str) -> str:
        if not self.shared_key:
            raise ValueError("Shared key not established")
        aesgcm = AESGCM(self.shared_key)
        raw = base64.urlsafe_b64decode(ciphertext)
        nonce, ct = raw[:12], raw[12:]
        return aesgcm.decrypt(nonce, ct, None).decode('utf-8')


# Alias for API consistency
htsp = Session
