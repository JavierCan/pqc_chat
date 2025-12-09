import os
import oqs
from typing import Tuple, Optional, Any

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag

# --- CONFIGURATION CONSTANTS ---
KEM_ALG = "Kyber512"

ENCRYPTION_KEY_LENGTH = 32
SALT_LENGTH = 16
NONCE_LENGTH = 12 
HEADER_LENGTH = 4
STEP_PAUSE = 1.0 
KDF_ITERATIONS = 480000

# --- CORE POST-QUANTUM CRYPTOGRAPHY FUNCTIONS ---

def generate_kyber_keypair() -> Tuple[bytes, bytes, Any]:
    """
    Initializes the Kyber512 KEM mechanism and generates a keypair.
    Returns: (public_key, secret_key, kem_object)
    """
    print(f"[PQC-Core] Initializing Key Encapsulation Mechanism: {KEM_ALG}...", flush=True)
    kem = oqs.KeyEncapsulation(KEM_ALG)
    
    print(f"[PQC-Core] Generating lattice-based keypair...", flush=True)
    public_key = kem.generate_keypair()
    secret_key = kem.export_secret_key()
    
    return public_key, secret_key, kem

def kyber_encapsulate(peer_public_key: bytes) -> Tuple[bytes, bytes]:
    """
    Generates a shared secret and encapsulates it for the peer.
    Returns: (ciphertext, shared_secret)
    """
    print(f"[PQC-Core] Encapsulating quantum-safe secret...", flush=True)
    with oqs.KeyEncapsulation(KEM_ALG) as kem:
        ciphertext, shared_secret = kem.encap_secret(peer_public_key)
    return ciphertext, shared_secret

def kyber_decapsulate(kem_context: Any, ciphertext: bytes) -> bytes:
    """
    Decapsulates the received ciphertext to recover the shared secret.
    Returns: shared_secret
    """
    print(f"[PQC-Core] Decapsulating received ciphertext...", flush=True)
    shared_secret = kem_context.decap_secret(ciphertext)
    return shared_secret

# --- SYMMETRIC CRYPTOGRAPHY & KDF FUNCTIONS ---

def derive_aes_key(shared_secret: bytes, salt: bytes) -> AESGCM:
    """
    Derives a 256-bit AES-GCM key from the quantum shared secret using PBKDF2-HMAC-SHA256.
    """
    print("[Crypto] KDF: Deriving AES-256 session key from quantum secret...", flush=True)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=ENCRYPTION_KEY_LENGTH,
        salt=salt,
        iterations=KDF_ITERATIONS,
        backend=default_backend()
    )
    key = kdf.derive(shared_secret)
    return AESGCM(key)

# --- NETWORK TRANSPORT UTILITIES ---

def send_message(sock: Any, message: bytes) -> None:
    """
    Sends a message prefixed with a 4-byte length header.
    """
    try:
        msg_len = len(message).to_bytes(HEADER_LENGTH, 'big')
        sock.sendall(msg_len + message)
    except BrokenPipeError:
        print("[Network] Error: Pipe broken during transmission.")
        pass

def receive_message(sock: Any) -> Optional[bytes]:
    """
    Receives a message based on the 4-byte length header.
    """
    try:
        msg_len_bytes = sock.recv(HEADER_LENGTH)
        if not msg_len_bytes: return None 
        msg_len = int.from_bytes(msg_len_bytes, 'big')
        
        data = bytearray()
        while len(data) < msg_len:
            packet = sock.recv(min(msg_len - len(data), 4096))
            if not packet: return None 
            data.extend(packet)
        return bytes(data) 
    except ConnectionResetError:
        return None

# --- TERMINAL CHAT HANDLER (For Server Console) ---

def run_chat_loop(sock: Any, aesgcm: AESGCM, role_name: str, starts_by_sending: bool) -> None:
    """
    Main loop for encrypted communication via terminal.
    Handles AES-GCM encryption/decryption and integrity checks.
    """
    print(f"\n--- QUANTUM-SECURE SESSION ACTIVE (AES-256-GCM) ---")
    try:
        while True:
            # SENDER LOGIC
            if starts_by_sending:
                my_msg = input(f"[{role_name}] > ")
                nonce = os.urandom(NONCE_LENGTH)
                ciphertext = aesgcm.encrypt(nonce, my_msg.encode(), None)
                send_message(sock, nonce + ciphertext)
                if my_msg == 'exit': break
            
            # RECEIVER LOGIC
            data = receive_message(sock)
            if not data: 
                print("[Network] Connection closed by peer.")
                break
            
            nonce, ciphertext = data[:NONCE_LENGTH], data[NONCE_LENGTH:]
            try:
                plaintext = aesgcm.decrypt(nonce, ciphertext, None).decode()
                peer = "Client" if role_name == "Server" else "Server"
                print(f"[{peer}] {plaintext}")
                if plaintext == 'exit': break
            except InvalidTag:
                print("[Security] CRITICAL: Authentication tag mismatch! Possible tampering detected.")
            
            if not starts_by_sending: starts_by_sending = True

    except Exception as e:
        print(f"[System] Runtime Error: {e}")