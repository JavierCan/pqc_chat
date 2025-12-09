import pickle
import base64
import ctypes
import oqs
from typing import Optional, Tuple
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization

# NIST Level 3 Post-Quantum Signature Algorithm
DILITHIUM_ALG = "Dilithium3"

class HybridCertificate:
    """
    A Hybrid Certificate structure containing:
    1. Server Identity (ID)
    2. Post-Quantum KEM Key (Kyber)
    3. Classical Identity Key (RSA)
    4. Post-Quantum Signing Key (Dilithium)
    5. Dual Signatures (RSA + Dilithium)
    """
    def __init__(
        self, 
        server_id: str, 
        kyber_pk: bytes, 
        rsa_sk: Optional[rsa.RSAPrivateKey] = None, 
        dilithium_sk: Optional[bytes] = None, 
        dilithium_pk: Optional[bytes] = None
    ):
        self.server_id = server_id
        self.kyber_pk = kyber_pk
        
        # Signature storage
        self.rsa_signature = b''
        self.dilithium_signature = b''
        
        # Public key storage for verification
        self.rsa_public_bytes = b''
        self.dilithium_public_bytes = dilithium_pk 
        
        # Auto-sign if private keys are provided
        if rsa_sk and dilithium_sk:
            self.sign_certificate(rsa_sk, dilithium_sk)

    def sign_certificate(self, rsa_sk: rsa.RSAPrivateKey, dilithium_sk_bytes: bytes):
        """
        Signs the certificate data using both RSA and Dilithium keys.
        """
        # --- 1. PREPARE DATA ---
        # Export RSA public key to embed in the certificate
        self.rsa_public_bytes = rsa_sk.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        
        # Data payload: Server ID + Kyber Key + Dilithium Public Key
        data_to_sign = self.server_id.encode() + self.kyber_pk + self.dilithium_public_bytes

        # --- 2. CLASSICAL SIGNATURE (RSA) ---
        self.rsa_signature = rsa_sk.sign(
            data_to_sign,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )

        # --- 3. POST-QUANTUM SIGNATURE (DILITHIUM) ---
        with oqs.Signature(DILITHIUM_ALG) as signer:
            # MEMORY FIX: Convert Python bytes to C-compatible string buffer
            # This prevents memory access errors in the underlying C library
            secret_buf = ctypes.create_string_buffer(dilithium_sk_bytes, len(dilithium_sk_bytes))
            signer.secret_key = secret_buf
            
            self.dilithium_signature = signer.sign(data_to_sign)

    def verify_signature(self) -> bool:
        """
        Verifies both RSA and Dilithium signatures.
        Returns True only if BOTH layers are valid.
        """
        try:
            # Reconstruct the original data payload
            data_to_verify = self.server_id.encode() + self.kyber_pk + self.dilithium_public_bytes
            
            # 1. Verify RSA Layer
            print("[PKI] Verifying Layer 1: RSA (Classical)...")
            rsa_pk = serialization.load_pem_public_key(self.rsa_public_bytes)
            rsa_pk.verify(
                self.rsa_signature,
                data_to_verify,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            
            # 2. Verify Dilithium Layer
            print("[PKI] Verifying Layer 2: Dilithium3 (Post-Quantum)...")
            with oqs.Signature(DILITHIUM_ALG) as verifier:
                is_valid = verifier.verify(data_to_verify, self.dilithium_signature, self.dilithium_public_bytes)
                
                if not is_valid:
                    raise ValueError("Dilithium signature invalid.")
            
            return True 
            
        except Exception as e:
            print(f"[PKI] Verification Failure: {e}")
            return False

    # --- PEM SERIALIZATION HELPERS ---
    
    def to_pem(self) -> bytes:
        """Serializes the object to a PEM-formatted byte string."""
        serialized_data = pickle.dumps(self)
        b64_data = base64.b64encode(serialized_data).decode('utf-8')
        
        # Split into 64-character lines standard for PEM
        lines = [b64_data[i:i+64] for i in range(0, len(b64_data), 64)]
        
        pem_str = "-----BEGIN HYBRID PQC CERTIFICATE-----\n" + \
                  "\n".join(lines) + \
                  "\n-----END HYBRID PQC CERTIFICATE-----\n"
        return pem_str.encode('utf-8')

    @staticmethod
    def from_pem(pem_data: bytes) -> Optional['HybridCertificate']:
        """Deserializes a PEM-formatted byte string back into a HybridCertificate object."""
        try:
            if not pem_data:
                raise ValueError("Received empty certificate data.")
                
            pem_str = pem_data.decode('utf-8')
            lines = pem_str.strip().split('\n')
            
            # Filter header/footer lines and reconstruct Base64
            b64_data = "".join([l for l in lines if "-----" not in l])
            serialized_data = base64.b64decode(b64_data)
            
            return pickle.loads(serialized_data)
        except Exception as e:
            print(f"[PKI] PEM Decoding Error: {e}")
            return None

# --- IDENTITY GENERATION HELPERS ---

def generate_rsa_identity() -> rsa.RSAPrivateKey:
    """Generates a standard RSA-2048 private key."""
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)

def generate_dilithium_identity() -> Tuple[bytes, bytes]:
    """Generates a Dilithium3 keypair (Public Key, Secret Key)."""
    with oqs.Signature(DILITHIUM_ALG) as sig:
        pk = sig.generate_keypair()
        sk = sig.export_secret_key()
        return pk, sk