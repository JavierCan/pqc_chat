import pickle
import base64
import ctypes  
import oqs
from typing import Optional, Tuple
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization


DILITHIUM_ALG = "Dilithium3"

class HybridCertificate:
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
        self.rsa_signature = b''
        self.dilithium_signature = b''
        self.rsa_public_bytes = b''
        self.dilithium_public_bytes = dilithium_pk 
        

        if rsa_sk and dilithium_sk:
            self.sign_certificate(rsa_sk, dilithium_sk)

    def sign_certificate(self, rsa_sk: rsa.RSAPrivateKey, dilithium_sk_bytes: bytes):
        # 1. Preparar llave pública RSA
        self.rsa_public_bytes = rsa_sk.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        
        # Datos a firmar (Payload Híbrido)
        data_to_sign = self.server_id.encode() + self.kyber_pk + self.dilithium_public_bytes

        # 2. Firma Clásica (RSA)
        self.rsa_signature = rsa_sk.sign(
            data_to_sign,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )

        # 3. Firma Post-Cuántica (Dilithium)
        with oqs.Signature(DILITHIUM_ALG) as signer:

            secret_buf = ctypes.create_string_buffer(dilithium_sk_bytes, len(dilithium_sk_bytes))
            signer.secret_key = secret_buf  
            # ============================
            self.dilithium_signature = signer.sign(data_to_sign)

    def verify_signature(self) -> bool:
        try:
            data_to_verify = self.server_id.encode() + self.kyber_pk + self.dilithium_public_bytes
            
            # Verificar RSA
            print("[PKI] Verifying Layer 1: RSA...")
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
            
            # Verificar Dilithium
            print("[PKI] Verifying Layer 2: Dilithium3...")
            with oqs.Signature(DILITHIUM_ALG) as verifier:
                is_valid = verifier.verify(data_to_verify, self.dilithium_signature, self.dilithium_public_bytes)
                if not is_valid: raise ValueError("Dilithium Invalid")
            
            return True 
        except Exception as e:
            print(f"[PKI] Verification Failure: {e}")
            return False

    def to_pem(self) -> bytes:
        serialized_data = pickle.dumps(self)
        b64_data = base64.b64encode(serialized_data).decode('utf-8')
        lines = [b64_data[i:i+64] for i in range(0, len(b64_data), 64)]
        pem_str = "-----BEGIN HYBRID PQC CERTIFICATE-----\n" + "\n".join(lines) + "\n-----END HYBRID PQC CERTIFICATE-----\n"
        return pem_str.encode('utf-8')

    @staticmethod
    def from_pem(pem_data: bytes):

        try:
            if not pem_data:

                return None
            
            pem_str = pem_data.decode('utf-8')

            lines = pem_str.strip().split('\n')

            b64_data = "".join([l for l in lines if "-----" not in l])

            serialized_data = base64.b64decode(b64_data)
            return pickle.loads(serialized_data)
        
        except Exception as e:

            print(f"[PKI] Error decodificando PEM: {e}")
            return None 


def generate_rsa_identity():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)

def generate_dilithium_identity():
    with oqs.Signature(DILITHIUM_ALG) as sig:
        pk = sig.generate_keypair()
        sk = sig.export_secret_key()
        return pk, sk