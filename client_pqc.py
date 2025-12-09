import socket
import os
import time
from protocol_pqc import (
    kyber_encapsulate, 
    derive_aes_key,
    run_chat_loop, 
    send_message, 
    receive_message, 
    STEP_PAUSE, 
    SALT_LENGTH
)
from hybrid_pki import HybridCertificate

HOST = '127.0.0.1'
PORT = 12345

def main():
    print("--- SECURE CLIENT TERMINAL (PQC HYBRID) ---", flush=True)

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            print(f"[Client] Attempting connection to {HOST}:{PORT}...", flush=True)
            s.connect((HOST, PORT))
            
            print("\n[Client] Initiating Hybrid Handshake protocol...", flush=True)
            
            # 1. Receive Server's Hybrid Certificate
            print("[Client] Waiting for Hybrid Certificate...", flush=True)
            cert_data = receive_message(s)
            
            # 2. Verify Certificate (Dual Signature)
            try:
                # Deserialize PEM format
                cert = HybridCertificate.from_pem(cert_data)
                if not cert:
                    raise ValueError("Failed to decode certificate data.")

                print(f"[Client] Certificate received. Server ID: {cert.server_id}", flush=True)
                print("[Client] Verifying dual signatures (RSA + Dilithium)...", flush=True)
                
                # The verify_signature method performs the internal crypto checks
                if cert.verify_signature():
                    print("[Client] SUCCESS: Dual signatures verified (RSA + Dilithium).", flush=True)
                    print("[Client] Trust established in hybrid environment.", flush=True)
                    server_pk = cert.kyber_pk # Extract the PQC KEM key
                else:
                    print("[Client] ERROR: Signature verification failed. Aborting connection.", flush=True)
                    return
            except Exception as e:
                print(f"[Client] Certificate Processing Error: {e}")
                return

            time.sleep(STEP_PAUSE)
            
            # 3. Encapsulate (Kyber)
            # Generate shared secret and encapsulate it for the server
            ciphertext, shared_secret = kyber_encapsulate(server_pk)
            print(f"[Client] Quantum secret encapsulated (Ciphertext size: {len(ciphertext)} bytes).", flush=True)
            
            send_message(s, ciphertext)
            
            # 4. Derive Keys
            # Generate random salt for KDF
            salt = os.urandom(SALT_LENGTH)
            send_message(s, salt)

            # Derive the final AES-256 key
            aesgcm = derive_aes_key(shared_secret, salt)
            print("[Client] Post-Quantum secure channel established (AES-GCM).", flush=True)

            # Start the encrypted chat loop
            run_chat_loop(s, aesgcm, "Client", True)

    except ConnectionRefusedError:
        print("[Client] Error: Connection refused. Ensure server is running.")
    except Exception as e:
        print(f"[Client] Critical Error: {e}")

if __name__ == "__main__":
    main()