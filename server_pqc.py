import socket
import time
from protocol_pqc import (
    generate_kyber_keypair, 
    kyber_decapsulate, 
    derive_aes_key,
    run_chat_loop, 
    send_message, 
    receive_message, 
    STEP_PAUSE
)
from hybrid_pki import (
    generate_rsa_identity, 
    generate_dilithium_identity, 
    HybridCertificate
)

HOST = '127.0.0.1'
PORT = 12345

def main():
    print("--- SECURE SERVER TERMINAL (FULL HYBRID PQC) ---", flush=True)

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)        
        s.bind((HOST, PORT))
        s.listen()
        print(f"[Server] Listening for secure connections on {HOST}:{PORT}...", flush=True)
        
        conn, addr = s.accept()
        with conn:
            print(f"[Server] Connection established from {addr}. Initiating Hybrid Handshake...", flush=True)

            # 1. KEM: Generate Kyber Keypair (Lattice-based)
            print("[Server] Phase 1: Generating Post-Quantum KEM Keys (Kyber-512)...", flush=True)
            kyber_pk, kyber_sk_ctx, server_kem = generate_kyber_keypair()
            time.sleep(STEP_PAUSE)

            # 2. IDENTITY: Generate RSA Keypair (Classical)
            print("[Server] Phase 2: Generating Classical Identity (RSA-2048)...", flush=True)
            rsa_sk = generate_rsa_identity()

            # 3. IDENTITY: Generate Dilithium Keypair (Post-Quantum)
            print("[Server] Phase 3: Generating Post-Quantum Identity (Dilithium3)...", flush=True)
            dil_pk, dil_sk = generate_dilithium_identity()

            # 4. CERTIFICATE: Create and Dual-Sign
            print("[Server] Phase 4: Constructing Hybrid Certificate (Dual Signature)...", flush=True)
            
            # Pass all keys to the constructor to create the bound identity
            cert = HybridCertificate(
                server_id="Server_Node_Alpha", 
                kyber_pk=kyber_pk, 
                rsa_sk=rsa_sk, 
                dilithium_sk=dil_sk, 
                dilithium_pk=dil_pk
            )
            
            # Serialize to PEM format
            pem_bytes = cert.to_pem()
            
            # Save physical copy for inspection
            print("[Server] Archiving certificate to 'server_cert.pem'...", flush=True)
            with open("server_cert.pem", "wb") as f:
                f.write(pem_bytes)

            # 5. Send Certificate
            print(f"[Server] Transmitting Hybrid Certificate ({len(pem_bytes)} bytes)...", flush=True)
            send_message(conn, pem_bytes)

            # --- Proceed with Kyber Key Encapsulation ---
            print("[Server] Waiting for encapsulated ciphertext...", flush=True)
            ciphertext = receive_message(conn)
            
            print("[Server] Waiting for KDF salt...", flush=True)
            salt = receive_message(conn)
            
            # Decapsulate to get the shared secret
            # Note: server_kem is the liboqs object maintained from generation
            shared_secret = kyber_decapsulate(server_kem, ciphertext)
            print(f"[Server] Quantum shared secret recovered ({len(shared_secret)} bytes).", flush=True)
            
            # Derive the final session key
            aesgcm = derive_aes_key(shared_secret, salt)
            
            # Start the secure chat loop
            run_chat_loop(conn, aesgcm, "Server", False)

if __name__ == "__main__":
    main()