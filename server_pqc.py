import socket
import time
import os
from protocol_pqc import (
    generate_kyber_keypair, 
    kyber_decapsulate, 
    derive_aes_key,
    send_message, 
    receive_message, 
    STEP_PAUSE,
    NONCE_LENGTH
)
from hybrid_pki import (
    generate_rsa_identity, 
    generate_dilithium_identity, 
    HybridCertificate
)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag

HOST = '127.0.0.1'
PORT = 12345

def run_headless_chat(sock, aesgcm):
    """
    Automated chat loop for the Cloud Demo.
    It receives messages and auto-replies.
    """
    print("[Server-Headless] Chat loop started.", flush=True)
    try:
        while True:
            # 1. Receive Data
            data = receive_message(sock)
            if not data: 
                print("[Server-Headless] Client disconnected.")
                break
            
            # 2. Decrypt
            nonce, ciphertext = data[:NONCE_LENGTH], data[NONCE_LENGTH:]
            try:
                plaintext = aesgcm.decrypt(nonce, ciphertext, None).decode()
                print(f"[Server-Headless] Received: {plaintext}", flush=True)
                
                # 3. Auto-Reply (Bot Mode)
                response_text = f"Server ACK: I received '{plaintext}' securely."
                
                # Encrypt Reply
                reply_nonce = os.urandom(NONCE_LENGTH)
                reply_ciphertext = aesgcm.encrypt(reply_nonce, response_text.encode(), None)
                send_message(sock, reply_nonce + reply_ciphertext)
                
            except InvalidTag:
                print("[Server-Headless] Error: Decryption failed (Invalid Tag).")
            except Exception as e:
                print(f"[Server-Headless] Processing error: {e}")
                
    except Exception as e:
        print(f"[Server-Headless] Loop error: {e}")

def start_server_thread():
    """
    Main function designed to run in a background thread.
    """
    print("--- STARTING BACKGROUND PQC SERVER ---", flush=True)

    # Use a try-except block to handle port already in use (common in Streamlit reloads)
    try:
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)        
        server_socket.bind((HOST, PORT))
        server_socket.listen(1)
        print(f"[Server] Listening internally on {HOST}:{PORT}...", flush=True)
        
        while True:
            # Accept loop to allow reconnections
            conn, addr = server_socket.accept()
            with conn:
                print(f"[Server] Internal connection from {addr}", flush=True)

                # 1. KEM (Kyber)
                kyber_pk, kyber_sk_ctx, server_kem = generate_kyber_keypair()
                time.sleep(0.5)

                # 2. Identities (RSA + Dilithium)
                rsa_sk = generate_rsa_identity()
                dil_pk, dil_sk = generate_dilithium_identity()

                # 3. Certificate
                cert = HybridCertificate(
                    server_id="Cloud_Server_Bot", 
                    kyber_pk=kyber_pk, 
                    rsa_sk=rsa_sk, 
                    dilithium_sk=dil_sk, 
                    dilithium_pk=dil_pk
                )
                pem_bytes = cert.to_pem()
                send_message(conn, pem_bytes)

                # 4. Handshake completion
                ciphertext = receive_message(conn)
                salt = receive_message(conn)
                
                shared_secret = kyber_decapsulate(server_kem, ciphertext)
                aesgcm = derive_aes_key(shared_secret, salt)
                
                # 5. Start Bot Chat
                run_headless_chat(conn, aesgcm)
                
    except OSError as e:
        print(f"[Server] Port error (likely already running): {e}")
    except Exception as e:
        print(f"[Server] Critical error: {e}")

if __name__ == "__main__":
    start_server_thread()