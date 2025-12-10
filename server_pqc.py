import socket
import time
import os
import threading 
from typing import Any
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
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.exceptions import InvalidTag

HOST = '127.0.0.1'
PORT = 12345

def run_headless_chat(sock: socket.socket, aesgcm: AESGCM):

    print("[Server-Headless] Chat loop started.", flush=True)
    try:
        while True:
            # 1. Receive Data
            data = receive_message(sock)
            if not data: 
                print("[Server-Headless] Client disconnected.")
                break
            

            nonce, ciphertext = data[:NONCE_LENGTH], data[NONCE_LENGTH:]
            try:
                plaintext = aesgcm.decrypt(nonce, ciphertext, None).decode()
                print(f"[Server-Headless] Received: {plaintext}", flush=True)
                

                response_text = f"Server ACK: I received '{plaintext}' securely."
                
                
                reply_nonce = os.urandom(NONCE_LENGTH)
                reply_ciphertext = aesgcm.encrypt(reply_nonce, response_text.encode(), None)
                send_message(sock, reply_nonce + reply_ciphertext)
                
            except InvalidTag:
                print("[Server-Headless] Error: Decryption failed (Invalid Tag).")
            except Exception as e:
                print(f"[Server-Headless] Processing error: {e}")
                
    except Exception as e:
        print(f"[Server-Headless] Loop error: {e}")

def handle_client(conn: socket.socket, addr: tuple):
    """
    Handles the full PQC Handshake and Chat for a single client connection.
    This function runs inside its own thread.
    """
    try:
        print(f"[Server] Handshake starting for {addr}...", flush=True)

        # 1. KEM (Kyber)
        kyber_pk, kyber_sk_ctx, server_kem = generate_kyber_keypair()
        time.sleep(STEP_PAUSE)

        # 2. Identities (RSA + Dilithium)
        rsa_sk: rsa.RSAPrivateKey = generate_rsa_identity()
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


        ciphertext = receive_message(conn)
        salt = receive_message(conn)
        
        shared_secret = kyber_decapsulate(server_kem, ciphertext)
        aesgcm = derive_aes_key(shared_secret, salt)
        

        run_headless_chat(conn, aesgcm)
        
    except Exception as e:
        print(f"[Server-Handler] Error processing client {addr}: {e}")
    finally:

        conn.close()
        print(f"[Server] Client {addr} connection closed.", flush=True)

def start_server_thread():
    """
    Main server listener. It starts a new thread for every incoming connection.
    """
    print("--- STARTING CONCURRENT PQC SERVER ---", flush=True)

    try:
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        

        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        

        try:
            server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        except AttributeError:

            pass
            
        server_socket.bind((HOST, PORT))
        server_socket.listen(5) 
        print(f"[Server] Listening internally for concurrent connections on {HOST}:{PORT}...", flush=True)
        
        while True:
            conn, addr = server_socket.accept()
            print(f"[Server] Incoming connection from {addr}. Starting new handler thread.", flush=True)
            
            client_thread = threading.Thread(target=handle_client, args=(conn, addr), daemon=True)
            client_thread.start()
            
    except OSError as e:

        if "Address already in use" in str(e):
             print(f"[Server] Critical: {e}. Port {PORT} is still in TIME_WAIT state. Server thread failed to start.", flush=True)
             return 
        else:
             raise e
    except Exception as e:
        print(f"[Server] Critical error: {e}")

if __name__ == "__main__":
    start_server_thread()