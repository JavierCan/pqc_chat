import streamlit as st
import socket
import os
import time
import pandas as pd
from datetime import datetime
from typing import Optional

# Import core cryptographic protocols
from protocol_pqc import (
    kyber_encapsulate, 
    derive_aes_key, 
    SALT_LENGTH, 
    NONCE_LENGTH, 
    HEADER_LENGTH
)
from hybrid_pki import HybridCertificate
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# --- PAGE CONFIGURATION ---
st.set_page_config(
    page_title="PQC Hybrid Chat System",
    layout="wide",
    initial_sidebar_state="expanded"
)

# --- CUSTOM CSS (Professional Terminal Style) ---
st.markdown("""
<style>
    /* Monospaced font for inputs to simulate terminal entry */
    .stTextInput > div > div > input {
        background-color: #0e1117;
        color: #00ff00;
        font-family: 'Courier New', monospace;
    }
    /* Standardize dataframe font */
    .dataframe {
        font-family: 'Courier New', monospace;
        font-size: 12px;
    }
</style>
""", unsafe_allow_html=True)

# SESSION STATE INITIALIZATION
if "socket" not in st.session_state:
    st.session_state.socket = None
if "connected" not in st.session_state:
    st.session_state.connected = False
if "messages" not in st.session_state:
    st.session_state.messages = []
if "logs" not in st.session_state:
    st.session_state.logs = [] 
if "aesgcm" not in st.session_state:
    st.session_state.aesgcm = None
if "server_id" not in st.session_state:
    st.session_state.server_id = "Unknown"

# NETWORK HELPER FUNCTIONS

def log_traffic(direction: str, packet_type: str, data_bytes: bytes, details: str = "") -> None:
    """
    Logs network events to the session state table.
    """
    if data_bytes and len(data_bytes) > 0:
        # Show first 8 bytes in Hex uppercase
        hex_preview = data_bytes[:10].hex().upper() + "..." 
        size = len(data_bytes)
    else:
        hex_preview = "N/A"
        size = 0

    timestamp = datetime.now().strftime("%H:%M:%S.%f")[:-3]
    
    st.session_state.logs.append({
        "Time": timestamp,
        "Direction": direction,
        "Type": packet_type,
        "Size (Bytes)": size,
        "Hex Preview": hex_preview,
        "Details": details
    })

def receive_bytes(sock: socket.socket, num_bytes: int) -> Optional[bytes]:
    data = bytearray()
    while len(data) < num_bytes:
        try:
            packet = sock.recv(num_bytes - len(data))
            if not packet: return None
            data.extend(packet)
        except socket.error:
            return None
    return bytes(data)

def receive_message_wrapper(sock: socket.socket) -> Optional[bytes]:
    try:
        len_bytes = receive_bytes(sock, HEADER_LENGTH)
        if not len_bytes: return None
        msg_len = int.from_bytes(len_bytes, 'big')
        
        data = receive_bytes(sock, msg_len)
        return data
    except Exception:
        return None

def connect_to_server():
    try:
        HOST = '127.0.0.1'
        PORT = 12345
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((HOST, PORT))
        st.session_state.socket = s
        
        # --- STEP 1: Receive Hybrid Certificate ---
        status_text.text("Status: Receiving Hybrid Certificate...")
        progress_bar.progress(10)
        
        cert_data = receive_message_wrapper(s)
        log_traffic(
            direction="RX (Inbound)", 
            packet_type="Hybrid Certificate (PEM)", 
            data_bytes=cert_data, 
            details="Payload: RSA_PK + Kyber_PK + Dilithium_PK + Signatures"
        )
        
        # --- STEP 2: Verify Dual Signatures ---
        status_text.text("Status: Verifying Dual Signatures (RSA + Dilithium)...")
        progress_bar.progress(30)
        time.sleep(0.5) 
        
        # Parse PEM
        cert = HybridCertificate.from_pem(cert_data)
        st.session_state.server_id = cert.server_id
        
        if cert.verify_signature():
            st.success("Identity Verified: RSA & Dilithium")
            
            # Log the actual signature to show calculation occurred
            log_traffic(
                direction="INTERNAL (CPU)", 
                packet_type="Crypto Validation", 
                data_bytes=cert.dilithium_signature, 
                details="Dilithium3 Signature Verification Successful"
            )
        else:
            st.error("Signature Verification Failed. Connection Aborted.")
            s.close()
            return

        # --- STEP 3: Kyber Encapsulation ---
        status_text.text("Status: Encapsulating Secret (Kyber-512)...")
        progress_bar.progress(60)
        time.sleep(0.5)
        
        ciphertext, shared_secret = kyber_encapsulate(cert.kyber_pk)
        
        log_traffic(
            direction="INTERNAL (CPU)", 
            packet_type="KEM Generation", 
            data_bytes=shared_secret, 
            details="Quantum Shared Secret Generated"
        )
        
        # Send Ciphertext
        msg_len = len(ciphertext).to_bytes(HEADER_LENGTH, 'big')
        s.sendall(msg_len + ciphertext)
        
        log_traffic(
            direction="TX (Outbound)", 
            packet_type="Kyber Ciphertext", 
            data_bytes=ciphertext, 
            details="Encapsulated Secret sent to Server"
        )

        # --- STEP 4: Key Derivation (AES) ---
        status_text.text("Status: Deriving AES-256 GCM Keys...")
        progress_bar.progress(80)
        
        salt = os.urandom(SALT_LENGTH)
        msg_len_salt = len(salt).to_bytes(HEADER_LENGTH, 'big')
        s.sendall(msg_len_salt + salt)
        
        log_traffic(
            direction="TX (Outbound)", 
            packet_type="KDF Salt", 
            data_bytes=salt, 
            details="Random Salt for PBKDF2"
        )
        
        # Finalize Session
        st.session_state.aesgcm = derive_aes_key(shared_secret, salt)
        st.session_state.connected = True
        
        progress_bar.progress(100)
        status_text.text("Status: Secure Post-Quantum Tunnel Established.")
        time.sleep(1)
        st.rerun()
        
    except Exception as e:
        st.error(f"Connection Error: {e}")

# --- UI LAYOUT ---

st.title("Hybrid PQC System")
st.caption(f"Architecture: Kyber-512 (KEM) + Dilithium3 (Auth) + RSA (Identity) + AES-GCM (Transport)")

# Sidebar: Connection Control
with st.sidebar:
    st.header("Network Status")
    if not st.session_state.connected:
        st.warning("Disconnected")
        if st.button("Initialize Handshake"):
            status_text = st.empty()
            progress_bar = st.progress(0)
            connect_to_server()
    else:
        st.success(f"Connected to: {st.session_state.server_id}")
        st.info("Protocol: AES-256-GCM")
        if st.button("Terminate Connection"):
            if st.session_state.socket:
                st.session_state.socket.close()
            st.session_state.connected = False
            st.rerun()

    st.divider()
    st.markdown("### Cryptographic Suite")
    st.markdown("- **KEM:** Kyber-512")
    st.markdown("- **Sig L1:** RSA-2048")
    st.markdown("- **Sig L2:** Dilithium3")

# Main Layout
col1, col2 = st.columns([2, 1])

# LEFT COLUMN: Chat Interface
with col1:
    st.subheader("Secure Channel")
    
    # Message History Container
    chat_container = st.container(height=400)
    with chat_container:
        for msg in st.session_state.messages:
            with st.chat_message(msg["role"]):
                st.markdown(msg["content"])
                st.caption(f"Ciphertext: {msg['encrypted_preview']}")

    # Chat Input
    if st.session_state.connected:
        prompt = st.chat_input("Type a message...")
        if prompt:
            # 1. Display User Message
            st.session_state.messages.append({
                "role": "user", 
                "content": prompt, 
                "encrypted_preview": "AES_GCM[...]"
            })
            
            # 2. Encrypt & Send
            nonce = os.urandom(NONCE_LENGTH)
            ciphertext = st.session_state.aesgcm.encrypt(nonce, prompt.encode(), None)
            
            final_packet = nonce + ciphertext
            msg_len = len(final_packet).to_bytes(HEADER_LENGTH, 'big')
            st.session_state.socket.sendall(msg_len + final_packet)
            
            log_traffic("TX", "AES Message", final_packet, f"Plaintext: {prompt}")
            st.rerun()

        # Polling Button (Manual Refresh)
        if st.button("Poll Messages"):
            try:
                st.session_state.socket.settimeout(0.1)
                packet = receive_message_wrapper(st.session_state.socket)
                if packet:
                    nonce, cipher = packet[:NONCE_LENGTH], packet[NONCE_LENGTH:]
                    plaintext = st.session_state.aesgcm.decrypt(nonce, cipher, None).decode()
                    
                    st.session_state.messages.append({
                        "role": "assistant", 
                        "content": plaintext, 
                        "encrypted_preview": cipher[:8].hex().upper()
                    })
                    log_traffic("RX", "AES Message", packet, f"Decrypted: {plaintext}")
                    st.rerun()
            except (socket.timeout, AttributeError):
                pass
            except Exception:
                pass
            finally:
                if st.session_state.socket:
                    st.session_state.socket.settimeout(None)

# RIGHT COLUMN: Traffic Analyzer
with col2:
    st.subheader("Traffic")
    st.markdown("Real-time packet inspection.")
    
    if st.session_state.logs:
        df_logs = pd.DataFrame(st.session_state.logs)
        
        # Display Dataframe
        st.dataframe(
            df_logs[["Time", "Direction", "Type", "Hex Preview"]],
            use_container_width=True,
            hide_index=True,
            height=400
        )
        
        # Detail View
        last_log = st.session_state.logs[-1]
        st.info(f"Packet Inspection:\n\nType: {last_log['Type']}\nDetails: {last_log['Details']}")
    else:
        st.text("No traffic captured yet.")



        