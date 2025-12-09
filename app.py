import streamlit as st
import socket
import os
import time
import threading  # <--- NUEVO
import pandas as pd
from datetime import datetime
from typing import Optional

# Import core protocols
from protocol_pqc import (
    kyber_encapsulate, 
    derive_aes_key, 
    SALT_LENGTH, 
    NONCE_LENGTH, 
    HEADER_LENGTH
)
from hybrid_pki import HybridCertificate
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# Import the server logic to run it locally
import server_pqc 

# --- PAGE CONFIGURATION ---
st.set_page_config(
    page_title="PQC Hybrid Chat System",
    layout="wide",
    initial_sidebar_state="expanded"
)

# --- BACKGROUND SERVER LAUNCHER ---
# This verifies if the server is running. If not, it starts it in a background thread.
@st.cache_resource
def launch_background_server():
    print("Initializing Background Server Thread...")
    server_thread = threading.Thread(target=server_pqc.start_server_thread, daemon=True)
    server_thread.start()
    return server_thread

# Launch the server immediately when the app loads
launch_background_server()

# --- CUSTOM CSS ---
st.markdown("""
<style>
    .stTextInput > div > div > input {
        background-color: #0e1117;
        color: #00ff00;
        font-family: 'Courier New', monospace;
    }
    .dataframe {
        font-family: 'Courier New', monospace;
        font-size: 12px;
    }
</style>
""", unsafe_allow_html=True)

# SESSION STATE
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

# NETWORK HELPERS (Same as before)
def log_traffic(direction: str, packet_type: str, data_bytes: bytes, details: str = "") -> None:
    if data_bytes and len(data_bytes) > 0:
        hex_preview = data_bytes[:10].hex().upper() + "..." 
        size = len(data_bytes)
    else:
        hex_preview = "N/A"
        size = 0
    timestamp = datetime.now().strftime("%H:%M:%S.%f")[:-3]
    st.session_state.logs.append({
        "Time": timestamp, "Direction": direction, "Type": packet_type,
        "Size (Bytes)": size, "Hex Preview": hex_preview, "Details": details
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

def connect_to_local_server():
    """Connects to the background thread server on localhost."""
    try:
        HOST = '127.0.0.1' # Always Localhost for Cloud Demo
        PORT = 12345
        
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(2.0)
        s.connect((HOST, PORT))
        s.settimeout(None)
        
        st.session_state.socket = s
        
        # 1. Certificate
        status_text.text("Status: Receiving Hybrid Certificate...")
        progress_bar.progress(10)
        cert_data = receive_message_wrapper(s)
        log_traffic("RX (Internal)", "Hybrid Certificate (PEM)", cert_data, "RSA + Kyber + Dilithium")
        
        # 2. Verify
        status_text.text("Status: Verifying Signatures...")
        progress_bar.progress(30)
        time.sleep(0.2)
        cert = HybridCertificate.from_pem(cert_data)
        st.session_state.server_id = cert.server_id
        
        if cert.verify_signature():
            st.success("Identity Verified: RSA & Dilithium")
            log_traffic("CPU", "Validation", cert.dilithium_signature, "Dilithium3 Verified")
        else:
            st.error("Verification Failed")
            return

        # 3. Kyber
        status_text.text("Status: Encapsulating Secret (Kyber)...")
        progress_bar.progress(60)
        ciphertext, shared_secret = kyber_encapsulate(cert.kyber_pk)
        log_traffic("CPU", "KEM Generation", shared_secret, "Secret Generated")
        
        msg_len = len(ciphertext).to_bytes(HEADER_LENGTH, 'big')
        s.sendall(msg_len + ciphertext)
        log_traffic("TX (Internal)", "Kyber Ciphertext", ciphertext, "Sent to Server Thread")

        # 4. AES Setup
        status_text.text("Status: Deriving Keys...")
        progress_bar.progress(80)
        salt = os.urandom(SALT_LENGTH)
        msg_len_salt = len(salt).to_bytes(HEADER_LENGTH, 'big')
        s.sendall(msg_len_salt + salt)
        log_traffic("TX (Internal)", "KDF Salt", salt, "Sent Salt")
        
        st.session_state.aesgcm = derive_aes_key(shared_secret, salt)
        st.session_state.connected = True
        progress_bar.progress(100)
        status_text.text("Status: Tunnel Established.")
        time.sleep(0.5)
        st.rerun()
        
    except Exception as e:
        st.error(f"Connection Error (Ensure Server Thread is running): {e}")

# --- UI LAYOUT ---
st.title("Full Hybrid PQC System (Cloud Demo)")
st.caption(f"Architecture: Kyber-512 + Dilithium3 + RSA + AES-GCM (Running in Container)")

with st.sidebar:
    st.header("Connection")
    st.info("Server Status: Running (Background Thread)")
    if not st.session_state.connected:
        if st.button("Initialize Handshake"):
            status_text = st.empty()
            progress_bar = st.progress(0)
            connect_to_local_server()
    else:
        st.success(f"Connected to: {st.session_state.server_id}")
        if st.button("Terminate Connection"):
            if st.session_state.socket: st.session_state.socket.close()
            st.session_state.connected = False
            st.rerun()

    st.divider()
    st.markdown("### Cryptographic Suite")
    st.markdown("- **KEM:** Kyber-512")
    st.markdown("- **Sig L1:** RSA-2048")
    st.markdown("- **Sig L2:** Dilithium3")

col1, col2 = st.columns([2, 1])

with col1:
    st.subheader("Secure Channel")
    chat_container = st.container(height=400)
    with chat_container:
        for msg in st.session_state.messages:
            with st.chat_message(msg["role"]):
                st.markdown(msg["content"])
                st.caption(f"Ciphertext: {msg['encrypted_preview']}")

    if st.session_state.connected:
        prompt = st.chat_input("Type a message...")
        if prompt:
            st.session_state.messages.append({"role": "user", "content": prompt, "encrypted_preview": "AES[...]"})
            nonce = os.urandom(NONCE_LENGTH)
            ciphertext = st.session_state.aesgcm.encrypt(nonce, prompt.encode(), None)
            final_packet = nonce + ciphertext
            msg_len = len(final_packet).to_bytes(HEADER_LENGTH, 'big')
            st.session_state.socket.sendall(msg_len + final_packet)
            log_traffic("TX", "AES Message", final_packet, f"Plain: {prompt}")
            st.rerun()

        if st.button("Check for Replies"):
            try:
                st.session_state.socket.settimeout(0.1)
                packet = receive_message_wrapper(st.session_state.socket)
                if packet:
                    nonce, cipher = packet[:NONCE_LENGTH], packet[NONCE_LENGTH:]
                    plaintext = st.session_state.aesgcm.decrypt(nonce, cipher, None).decode()
                    st.session_state.messages.append({"role": "assistant", "content": plaintext, "encrypted_preview": cipher[:8].hex().upper()})
                    log_traffic("RX", "AES Message", packet, f"Decrypted: {plaintext}")
                    st.rerun()
            except Exception:
                pass
            finally:
                if st.session_state.socket: st.session_state.socket.settimeout(None)

with col2:
    st.subheader("Traffic Analysis")
    if st.session_state.logs:
        df_logs = pd.DataFrame(st.session_state.logs)
        st.dataframe(df_logs[["Time", "Direction", "Type", "Hex Preview"]], use_container_width=True, hide_index=True, height=400)
        last_log = st.session_state.logs[-1]
        st.info(f"Packet Details:\n\n{last_log['Details']}")
    else:
        st.text("Waiting for traffic...")