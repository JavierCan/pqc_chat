#!/bin/bash

echo "--- LIVE MODE: FULL HYBRID (KYBER + DILITHIUM + RSA) + WIRESHARK ---"

# 1. Open Wireshark immediately in capture mode (-k)
# We filter port 12345 to see only our Chat traffic
echo "[*] Opening Wireshark to capture quantum traffic..."
# Nota: Si wireshark pide sudo, podrías necesitar lanzarlo manual o configurar permisos
wireshark -k -i lo -f "tcp port 12345" -Y "tcp.port == 12345" &

echo "[*] Waiting for Wireshark to load..."
sleep 5

# 2. Launch the PQC SERVER
echo "[*] Starting Full Hybrid Server (Kyber + Dilithium + RSA)..."
gnome-terminal --title="SERVER (FULL HYBRID)" -- bash -c "python3 server_pqc.py; exec bash"

sleep 2

# 3. Launch the PQC CLIENT
echo "[*] Starting Full Hybrid Client..."
gnome-terminal --title="CLIENT (FULL HYBRID)" -- bash -c "python3 client_pqc.py; exec bash"

echo "---------------------------------------------------"
echo "  QUANTUM SYSTEM ACTIVE!"
echo "  1. In Wireshark you'll see the Hybrid Certificate transmission."
echo "  2. The handshake verifies DUAL SIGNATURES (RSA + Dilithium)."
echo "  3. Key Exchange uses Kyber-512 (Lattice-based)."
echo "---------------------------------------------------"