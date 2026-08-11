#!/usr/bin/env bash
# install.sh — PhoneGG installer (Termux & Linux)
set -e

echo "========================================="
echo "        PhoneGG OSINT Toolkit"
echo "========================================="
echo ""

# Deteksi Termux vs Linux
if [ -d "/data/data/com.termux" ]; then
    echo "[*] Termux terdeteksi"
    pkg update -y && pkg upgrade -y
    pkg install -y python git
else
    echo "[*] Linux/PC terdeteksi"
    if command -v apt >/dev/null 2>&1; then
        sudo apt update && sudo apt install -y python3 python3-venv python3-pip git
    elif command -v dnf >/dev/null 2>&1; then
        sudo dnf install -y python3 python3-pip git
    elif command -v pacman >/dev/null 2>&1; then
        sudo pacman -S --noconfirm python python-pip git
    elif command -v yum >/dev/null 2>&1; then
        sudo yum install -y python3 python3-pip git
    else
        echo "[!] Package manager tidak dikenal. Install Python 3 & git manual."
    fi
fi

# Virtual environment
if python3 -m venv venv 2>/dev/null; then
    source venv/bin/activate
    echo "[*] Virtual environment aktif"
else
    echo "[!] venv gagal, lanjut tanpa virtualenv"
fi

python3 -m pip install --upgrade pip
python3 -m pip install -r requirements.txt

# Playwright browser
echo "[*] Install Playwright browser..."
python3 -m playwright install chromium 2>/dev/null || echo "[!] Playwright install skipped"

# .env
if [ ! -f ".env" ]; then
    cp .env.example .env
    echo "[!] File .env dibuat. Isi API_KEY, GOOGLE_API_KEY, GOOGLE_CX, HIBP_API_KEY."
fi

# Buat folder exports
mkdir -p exports

echo ""
echo "========================================="
echo "  Instalasi selesai!"
echo "========================================="
echo ""
echo "  Jalankan Web   : python3 app.py"
echo "  Web URL        : http://localhost:5000"
echo "  API Docs        : http://localhost:5000/apidocs/"
echo ""
