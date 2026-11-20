#!/usr/bin/env bash
# RézoLab — installateur Linux / macOS. À lancer SANS sudo : bash scripts/install.sh
set -u
HERE="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" && pwd)"
# Recherche de rezolab.py : à côté du script, dans ./rezolab, puis dans le dossier parent (scripts/ -> racine du projet)
APP=""; ROOT=""
for base in "$HERE" "$(dirname "$HERE")"; do
    for d in "$base" "$base/rezolab"; do
        if [ -z "$APP" ] && [ -f "$d/rezolab.py" ]; then APP="$d"; ROOT="$base"; fi
    done
done
[ -n "$APP" ] || { echo "[ÉCHEC] rezolab.py introuvable. Cherché dans : $HERE, $HERE/rezolab, $(dirname "$HERE"), $(dirname "$HERE")/rezolab"; exit 1; }
cd "$ROOT" || exit 1
REQ="requirements.txt"; [ -f "$REQ" ] || REQ="$APP/requirements.txt"
[ -f "$REQ" ] || { echo "[ÉCHEC] requirements.txt introuvable (cherché dans $ROOT et $APP)."; exit 1; }
GREEN='\033[0;32m'; RED='\033[0;31m'; YEL='\033[1;33m'; NC='\033[0m'
ok()   { echo -e "${GREEN}[OK]${NC} $1"; }
warn() { echo -e "${YEL}[ATTENTION]${NC} $1"; }
fail() { echo -e "${RED}[ÉCHEC]${NC} $1"; exit 1; }

[ "$(id -u)" -eq 0 ] && fail "Lancez l'installateur sans sudo (le venv doit appartenir à votre utilisateur)."
OS="$(uname -s)"
case "$OS" in Darwin|Linux) ok "système : $OS" ;; *) fail "Système non pris en charge : $OS (Windows : install_windows.bat)." ;; esac

# 1. Python 3.8+
pyok() { command -v python3 >/dev/null 2>&1 && python3 -c 'import sys; sys.exit(0 if sys.version_info >= (3,8) else 1)'; }
if ! pyok; then
    warn "Python 3.8+ introuvable."
    if [ "$OS" = "Darwin" ]; then
        if command -v brew >/dev/null 2>&1; then
            read -r -p "Installer Python avec Homebrew ? [O/n] " r
            case "${r:-O}" in [Oo]*|[Yy]*) brew install python || fail "Échec de brew install python." ;; esac
        else
            fail "Installez Python : https://www.python.org/downloads/macos/ ou Homebrew (https://brew.sh) puis « brew install python »."
        fi
    else
        fail "Installez Python 3 : Debian/Ubuntu : sudo apt install python3 python3-venv python3-pip — Fedora : sudo dnf install python3."
    fi
    pyok || fail "Python 3.8+ toujours introuvable (ouvrez un nouveau terminal puis relancez)."
fi
ok "$(python3 --version)"

# 2. venv + dépendances
if [ ! -x .venv/bin/python ]; then
    echo "[*] Création de l'environnement virtuel …"
    python3 -m venv .venv || fail "Création du venv impossible (Debian/Ubuntu : sudo apt install python3-venv)."
fi
.venv/bin/python -m pip install --quiet --upgrade pip || warn "mise à jour de pip ignorée"
.venv/bin/python -m pip install --quiet -r "$REQ" || fail "Installation de scapy impossible (réseau ?)."
.venv/bin/python -c "from scapy.all import AsyncSniffer, srp, sr, Ether, conf" || fail "scapy installé mais inutilisable."
ok "scapy $(.venv/bin/python -c 'import scapy; print(scapy.VERSION)') installé"

# 3. droits d'exécution et spécificités macOS
chmod +x scripts/*.sh scripts/RezoLab.command 2>/dev/null
if [ "$OS" = "Darwin" ]; then
    xattr -dr com.apple.quarantine . 2>/dev/null   # évite le blocage de RezoLab.command téléchargé
    ok "macOS : double-cliquez sur scripts/RezoLab.command (ou : sudo bash scripts/run.sh)"
    warn "Autorisez Python dans le pare-feu / « Réseau local » si macOS le demande."
else
    ok "Linux : lancez  sudo bash scripts/run.sh"
fi
echo
echo "Installation terminée. Ouvrez ensuite http://127.0.0.1:8420"
