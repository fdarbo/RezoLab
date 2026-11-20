#!/usr/bin/env bash
# RézoLab — lanceur avec vérification de l'environnement (Linux / macOS)
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

VENV=".venv"
PY="$VENV/bin/python"        # Windows : utilisez run_windows.bat
GREEN='\033[0;32m'; RED='\033[0;31m'; YEL='\033[1;33m'; NC='\033[0m'

ok()   { echo -e "${GREEN}[OK]${NC} $1"; }
fail() { echo -e "${RED}[ÉCHEC]${NC} $1"; exit 1; }
warn() { echo -e "${YEL}[ATTENTION]${NC} $1"; }

# 1. Python disponible ?
command -v python3 >/dev/null 2>&1 || fail "python3 introuvable. Installez Python 3.8+ (voir install.sh)."
ok "python3 : $(python3 --version)"

# 2. venv : création si absent, sinon vérification qu'il est valide
if [ ! -x "$PY" ]; then
    echo "[*] Création du venv dans $VENV …"
    python3 -m venv "$VENV" || fail "Impossible de créer le venv (paquet python3-venv requis sur Debian/Ubuntu)."
fi
"$PY" --version >/dev/null 2>&1 || fail "Venv invalide ($VENV). Supprimez-le : rm -rf $VENV puis relancez."
ok "venv valide : $("$PY" --version)"

# 3. pip présent dans le venv ?
if ! "$PY" -m pip --version >/dev/null 2>&1; then
    echo "[*] Installation de pip dans le venv …"
    "$PY" -m ensurepip --upgrade >/dev/null 2>&1 || fail "pip manquant dans le venv."
fi
ok "pip : $("$PY" -m pip --version | cut -d' ' -f1-2)"

# 4. Dépendances : installation automatique si absente
echo "[*] Vérification des dépendances …"
if ! "$PY" -c "import scapy" 2>/dev/null; then
    warn "scapy absent de ce venv -> installation"
    "$PY" -m pip install --quiet --upgrade pip || true
    [ -f "$REQ" ] || fail "requirements.txt introuvable (cherché dans $ROOT et $APP)."
    "$PY" -m pip install --quiet -r "$REQ" || fail "Échec de l'installation de scapy."
fi
ok "scapy importable dans le venv ($("$PY" -c 'import scapy; print(scapy.VERSION)'))"

# Vérification fine des éléments scapy utilisés par RézoLab (capture, scan, cartographie)
"$PY" - <<'PYEOF' || fail "Un module scapy requis est manquant (voir erreur ci-dessus)."
from scapy.all import AsyncSniffer, rdpcap, conf, srp, sr, Ether, get_if_list, get_if_addr, get_if_hwaddr
from scapy.utils import ltoa
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.inet6 import IPv6
from scapy.layers.dns import DNS
from scapy.layers.dhcp import BOOTP, DHCP
from scapy.layers.l2 import ARP
PYEOF
ok "tous les modules scapy requis sont présents"

# 5. Droits : la capture réelle et le scan exigent root
if [ "$(id -u)" -ne 0 ]; then
    warn "pas root : la capture LIVE et le scan risquent d'échouer."
    warn "recommandé : sudo bash $0 — l'app se lancera quand même, et les pcaps fonctionnent sans root."
fi

# 6. Port libre ? (ss sous Linux, lsof sous macOS)
if { command -v ss >/dev/null 2>&1 && ss -tln | grep -q ':8420 '; } || \
   { command -v lsof >/dev/null 2>&1 && lsof -iTCP:8420 -sTCP:LISTEN >/dev/null 2>&1; }; then
    warn "le port 8420 est déjà occupé (instance déjà lancée ?) -> http://127.0.0.1:8420"
fi

# 7. Lancement
echo -e "${GREEN}[✓]${NC} Environnement prêt — lancement de RézoLab …"
exec "$PY" "$APP/rezolab.py" "$@"
