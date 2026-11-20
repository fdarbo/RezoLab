#!/bin/bash
# RézoLab — lanceur macOS (double-clic dans le Finder). Demande le mot de passe administrateur.
HERE="$(cd "$(dirname "$0")" && pwd)"
echo "RézoLab a besoin des droits administrateur pour capturer le réseau."
( sleep 4; open "http://127.0.0.1:8420" ) &
exec sudo "$HERE/run.sh" "$@"
