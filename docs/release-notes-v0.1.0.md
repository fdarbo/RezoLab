# RézoLab 0.1.0 — première version publique

Outil **pédagogique** de capture, d'analyse et de cartographie d'un réseau local, avec interface web animée (Python + Scapy).

## Nouveautés

- **Capture** par interface, filtres DNS / ICMP / DHCP / HTTP(S) / Telnet / FTP / SSH / TCP / UDP / ARP, IPv6 optionnel, import de fichiers `.pcap`.
- **Chemin animé** (client → routeur → Internet → serveur / DNS) et **diagramme de séquence** avec domaines distants (DNS appris et DNS inverse).
- **Flux TCP** : réassemblage, décodage HTTP (chunked, gzip) et Telnet, vues ASCII / hexadécimal, **détection des identifiants en clair** (HTTP Basic, cookies, formulaires, Telnet, FTP, POP3, IMAP, SMTP).
- **Cartographie** : découverte passive (trafic capturé, table des voisins) et active (balayage ARP + scan SYN), ports et services ouverts, type d'appareil deviné et modifiable, machines non confirmées grisées, zoom et déplacement.
- Interface claire/sombre, volets masquables, aide intégrée, relecture animée.
- Installateurs pour **Linux**, **macOS** et **Windows**.

## Installation

Téléchargez l'archive, puis : Linux/macOS `./install.sh` · Windows `install_windows.bat`. Détails dans le [README](../README.md).

## Limites connues

- Développé et testé sous **Linux** ; Windows et macOS « au mieux ».
- Pas de déchiffrement TLS/SSH ; l'UDP n'est pas conservé pour « Flux TCP » ; les types d'appareils sont des estimations.
- Les ports à l'écoute de votre propre machine ne sont lus automatiquement que sous Linux.

## Avertissement

N'utilisez RézoLab que sur des réseaux qui vous appartiennent ou avec une autorisation écrite. Fourni sans garantie, sous licence GPL-2.0-only.
