

Outil **pédagogique** pour comprendre un réseau local : capture de paquets, animation du trajet, diagramme de séquence, suivi de flux TCP (avec détection des identifiants en clair) et **cartographie** des machines du réseau.
Interface web locale (`http://127.0.0.1:8420`), serveur en Python + [Scapy](https://scapy.net).

> ⚠️ **Usage autorisé uniquement.** N'analysez et ne scannez que des réseaux qui vous appartiennent ou pour lesquels vous avez une autorisation écrite.

## Aperçu

*Captures réalisées avec des données de démonstration (adresses fictives, identifiants factices).*

**Chemin animé** — le trajet des paquets, avec leur type sur la flèche :

![Chemin animé](/home/fdarbo/Analyse_reseau/RezoLab/docs/01-chemin-anime.png "Chemin animé")

**Diagramme de séquence** — un échange par ligne, avec l'adresse ou le domaine distant :

![Diagramme de séquence](/home/fdarbo/Analyse_reseau/RezoLab/docs/02-diagramme-sequence.png)

**Flux TCP** — décodage HTTP et détection des identifiants en clair :

![Flux TCP et secrets](/home/fdarbo/Analyse_reseau/RezoLab/docs/03-flux-tcp-secrets.png)

**Cartographie** — machines du réseau, ports ouverts, type d'appareil deviné :

![Cartographie](/home/fdarbo/Analyse_reseau/RezoLab/docs/04-cartographie.png)

**Aide intégrée** — bouton « ? Aide », ouverture et fermeture en fondu :

![Aide](/home/fdarbo/Analyse_reseau/RezoLab/docs/05-aide.png)

## Installation

| Système     | Installer (une fois)                          | Lancer                                                                                            |
| ----------- | --------------------------------------------- | ------------------------------------------------------------------------------------------------- |
| **Linux**   | `bash scripts/install.sh` (sans sudo)         | `sudo bash scripts/run.sh`                                                                        |
| **macOS**   | `bash scripts/install.sh` (sans sudo)         | double-clic sur `scripts/RezoLab.command`, ou `sudo bash scripts/run.sh`                          |
| **Windows** | double-clic sur `scripts\install_windows.bat` | raccourci « RezoLab » du Bureau, ou `scripts\run_windows.bat` (demande les droits administrateur) |

Ouvrez ensuite <http://127.0.0.1:8420>.

> Les scripts fonctionnent depuis n'importe quel répertoire. On les appelle avec `bash` car les droits d'exécution sont souvent perdus au téléchargement (sinon : `chmod +x scripts/*.sh scripts/RezoLab.command`).

- **Linux** : Debian/Ubuntu : `sudo apt install python3 python3-venv python3-pip`. Pour les noms de fabricants (MAC) : `wireshark-common`.
- **macOS** : Python 3.8+ (Homebrew : `brew install python`). Autorisez Python dans le pare-feu / « Réseau local » si macOS le demande.
- **Windows** : Python 3.8+ (l'installateur propose `winget`) et **[Npcap](https://npcap.com)** (cochez « WinPcap API-compatible Mode »), indispensable à la capture.

Installation manuelle : `python3 -m venv .venv && .venv/bin/pip install -r requirements.txt && sudo .venv/bin/python rezolab/rezolab.py`.
Désinstallation : supprimer le dossier (et le raccourci du Bureau sous Windows).

## Fonctions

- **Capture** par interface, filtres DNS / ICMP / DHCP / HTTP(S) / Telnet / FTP / SSH / TCP / UDP / ARP, IPv6 optionnel.
- **Chemin animé** (client → routeur → Internet → serveur / DNS) et **diagramme de séquence** avec domaines distants.
- **Flux TCP** : décodage HTTP (chunked, gzip), Telnet ; surlignage des secrets en clair (HTTP Basic, cookies, FTP, POP3, IMAP, SMTP).
- **Cartographie** : découverte passive (trafic, table des voisins) et active (balayage ARP + scan SYN), ports ouverts, type d'appareil deviné et modifiable.
- Import de fichiers `.pcap`, relecture animée, thème clair/sombre, aide intégrée (bouton « ? Aide »).

## Conseils d'utilisation

- **Filtrer par protocole avant de capturer.** Cochez les protocoles qui vous intéressent dans le menu « Protocoles » *avant* de cliquer sur « Capturer » (ou avant de charger un pcap) : seuls les paquets utiles sont conservés, ce qui facilite leur repérage d'un point de vue pédagogique (par exemple DNS puis TCP pour suivre une navigation, Telnet ou FTP pour observer un échange en clair). Cochés avant la capture, les protocoles limitent la capture elle-même (filtre BPF) ; cochés après, ils masquent seulement l'affichage.
- **Compléter la cartographie avec `nmap -sn`.** Pendant que RézoLab tourne, lancez dans un terminal `nmap -sn 192.168.1.0/24` (adaptez la plage) : ce balayage, sans scan de ports, complète la carte. Les machines apparaissent grâce à la table des voisins du système et aux réponses ARP capturées (ne filtrez pas l'ARP). Avec les droits root, nmap utilise l'ARP, plus fiable en réseau local. Ne scannez que vos propres réseaux.

## Structure du dépôt

```
rezolab/rezolab.py    serveur, capture, décodeurs, scan et cartographie
rezolab/static/       interface web : index.html, app.css, app.js
tests/                tests automatiques (sans réseau ni root)
docs/                 captures d'écran, notes de version
scripts/              installateurs et lanceurs : install.sh, run.sh, RezoLab.command, install_windows.*, run_windows.bat
CHANGELOG.md  LICENSE  requirements.txt
```

## Tests

```bash
python -m unittest discover -s tests -v      # ou : python -m pytest
```

Ils couvrent les filtres, le réassemblage TCP, le décodage HTTP/Telnet, la détection d'identifiants, la cartographie et le serveur (protection contre les requêtes non locales, accès aux fichiers). Ils ne remplacent pas un essai de capture réelle.

## Limites

- **Import de pcap/pcapng** : jusqu'à 1 Go, lu en flux ; les 200 000 premiers paquets sont conservés. Le fichier doit être **lisible par votre navigateur** :
  un pcap créé avec `sudo` (tcpdump…) appartient souvent à root, donc `sudo chown $USER fichier.pcap`. Un navigateur Snap/Flatpak peut aussi ne pas accéder à certains dossiers (cas fréquent avec **Firefox Snap** sous Ubuntu). Dans ces cas, utilisez le bouton **📁 Chemin** : saisissez le chemin complet du fichier, RézoLab le lit lui-même, sans passer par le navigateur. On peut aussi le charger au lancement :
  `sudo bash scripts/run.sh /chemin/vers/capture.pcap`.

- Développé et testé sous **Linux**. Windows et macOS sont pris en charge « au mieux » : la table des voisins passe par `arp -a`, et les ports à l'écoute de votre propre machine ne sont lus automatiquement que sous Linux.

- Pas de déchiffrement TLS/SSH ; l'UDP n'est pas conservé pour « Flux TCP » ; les types d'appareils sont des estimations.

- Capturer sur une interface VPN (`tun0`) montre le trafic en clair ; sur l'interface physique, seulement le tunnel.

## Licence

[GPL-2.0-only](LICENSE) — compatible avec Scapy (GPL-2.0). Fourni « tel quel », sans aucune garantie.
Copyright © 2026 fdarbo.
