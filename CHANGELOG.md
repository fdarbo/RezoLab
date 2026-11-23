# Journal des modifications

Format inspiré de [Keep a Changelog](https://keepachangelog.com/fr/1.1.0/) ; versionnage [SemVer](https://semver.org/lang/fr/).
Le numéro de version est défini à un seul endroit : `__version__` dans `rezolab.py`.

## [0.1.0] — première version publique
### Ajouté
- Capture par interface, filtres (DNS, ICMP, DHCP, HTTP/S, Telnet, FTP, SSH, TCP, UDP, ARP), IPv6 optionnel, import de `.pcap`.
- Chemin animé, diagramme de séquence, suivi de flux TCP (HTTP, Telnet), détection des identifiants en clair.
- Cartographie : découverte passive et active (ARP + SYN), ports et services, type d'appareil modifiable.
- Interface claire/sombre, volets masquables, aide intégrée ; installateurs Linux, macOS et Windows.
- Conseils d'utilisation (README et aide) : filtrer par protocole avant de capturer ; compléter la carte avec `nmap -sn`.
- Tests automatiques (`tests/`) et interface séparée en `static/index.html`, `app.css`, `app.js`.
### Corrigé avant publication
- Scripts d'installation et de lancement indépendants de leur emplacement : ils retrouvent `rezolab.py` à la racine ou dans `rezolab/`, et fonctionnent depuis `scripts/`.
- Telnet : l'identifiant affiché n'inclut plus les négociations (`WILL NAWS`…) envoyées avant la saisie.
- Pcap capturé sur une autre machine : l'IP du poste et la passerelle sont déduites du fichier (badge « IP · GW » cliquable pour les corriger) ;
  les diagrammes affichent de nouveau le flux client → serveur.
- Import de pcap : bouton « 📁 Chemin » et lancement `rezolab.py fichier.pcap` (lecture par RézoLab, utile quand le navigateur — Firefox Snap — ne peut pas lire le fichier) ;
  envoi en flux (jusqu'à 1 Go, lecture paquet par paquet), diagnostic d'un fichier illisible par le navigateur, refus propres côté serveur ;
  retour visuel pendant l'analyse, lecture animée automatique, messages d'erreur explicites
  (fichier sans paquet exploitable, paquets masqués par les filtres).
- Cartographie : carte adaptée au format du panneau ; diagramme de séquence : bulles et textes ne se chevauchent plus.
