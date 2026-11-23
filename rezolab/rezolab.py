#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
# RézoLab — outil pédagogique de capture, de scan et de cartographie de réseau local
# Copyright (c) 2026 fdarbo
# Fourni « tel quel », sans garantie. À utiliser uniquement sur des réseaux qui vous appartiennent
# ou pour lesquels vous avez une autorisation. Voir LICENSE (GPL-2.0) et README.md.
# Capture live :  sudo bash scripts/run.sh   (ou : sudo python3 rezolab/rezolab.py)
__version__ = "0.1.0"

import base64, json, os, re, sys, threading, time, socket, zlib, ipaddress, concurrent.futures, subprocess, tempfile
import urllib.parse
from http.server import ThreadingHTTPServer, SimpleHTTPRequestHandler
from io import BytesIO

try:
    from scapy.all import AsyncSniffer, rdpcap, conf, get_if_list, get_if_addr, srp, sr, Ether, get_if_hwaddr
    from scapy.utils import ltoa, PcapReader
    from scapy.layers.inet import IP, TCP, UDP, ICMP
    from scapy.layers.inet6 import IPv6
    from scapy.layers.dns import DNS
    from scapy.layers.dhcp import BOOTP, DHCP
    from scapy.layers.l2 import ARP
    HAVE_SCAPY = True
    SCAPY_ERR = ""
except Exception:
    import traceback
    HAVE_SCAPY = False
    SCAPY_ERR = traceback.format_exc()

HOST, PORT = "127.0.0.1", 8420
BASE = os.path.dirname(os.path.abspath(__file__))
STATIC = os.path.join(BASE, "static")
MAX_PACKETS = 200_000            # plafond mémoire
MAX_PCAP_BYTES = 1024 * 1024 * 1024        # 1 Go (le fichier est lu en flux, pas chargé en mémoire)
MAX_PAY_TOTAL = 128 * 1024 * 1024    # octets applicatifs TCP gardés en mémoire (total)
MAX_PAY_FLOW = 1024 * 1024           # ... par flux
MAX_STREAM_RETURN = 512 * 1024       # octets renvoyés à l'UI pour un flux
MAX_DECOMP = 4 * 1024 * 1024
MAX_TEXT = 60_000                    # caractères max par corps HTTP affiché

class Capture:
    """Paquets résumés + charges utiles TCP (pour « Suivre le flux »)."""
    def __init__(self):
        self.packets = []
        self.pay = {}            # index paquet -> (seq TCP, octets)
        self.paysid = {}         # sid -> octets stockés
        self.paytotal = 0
        self.cut = set()         # sid dont des données n'ont pas pu être gardées
        self.full = False

    def add(self, s, pay):       # l'appelant tient STATE["lock"]
        if len(self.packets) >= MAX_PACKETS:
            self.full = True
            return
        idx = len(self.packets)
        s["i"] = idx
        self.packets.append(s)
        if pay and pay[1]:
            n, sid = len(pay[1]), s["sid"]
            used = self.paysid.get(sid, 0)
            if self.paytotal + n <= MAX_PAY_TOTAL and used + n <= MAX_PAY_FLOW:
                self.pay[idx] = pay
                self.paysid[sid] = used + n
                self.paytotal += n
            else:
                self.cut.add(sid)

STATE = {
    "running": False, "cap": Capture(), "lock": threading.Lock(),
    "ctl": threading.Lock(),     # sérialise start/stop/pcap
    "iface": None, "sniffer": None, "ipv6": False,
    "epoch": 0,                  # +1 à chaque clear/start/pcap -> l'UI se resynchronise
}

# ---------------------------------------------------------------- interfaces / contexte réseau
VIRTUAL = ("lo","tun","tap","wg","ppp","utun","tailscale","docker","veth","br-","virbr","vmnet","zt")

def _gw_for(iface):
    best = None
    try:
        for net, msk, gw, ifc, _a, metric in conf.route.routes:
            if net == 0 and msk == 0 and str(ifc) == str(iface) and gw not in ("0.0.0.0", None):
                if best is None or metric < best[0]: best = (metric, gw)
    except Exception: pass
    return best[1] if best else ""

def _ip_of(iface):
    try:
        ip = get_if_addr(iface)
        return "" if ip in ("0.0.0.0", None) else ip
    except Exception: return ""

def list_ifaces():
    out = []
    try:
        for n in get_if_list():
            if n == "lo": continue
            label = n
            try:
                o = conf.ifaces.dev_from_name(n)
                label = getattr(o, "description", None) or getattr(o, "name", None) or n
            except Exception:
                pass
            low = str(label).lower()
            virt = n.startswith(VIRTUAL) or any(k in low for k in ("virtual", "vmware", "vpn", "wireguard", "loopback", "hyper-v", "bluetooth", "tap-", "tunnel"))
            out.append({"name": n, "label": str(label), "ip": _ip_of(n), "gw": _gw_for(n), "virtual": virt})
    except Exception: pass
    return out

def auto_iface():
    """Interface réelle (pas VPN/docker) avec route par défaut, sinon celle de scapy."""
    ifs = list_ifaces()
    for i in ifs:
        if i["ip"] and i["gw"] and not i["virtual"]: return i["name"]
    for i in ifs:
        if i["ip"] and not i["virtual"]: return i["name"]
    try: return str(conf.route.route("0.0.0.0")[0])
    except Exception: return None

_CTX = {}
def network_context(iface=None):
    """(IP locale, passerelle) de l'interface donnée (ou automatique), cache 30 s."""
    if not HAVE_SCAPY: return "", ""
    iface = iface or auto_iface()
    hit = _CTX.get(iface)
    if hit and time.time() - hit[0] < 30: return hit[1]
    ip, gw = (_ip_of(iface), _gw_for(iface)) if iface else ("", "")
    _CTX[iface] = (time.time(), (ip, gw))
    return ip, gw

# ---------------------------------------------------------------- DNS inverse (noms des serveurs distants)
_RDNS = {}
_POOL = concurrent.futures.ThreadPoolExecutor(max_workers=8)

def _ptr(ip):
    try:
        a = ipaddress.ip_address(ip)
        if a.is_private or a.is_loopback or a.is_multicast or a.is_link_local or a.is_unspecified:
            return ""                                   # on ne résout que les IP publiques
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return ""

def rdns(ips):
    out, futs = {}, {}
    for ip in ips[:30]:
        if ip in _RDNS: out[ip] = _RDNS[ip]
        else: futs[ip] = _POOL.submit(_ptr, ip)
    for ip, f in futs.items():
        try: out[ip] = _RDNS[ip] = f.result(timeout=3)
        except Exception: out[ip] = ""                  # délai dépassé : non mis en cache
    return out

# ---------------------------------------------------------------- cartographie (passive + scan actif)
HLOCK = threading.Lock()
HOSTS, HV = {}, [0]                     # ip -> fiche ; HV = version (change à chaque nouveauté)
SCAN = {"running": False, "stop": False, "phase": "", "done": 0, "total": 0, "error": "", "cidr": ""}
COMMON_PORTS = [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995, 1723, 3306, 3389, 5900, 8080, 8443]
SERVER_PORTS = {21, 22, 25, 53, 80, 110, 143, 443, 445, 3306, 3389, 5900, 8080, 8443}

def _vendor(mac):
    try:
        if int(mac.split(":")[0], 16) & 2: return "MAC aléatoire"
        v = conf.manufdb._get_manuf(mac)
        return "" if not v or v.lower() == mac.lower() else str(v)[:28]
    except Exception:
        return ""

def touch_host(ip, mac=None, port=None, via=None, name=None):
    try: a = ipaddress.ip_address(ip)
    except ValueError: return
    if (not a.is_private or a.is_multicast or a.is_unspecified or a.is_loopback
            or a.is_link_local or ip.endswith(".255")): return
    with HLOCK:
        h = HOSTS.get(ip)
        ch = h is None
        if ch:
            if len(HOSTS) >= 2000: return
            h = HOSTS[ip] = {"ip": ip, "mac": "", "vendor": "", "name": "", "ports": {}, "via": set()}
        if mac and h["mac"] != mac.lower(): h["mac"], h["vendor"], ch = mac.lower(), _vendor(mac), True
        if port is not None and port not in h["ports"]: h["ports"][port] = 1; ch = True
        if name and h["name"] != name: h["name"], ch = name, True
        if via and via not in h["via"]: h["via"].add(via); ch = True
        if ch: HV[0] += 1

CONFIRMED = {"passif", "scan", "local", "actif"}      # sources qui prouvent qu'une machine est allumée

def read_neighbors(iface, path=None):
    """Voisins du noyau. REACHABLE/DELAY/PROBE = « actif » (confirmé) ; STALE = « voisins » (non confirmé, peut être éteinte)."""
    rows = None
    if path is None:
        try:
            r = subprocess.run(["ip", "-4", "neigh", "show"] + (["dev", iface] if iface else []),
                               capture_output=True, text=True, timeout=2)
            if r.returncode == 0: rows = r.stdout.splitlines()
        except Exception:
            rows = None
    if rows is not None:
        for ln in rows:
            c = ln.split()
            if "lladdr" in c and c[-1] not in ("FAILED", "INCOMPLETE"):
                touch_host(c[0], mac=c[c.index("lladdr") + 1],
                           via="actif" if c[-1] in ("REACHABLE", "DELAY", "PROBE") else "voisins")
        return len(rows)
    if path is None:                                          # macOS / Windows : « arp -a »
        n = 0
        try: out = subprocess.run(["arp", "-a"], capture_output=True, text=True, timeout=3).stdout
        except Exception: out = ""
        for ln in out.splitlines():
            m = re.search(r"(\d+\.\d+\.\d+\.\d+)\)?\s+(?:at\s+)?([0-9a-fA-F]{1,2}(?:[:-][0-9a-fA-F]{1,2}){5})", ln)
            if m:
                mac = ":".join(x.zfill(2) for x in re.split(r"[:-]", m.group(2))).lower()
                touch_host(m.group(1), mac=mac, via="voisins"); n += 1
        if n: return n
    try:
        with open(path or "/proc/net/arp") as f: rows = f.read().splitlines()[1:]
    except Exception:
        return 0
    n = 0
    for ln in rows:
        c = ln.split()
        if len(c) >= 6 and (not iface or c[5] == iface) and int(c[2], 16) & 2 and c[3] != "00:00:00:00:00:00":
            touch_host(c[0], mac=c[3], via="voisins"); n += 1
    return n

def local_listening_ports():
    ports = set()
    for f, loop in (("/proc/net/tcp", "0100007F"), ("/proc/net/tcp6", "00000000000000000000000001000000")):
        try:
            with open(f) as fh:
                lignes = fh.read().splitlines()[1:]
            for ln in lignes:
                c = ln.split()
                if len(c) > 3 and c[3] == "0A":                      # LISTEN
                    addr, port = c[1].split(":")
                    if addr != loop: ports.add(int(port, 16))
        except Exception:
            pass
    return ports

_LOC = {"t": 0.0}
def touch_local(iface, li):
    """Notre propre machine : toujours présente, avec ses ports à l'écoute."""
    if not li or time.time() - _LOC["t"] < 5: return
    _LOC["t"] = time.time()
    try: mac = get_if_hwaddr(iface)
    except Exception: mac = None
    touch_host(li, mac=mac, via="local")
    for p in local_listening_ports(): touch_host(li, port=p, via="local")

def parse_ports(txt):
    txt = (txt or "").strip().lower()
    if not txt or txt == "courants": return COMMON_PORTS
    out = []
    for tok in txt.replace(" ", "").split(","):
        if "-" in tok:
            a, b = tok.split("-", 1); out += range(int(a), int(b) + 1)
        elif tok: out.append(int(tok))
    out = sorted({p for p in out if 0 < p < 65536})[:2000]
    if not out: raise ValueError("ports invalides")
    return out

def note_packet(s):
    """Mode passif : une machine qui émet existe ; un SYN-ACK révèle un port ouvert ; l'ARP donne la MAC."""
    try:
        if s.get("smac"): touch_host(s["src"], mac=s["smac"], via="passif")
        elif s.get("src"): touch_host(s["src"], via="passif")
        if s.get("fl") == "SA" and s.get("sport"): touch_host(s["src"], port=s["sport"], via="passif")
    except Exception:
        pass

def hosts_snapshot(gw):
    with HLOCK:
        out = []
        for h in HOSTS.values():
            ports = sorted(h["ports"])
            kind = "router" if h["ip"] == gw else "server" if SERVER_PORTS & set(ports) else "pc"
            out.append({"ip": h["ip"], "mac": h["mac"], "vendor": h["vendor"], "name": h["name"],
                        "ports": ports, "via": sorted(h["via"]), "kind": kind,
                        "confirmed": bool(h["via"] & CONFIRMED)})
    return out

def _lan_cidr(iface):
    try:
        for net, msk, gw, ifc, _a, _m in conf.route.routes:
            if str(ifc) == str(iface) and net and msk and gw in ("0.0.0.0", None):
                n = ipaddress.ip_network(f"{ltoa(net)}/{bin(msk).count('1')}", strict=False)
                if n.is_private and not n.is_link_local and n.prefixlen >= 22: return n
    except Exception:
        pass
    ip = _ip_of(iface)
    return ipaddress.ip_network(ip + "/24", strict=False) if ip else None

def _lan_name(ip):
    try: return socket.gethostbyaddr(ip)[0]
    except Exception: return ""

def scan_worker(iface, net, ports):
    S = SCAN
    try:
        hosts = [str(x) for x in net.hosts()]
        my_ip = _ip_of(iface)
        try: my_mac = get_if_hwaddr(iface)
        except Exception: my_mac = None
        if my_ip: touch_host(my_ip, mac=my_mac, via="scan")
        S.update(phase="ARP", done=0, total=len(hosts) * 2, iface=iface, replies=0, note="")
        found, todo = set(), hosts
        for _rnd in (1, 2):                                       # 2 passes : les appareils Wi-Fi en veille répondent parfois au 2e
            nxt = []
            for i in range(0, len(todo), 64):
                if S["stop"]: break
                chunk = todo[i:i + 64]
                ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=chunk), iface=iface, timeout=2, verbose=0)
                got = set()
                for _s, r in ans:
                    got.add(r[ARP].psrc); found.add(r[ARP].psrc)
                    touch_host(r[ARP].psrc, mac=r[Ether].src, via="scan")
                nxt += [x for x in chunk if x not in got]
                S["done"] += len(chunk); S["replies"] = len(found)
            todo = nxt
            S["done"] = max(S["done"], len(hosts) if _rnd == 1 else len(hosts) * 2)
        read_neighbors(iface); touch_local(iface, my_ip)
        if len(found - {my_ip}) <= 1 and not S["stop"]:
            S["note"] = ("seule la passerelle répond à l'ARP : isolation des clients (Wi-Fi/invité) ou aucune autre machine ; "
                         "essayez « ip neigh » ou « sudo arp-scan -l » pour comparer")
        with HLOCK:
            live = [ip for ip in HOSTS if ipaddress.ip_address(ip) in net and ip != my_ip
                    and HOSTS[ip]["via"] & CONFIRMED]          # on ne scanne que les machines vivantes
        if not S["stop"]:
            S.update(phase="Noms", done=0, total=len(live))
            futs = {ip: _POOL.submit(_lan_name, ip) for ip in live}
            dl = time.time() + 6
            for ip, f in futs.items():
                try: nm = f.result(timeout=max(0.1, dl - time.time()))
                except Exception: nm = ""
                if nm: touch_host(ip, name=nm)
        S.update(phase="Ports", done=0, total=len(live))
        for n, ip in enumerate(live):                              # scan SYN des ports courants
            if S["stop"]: break
            ans, _ = sr(IP(dst=ip) / TCP(dport=ports, flags="S"), timeout=1.5 + len(ports) / 300, verbose=0, iface=iface)
            for snt, r in ans:
                if r.haslayer(TCP) and int(r[TCP].flags) & 0x12 == 0x12:
                    touch_host(ip, port=snt[TCP].dport, via="scan")
            S["done"] = n + 1
        S["phase"] = "Arrêté" if S["stop"] else "Terminé"
    except Exception as e:
        S["error"] = f"{e} (droits root requis ?)"
    finally:
        S["running"] = False

# ---------------------------------------------------------------- filtre BPF
HOST_RE = re.compile(r"^[A-Za-z0-9._:\-]{1,253}$")

def build_bpf(protocols, host, ipv6=False):
    proto_map = {
        "dns":  "port 53",
        "icmp": "icmp or icmp6" if ipv6 else "icmp",
        "dhcp": "udp port 67 or udp port 68 or udp port 546 or udp port 547",
        "http": "tcp port 80 or tcp port 443",   # inclut HTTPS
        "telnet": "tcp port 23",
        "ftp":  "tcp port 21 or tcp port 20",
        "ssh":  "tcp port 22",
        "tcp":  "tcp",
        "udp":  "udp",
        "arp":  "arp",
    }
    parts = [proto_map[p] for p in protocols if p in proto_map]
    if parts:
        bpf = " or ".join(f"({p})" for p in parts)
    else:
        bpf = "ip or ip6 or arp" if ipv6 else "ip or arp"
    if host:
        if not HOST_RE.match(host):
            raise ValueError("hôte invalide")
        bpf = f"({bpf}) and host {host}"
    if not ipv6:                                  # « tcp », « port 53 »... matchent aussi l'IPv6
        bpf = f"({bpf}) and not ip6"
    return bpf

# ---------------------------------------------------------------- analyse paquet
TCP_NAMES = {
    "S": "SYN (ouvert.)", "SA": "SYN-ACK (accept.)", "A": "ACK", "PA": "ACK+DATA",
    "FA": "FIN-ACK (fermeture)", "FPA": "FIN+PSH+ACK", "R": "RST (reset)", "RA": "RST-ACK",
}
FLAG_ORDER = "SFRPAUEC"

def _txt(x):
    if isinstance(x, bytes): return x.decode(errors="replace")
    return str(x)

def _iter_rr(field):
    """Itère sur les enregistrements DNS (liste en scapy>=2.5, chaîne de payloads avant)."""
    if field is None: return
    if isinstance(field, (list, tuple)):
        yield from field; return
    try:
        yield from field.iterpayloads()
    except Exception:
        return

def _first(field):
    if isinstance(field, (list, tuple)):
        return field[0] if field else None
    return field

def tcp_payload(pkt):
    """Données applicatives TCP, sans le bourrage Ethernet."""
    t = pkt[TCP]
    raw = bytes(t.payload)
    n = None
    if IP in pkt and pkt[IP].len:
        n = pkt[IP].len - (pkt[IP].ihl or 5) * 4 - (t.dataofs or 5) * 4
    elif IPv6 in pkt and pkt[IPv6].plen:
        n = pkt[IPv6].plen - (t.dataofs or 5) * 4
    return raw[:max(n, 0)] if n is not None else raw

def summarize(pkt):
    """Paquet scapy -> dict simple pour l'UI (clé privée _pay = charge utile TCP)."""
    domains = []
    src = dst = info = ""
    sport = dport = None
    extra = {}
    is_arp = ARP in pkt

    if is_arp: proto = "ARP"
    elif BOOTP in pkt: proto = "DHCP"
    elif DNS in pkt: proto = "DNS"
    elif ICMP in pkt: proto = "ICMP"
    elif IPv6 in pkt and pkt[IPv6].nh == 58: proto = "ICMP"
    elif UDP in pkt: proto = "UDP"
    elif TCP in pkt: proto = "TCP"
    else:
        s = pkt.summary()
        proto = s.split()[0] if s else "?"

    if is_arp:
        a = pkt[ARP]
        src, dst = a.psrc, a.pdst
        extra["smac"] = a.hwsrc
        if a.op == 1: info = f"ARP request: who-has {a.pdst}? tell {a.psrc}"
        elif a.op == 2: info = f"ARP reply: {a.psrc} is-at {a.hwsrc}"
        else: info = f"ARP op {a.op}"
    else:
        if IP in pkt: src, dst = pkt[IP].src, pkt[IP].dst
        elif IPv6 in pkt: src, dst = pkt[IPv6].src, pkt[IPv6].dst

        if TCP in pkt:
            sport, dport = pkt[TCP].sport, pkt[TCP].dport
            flags = str(pkt[TCP].flags)
            fl = "".join(c for c in FLAG_ORDER if c in flags)
            canon = TCP_NAMES.get(fl) or fl or flags
            info = f"TCP {canon} {sport} > {dport}"
            extra["fl"] = fl
            pl = tcp_payload(pkt)
            if pl:
                extra["_pay"] = (int(pkt[TCP].seq), pl)
        elif UDP in pkt:
            sport, dport = pkt[UDP].sport, pkt[UDP].dport
            info = f"UDP {sport} > {dport}"

        if DNS in pkt:
            d = pkt[DNS]
            q = _first(d.qd)
            qname = _txt(q.qname).rstrip(".") if q is not None and hasattr(q, "qname") else "?"
            info = f"DNS {'query' if d.qr == 0 else 'response'}: {qname}"
            for n, rr in enumerate(_iter_rr(d.an)):
                if n >= 20: break
                try:
                    if rr.type in (1, 28):      # A / AAAA : on garde le nom DEMANDÉ (pas le CNAME)
                        domains.append([qname if qname != "?" else _txt(rr.rrname).rstrip("."),
                                        _txt(rr.rdata)])
                except Exception:
                    pass
        elif BOOTP in pkt:
            msg = None
            if DHCP in pkt:
                msg = next((o[1] for o in pkt[DHCP].options
                            if isinstance(o, tuple) and o[0] == "message-type"), None)
            names = {1: "DISCOVER", 2: "OFFER", 3: "REQUEST", 4: "DECLINE", 5: "ACK",
                     6: "NAK", 7: "RELEASE", 8: "INFORM"}
            label = names.get(msg, str(msg).upper() if isinstance(msg, str) else "…")
            b = pkt[BOOTP]
            who = b.yiaddr if b.yiaddr and b.yiaddr != "0.0.0.0" else \
                  ":".join(f"{x:02x}" for x in bytes(b.chaddr)[:6])
            info = f"DHCP {label} for {who}"
        elif ICMP in pkt:
            it = pkt[ICMP].type
            info = ("ICMP echo-request (ping)" if it == 8 else
                    "ICMP echo-reply" if it == 0 else f"ICMP type {it}")
        elif IPv6 in pkt and pkt[IPv6].nh == 58:
            info = f"ICMPv6 {pkt[IPv6].payload.name}"

    sid_src = f"{src}:{sport}" if sport else src
    sid_dst = f"{dst}:{dport}" if dport else dst
    sid = "|".join(sorted([sid_src, sid_dst])) + "|" + ("ARP" if is_arp else "IP")
    return {"t": float(pkt.time), "src": src, "dst": dst, "proto": proto,
            "sport": sport, "dport": dport, "info": info, "len": len(pkt),
            "sid": sid, "domains": domains, "v6": IPv6 in pkt, **extra}

# ---------------------------------------------------------------- « Suivre le flux TCP »
def render_text(s):
    """Texte affichable : CRLF -> LF, caractères de contrôle -> '.'."""
    s = s.replace("\r\n", "\n").replace("\r", "")
    return "".join(ch if (ch in "\n\t" or (ch >= " " and ch not in "\x7f\ufffd")) else "."
                   for ch in s)

def printable_ratio(b):
    b = b[:2048]
    if not b: return 0.0
    return sum(1 for c in b if 32 <= c < 127 or c in (9, 10, 13)) / len(b)

def reassemble(entries):
    """entries: [(idx_paquet, seq, octets)] d'UN sens -> ([(idx, octets)], trou_détecté).
    Remet dans l'ordre des numéros de séquence, ignore les retransmissions."""
    if not entries: return [], False
    base = entries[0][1]
    def rel(x):
        r = (x - base) & 0xFFFFFFFF
        return r - (1 << 32) if r >= (1 << 31) else r
    segs = sorted(((rel(seq), idx, b) for idx, seq, b in entries), key=lambda t: (t[0], t[1]))
    out, nxt, gaps = [], segs[0][0], False
    for r, idx, b in segs:
        if r + len(b) <= nxt: continue                 # retransmission
        if r < nxt: b, r = b[nxt - r:], nxt            # chevauchement
        elif r > nxt: gaps = True                      # paquet manquant
        out.append((idx, b)); nxt = r + len(b)
    return out, gaps

CLEAR_PORTS = {80: "http", 8080: "http", 8000: "http", 8888: "http", 23: "telnet",
               21: "ftp", 25: "smtp", 587: "smtp", 110: "pop3", 143: "imap"}
HTTP_STARTS = (b"GET ", b"POST ", b"HEAD ", b"PUT ", b"DELETE ", b"OPTIONS ", b"PATCH ",
               b"CONNECT ", b"HTTP/1.")
PROTO_LABEL = {"http": "HTTP", "telnet": "Telnet", "ftp": "FTP", "smtp": "SMTP", "pop3": "POP3",
               "imap": "IMAP", "tls": "TLS", "ssh": "SSH", "text": "Texte", "binary": "Binaire"}
CLEAR_PROTOS = {"http", "telnet", "ftp", "smtp", "pop3", "imap", "text"}

def looks_tls(h):
    return len(h) >= 3 and h[0] in (0x14, 0x15, 0x16, 0x17) and h[1] == 3 and h[2] <= 4

def guess_proto(ports, c2s, s2c):
    for h in (c2s[:16], s2c[:16]):
        if looks_tls(h): return "tls"
        if h.startswith(HTTP_STARTS): return "http"
        if h.startswith(b"SSH-"): return "ssh"
    for p in ports:
        if p in CLEAR_PORTS: return CLEAR_PORTS[p]
    if printable_ratio(c2s) > 0.85 and printable_ratio(s2c) > 0.85: return "text"
    return "binary"

# -- Telnet : on rend les négociations IAC lisibles
TEL_CMD = {240: "SE", 241: "NOP", 242: "DM", 243: "BRK", 244: "IP", 245: "AO", 246: "AYT",
           247: "EC", 248: "EL", 249: "GA", 250: "SB", 251: "WILL", 252: "WONT", 253: "DO", 254: "DONT"}
TEL_OPT = {0: "BINARY", 1: "ECHO", 3: "SGA", 5: "STATUS", 24: "TTYPE", 31: "NAWS", 32: "TSPEED",
           33: "LFLOW", 34: "LINEMODE", 35: "XDISPLOC", 36: "ENVIRON", 39: "NEW-ENVIRON"}

def telnet_decode(b):
    b = b.replace(b"\r\x00", b"\r\n")
    out, text, i = [], bytearray(), 0
    def flush():
        if text: out.append(render_text(text.decode("utf-8", "replace"))); text.clear()
    while i < len(b):
        c = b[i]
        if c == 255 and i + 1 < len(b):
            cmd = b[i + 1]
            if cmd == 255: text.append(63); i += 2; continue          # 0xFF littéral
            if cmd in (251, 252, 253, 254) and i + 2 < len(b):
                flush(); out.append(f"⟨{TEL_CMD[cmd]} {TEL_OPT.get(b[i+2], b[i+2])}⟩"); i += 3; continue
            if cmd == 250:
                j = b.find(b"\xff\xf0", i + 2)
                j = len(b) if j < 0 else j
                opt = b[i + 2] if i + 2 < len(b) else 0
                flush(); out.append(f"⟨SB {TEL_OPT.get(opt, opt)} …⟩"); i = j + 2; continue
            flush(); out.append(f"⟨{TEL_CMD.get(cmd, cmd)}⟩"); i += 2; continue
        if c: text.append(c)
        i += 1
    flush()
    return "".join(out)

# -- HTTP : messages, chunked, gzip/deflate
def _parse_headers(head):
    lines = head.split("\r\n")
    h = {}
    for ln in lines[1:]:
        if ":" in ln:
            k, v = ln.split(":", 1); h[k.strip().lower()] = v.strip()
    return lines[0], h

def _dechunk(data, pos):
    out, start = bytearray(), pos
    while True:
        le = data.find(b"\r\n", pos)
        if le < 0: return bytes(out), pos - start, False
        try: size = int(data[pos:le].split(b";")[0].strip() or b"0", 16)
        except ValueError: return bytes(out), pos - start, False
        pos = le + 2
        if size == 0:
            if data[pos:pos + 2] == b"\r\n": return bytes(out), pos + 2 - start, True
            e = data.find(b"\r\n\r\n", pos)                              # trailers
            return (bytes(out), (e + 4 if e >= 0 else len(data)) - start, e >= 0)
        if pos + size > len(data):
            out += data[pos:]; return bytes(out), len(data) - start, False
        out += data[pos:pos + size]; pos += size + 2

def _body_text(body, hdrs):
    enc = hdrs.get("content-encoding", "").lower()
    try:
        if enc in ("gzip", "x-gzip"):
            body = zlib.decompressobj(16 + zlib.MAX_WBITS).decompress(body, MAX_DECOMP)
        elif enc == "deflate":
            try: body = zlib.decompressobj().decompress(body, MAX_DECOMP)
            except zlib.error: body = zlib.decompressobj(-zlib.MAX_WBITS).decompress(body, MAX_DECOMP)
        elif enc in ("br", "zstd"):
            return f"[corps compressé en {enc} : non décodé, {len(body)} octets]"
    except zlib.error:
        return f"[corps {enc} illisible ou incomplet, {len(body)} octets]"
    ctype = hdrs.get("content-type", "").lower()
    texty = ctype.startswith("text/") or any(k in ctype for k in
            ("json", "xml", "javascript", "x-www-form-urlencoded", "html"))
    if texty or (not ctype and printable_ratio(body) > 0.9):
        m = re.search(r"charset=([\w\-]+)", ctype)
        try: txt = body.decode(m.group(1) if m else "utf-8", "replace")
        except LookupError: txt = body.decode("utf-8", "replace")
        txt = render_text(txt)
        return txt[:MAX_TEXT] + ("\n… (tronqué)" if len(txt) > MAX_TEXT else "")
    return f"[corps binaire {ctype or 'type inconnu'}, {len(body)} octets]"

def _no_body_status(first):
    parts = first.split()
    if len(parts) >= 2 and parts[0].startswith("HTTP/") and parts[1].isdigit():
        c = int(parts[1]); return c < 200 or c in (204, 304)
    return False

def _http_messages(data, is_req):
    msgs, pos, n = [], 0, len(data)
    while pos < n and len(msgs) < 200:
        end = data.find(b"\r\n\r\n", pos)
        if end < 0:
            msgs.append(render_text(data[pos:].decode("latin-1")) + "\n… (en-têtes incomplets)")
            break
        head = data[pos:end].decode("latin-1")
        first, hdrs = _parse_headers(head)
        bstart, complete = end + 4, True
        te, cl = hdrs.get("transfer-encoding", "").lower(), hdrs.get("content-length", "")
        if "chunked" in te:
            body, used, complete = _dechunk(data, bstart); pos = bstart + used
        elif cl.isdigit():
            ln = int(cl); body = data[bstart:bstart + ln]; complete = len(body) == ln; pos = bstart + ln
        elif is_req or _no_body_status(first):
            body, pos = b"", bstart
        else:
            body, pos = data[bstart:], n
        txt = render_text(head)
        if body: txt += "\n\n" + _body_text(body, hdrs)
        if not complete: txt += "\n… (corps incomplet : paquet manquant ou capture arrêtée)"
        msgs.append(txt)
    return msgs

def http_decode(c2s, s2c):
    req, rsp = _http_messages(c2s, True), _http_messages(s2c, False)
    out = []
    for i in range(max(len(req), len(rsp))):
        if i < len(req): out.append({"d": 0, "t": req[i]})
        if i < len(rsp): out.append({"d": 1, "t": rsp[i]})
    return out

# -- Détection d'identifiants / secrets en clair
USER_P = re.compile(r"(?i)(login|user ?name|user)\s*:\s*$")
PASS_P = re.compile(r"(?i)(password|passwd|mot de passe)\s*:\s*$")

def _b64(x):
    try: return base64.b64decode(x + "=" * (-len(x) % 4)).decode("utf-8", "replace")
    except Exception: return None

def _telnet_secrets(dec):
    """Après une invite login:/password: du serveur, la ligne suivante tapée par le client."""
    out, tail, mode, buf = [], "", None, ""
    for d, t in dec:
        if d == 1:
            tail = (tail + t)[-80:]
            m = "pass" if PASS_P.search(tail) else "user" if USER_P.search(tail) else None
            if m: mode, buf, tail = m, "", ""
        elif mode:
            buf += re.sub(r"⟨[^⟩]*⟩", "", t)          # ignore les négociations Telnet (⟨WILL NAWS⟩…)
            if "\n" in buf:
                val = buf.split("\n")[0].strip()
                if val:
                    out.append({"kind": "Telnet : " + ("mot de passe" if mode == "pass" else "identifiant"),
                                "value": val, "raw": None, "d": 0})
                mode, buf = None, ""
    return out

def _text_secrets(proto, t0, t1):
    out = []
    def add(kind, value, raw=None, d=0): out.append({"kind": kind, "value": value, "raw": raw, "d": d})
    if proto == "http":
        for m in re.finditer(r"(?im)^(?:Proxy-)?Authorization:[ \t]*Basic[ \t]+([A-Za-z0-9+/=_\-]+)", t0):
            v = _b64(m.group(1)); add("HTTP Basic (identifiant:mot de passe)", v if v is not None else m.group(1), m.group(1))
        for m in re.finditer(r"(?im)^(?:Proxy-)?Authorization:[ \t]*(Bearer|Token|Digest)[ \t]+(.+?)[ \t\r]*$", t0):
            add("HTTP " + m.group(1), m.group(2)[:120], m.group(2)[:120])
        for m in re.finditer(r"(?im)^Cookie:[ \t]*(.+?)[ \t\r]*$", t0):
            add("Cookie envoyé", m.group(1)[:160], m.group(1)[:160])
        for m in re.finditer(r"(?im)^(?:X-API-Key|X-Auth-Token|Api-Key):[ \t]*(.+?)[ \t\r]*$", t0):
            add("Clé d'API", m.group(1)[:120], m.group(1)[:120])
        for m in re.finditer(r"(?i)\b(pass(?:word|wd)?|pwd|mdp|secret|token|api[_-]?key|login|user(?:name)?|email)=([^&\s\"']{1,80})", t0):
            add(f"Champ « {m.group(1)} »", urllib.parse.unquote_plus(m.group(2)), m.group(2))
        for m in re.finditer(r"(?im)^Set-Cookie:[ \t]*([^;\r\n]+)", t1):
            add("Cookie reçu", m.group(1)[:160], m.group(1)[:160], 1)
    elif proto in ("ftp", "pop3"):
        for m in re.finditer(r"(?im)^(USER|PASS)[ \t]+(.+?)[ \t\r]*$", t0):
            add("Identifiant" if m.group(1).upper() == "USER" else "Mot de passe", m.group(2), m.group(2))
    elif proto == "imap":
        for m in re.finditer(r"(?im)^\S+[ \t]+LOGIN[ \t]+(\S+)[ \t]+(\S+)", t0):
            add("IMAP : identifiant", m.group(1).strip('"'), m.group(1).strip('"'))
            add("IMAP : mot de passe", m.group(2).strip('"'), m.group(2).strip('"'))
    elif proto == "smtp":
        lines = t0.splitlines()
        for i, ln in enumerate(lines):
            u = ln.strip()
            m = re.match(r"(?i)AUTH PLAIN\s+(\S+)", u)
            if m:
                v = _b64(m.group(1))
                if v: add("SMTP AUTH PLAIN (identifiant:mot de passe)", ":".join(p for p in v.split("\0") if p), m.group(1))
            elif re.match(r"(?i)AUTH LOGIN\s*$", u):
                for j, lab in ((1, "identifiant"), (2, "mot de passe")):
                    if i + j < len(lines):
                        v = _b64(lines[i + j].strip())
                        if v: add(f"SMTP AUTH LOGIN : {lab}", v, lines[i + j].strip())
    return out

def find_secrets(proto, s0, s1, decoded):
    if proto == "telnet" and decoded:
        out = _telnet_secrets([(x["d"], x["t"]) for x in decoded])
    elif proto in ("http", "ftp", "pop3", "imap", "smtp"):
        out = _text_secrets(proto, s0.decode("latin-1"), s1.decode("latin-1"))
    else:
        out = []
    seen, res = set(), []
    for x in out:
        k = (x["kind"], x["value"])
        if k in seen: continue
        seen.add(k); res.append(x)
        if len(res) >= 50: break
    return res

def build_stream(frames, pay, cut):
    """frames: paquets (dict) du flux dans l'ordre de capture; pay: {idx: (seq, octets)}."""
    first = frames[0]
    client = None
    for p in frames:                                   # SYN sans ACK = client
        fl = p.get("fl", "")
        if "S" in fl and "A" not in fl: client = (p["src"], p["sport"]); break
    if client is None:
        for p in frames:                               # SYN-ACK = serveur
            fl = p.get("fl", "")
            if "S" in fl and "A" in fl: client = (p["dst"], p["dport"]); break
    a, b = (first["src"], first["sport"]), (first["dst"], first["dport"])
    if client is None:                                 # sinon : le port le plus haut est le client
        client = a if (a[1] or 0) >= (b[1] or 0) else b
    server = b if client == a else a
    ent = ([], [])
    for p in frames:
        if p["i"] in pay:
            d = 0 if (p["src"], p["sport"]) == client else 1
            ent[d].append((p["i"],) + pay[p["i"]])
    seg0, gap0 = reassemble(ent[0]); seg1, gap1 = reassemble(ent[1])
    s0, s1 = b"".join(x for _, x in seg0), b"".join(x for _, x in seg1)

    merged = sorted([(i, 0, x) for i, x in seg0] + [(i, 1, x) for i, x in seg1], key=lambda t: (t[0], t[1]))
    chunks = []                                        # fusionne les segments consécutifs d'un même sens
    for _, d, x in merged:
        if chunks and chunks[-1][0] == d: chunks[-1][1] += x
        else: chunks.append([d, bytearray(x)])
    budget, truncated, raw = MAX_STREAM_RETURN, False, []
    for d, x in chunks:
        if budget <= 0: truncated = True; break
        if len(x) > budget: x = x[:budget]; truncated = True
        budget -= len(x); raw.append((d, bytes(x)))

    proto = guess_proto({client[1], server[1]}, s0, s1)
    decoded = None
    if proto == "http": decoded = http_decode(s0, s1)
    elif proto == "telnet": decoded = [{"d": d, "t": telnet_decode(x)} for d, x in raw]

    secrets = find_secrets(proto, s0, s1, decoded)
    notes = []
    if proto in ("http", "telnet", "ftp", "pop3", "imap", "smtp"):
        notes.append("⚠ Flux EN CLAIR : contenu et identifiants lisibles par toute machine sur le chemin.")
    elif proto == "tls":
        notes.append("🔒 Flux chiffré (TLS) : seul le début de la négociation est visible, le contenu est illisible.")
    elif proto == "ssh":
        notes.append("🔒 SSH : seule la bannière est en clair, la suite est chiffrée.")
    elif not raw:
        notes.append("Aucune donnée applicative dans ce flux (handshake / ACK seulement).")
    if gap0 or gap1: notes.append("Des paquets manquent (capture incomplète) : le flux peut présenter des trous.")
    if truncated or cut: notes.append("Flux tronqué (limite de mémoire/affichage).")

    return {
        "flow": {"client": f"{client[0]}:{client[1]}", "server": f"{server[0]}:{server[1]}",
                 "proto": proto, "label": PROTO_LABEL.get(proto, proto), "clear": proto in CLEAR_PROTOS,
                 "bytes_c2s": len(s0), "bytes_s2c": len(s1), "note": " ".join(notes)},
        "chunks": [{"d": d, "n": len(x), "t": render_text(x.decode("utf-8", "replace")),
                    "b": base64.b64encode(x).decode()} for d, x in raw],
        "decoded": decoded,
        "secrets": secrets,
        "frames": frames[:5000],
    }

# ---------------------------------------------------------------- serveur HTTP
ALLOWED_HOSTS = {"127.0.0.1", "localhost", "[::1]"}

def _origin_ok(origin):
    if not origin: return True            # curl, navigation directe
    try:
        u = urllib.parse.urlparse(origin)
        return u.hostname in ("127.0.0.1", "localhost", "::1") and (u.port or 80) == PORT
    except Exception:
        return False

def _index_path():
    for d in (STATIC, BASE):
        p = os.path.join(d, "index.html")
        if os.path.isfile(p): return p
    return None

PCAP_MAGICS = {"d4c3b2a1", "a1b2c3d4", "4d3cb2a1", "a1b23c4d", "0a0d0d0a"}     # pcap (4 variantes) et pcapng

def ingest_pcap(path):
    """Analyse un fichier pcap/pcapng -> (code HTTP, dict). Remplace la capture courante en cas de succès."""
    cap, err = Capture(), None
    try:
        for p in iter_pcap(path):
            try: s = summarize(p)
            except Exception: continue
            cap.add(s, s.pop("_pay", None)); note_packet(s)
            if cap.full: break
    except Exception as e:
        err = str(e) or e.__class__.__name__
    if not cap.packets:
        return 400, {"error": err or "Aucun paquet exploitable dans ce fichier (format ou protocoles non pris en charge)."}
    with STATE["lock"]:
        STATE["cap"] = cap; STATE["epoch"] += 1
    out = {"ok": True, "count": len(cap.packets)}
    if cap.full: out["warning"] = f"limite de {MAX_PACKETS} paquets atteinte : la suite du fichier est ignorée"
    elif err: out["warning"] = "fichier incomplet ou corrompu, lecture arrêtée : " + err
    return 200, out

def expand_path(p):
    """Chemin saisi par l'utilisateur ; « ~ » désigne le dossier de l'utilisateur d'origine même sous sudo."""
    p = (p or "").strip().strip("\"'")
    if p.startswith("~"):
        home, su = None, os.environ.get("SUDO_USER")
        if su:
            try:
                import pwd; home = pwd.getpwnam(su).pw_dir
            except Exception:
                home = None
        p = (home + p[1:]) if home else os.path.expanduser(p)
    return p

def load_pcap_path(path):
    """Charge un pcap/pcapng par son chemin absolu (lu par RézoLab, indépendamment du navigateur)."""
    p = expand_path(path)
    if not p: return 400, {"error": "chemin vide"}
    if not os.path.isabs(p): return 400, {"error": "donnez le chemin complet, ex. /home/vous/capture.pcap"}
    if not os.path.isfile(p): return 404, {"error": f"fichier introuvable : {p}"}
    try:
        size = os.path.getsize(p)
        with open(p, "rb") as f: magic = f.read(4)
    except OSError as e:
        return 403, {"error": f"lecture impossible : {e.strerror or e}"}
    if size > MAX_PCAP_BYTES: return 413, {"error": f"fichier trop volumineux ({size // 1048576} Mo ; limite {MAX_PCAP_BYTES // 1048576} Mo)"}
    if magic.hex() not in PCAP_MAGICS:
        return 400, {"error": f"ce fichier n'est pas un pcap/pcapng (signature {magic.hex() or 'vide'})"}
    with STATE["ctl"]:
        if STATE["running"]: return 409, {"error": "arrêtez la capture avant d'importer un pcap"}
        code, out = ingest_pcap(p)
    out["name"] = os.path.basename(p)
    return code, out

def iter_pcap(path):
    """Lecture paquet par paquet (pcap et pcapng) : pas de chargement complet en mémoire."""
    with PcapReader(path) as r:
        for p in r:
            yield p

class Handler(SimpleHTTPRequestHandler):
    def __init__(self, *a, **kw):
        super().__init__(*a, directory=STATIC, **kw)   # translate_path standard = anti-traversal

    def log_message(self, *a): pass

    def _json(self, obj, code=200):
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def _guard(self):
        """Anti DNS-rebinding / CSRF : Host et Origin doivent être locaux."""
        host = self.headers.get("Host", "")
        h = host.rsplit(":", 1)[0] if not host.startswith("[") else host.split("]")[0] + "]"
        if h not in ALLOWED_HOSTS or not _origin_ok(self.headers.get("Origin")):
            self._json({"error": "forbidden"}, 403)
            return False
        return True

    def do_GET(self):
        if not self._guard(): return
        u = urllib.parse.urlparse(self.path)
        path, qs = u.path, urllib.parse.parse_qs(u.query)

        if path == "/api/status":
            with STATE["lock"]:
                running_if = STATE["iface"] if STATE["running"] else None
            want = running_if or (qs.get("iface", [""])[0] or None)
            li, gw = network_context(want)
            with STATE["lock"]:
                cap = STATE["cap"]
                return self._json({"running": STATE["running"], "count": len(cap.packets),
                                   "scapy": HAVE_SCAPY, "local_ip": li, "gateway": gw,
                                   "version": __version__, "iface": want or auto_iface(), "epoch": STATE["epoch"],
                                   "full": cap.full, "ipv6": STATE["ipv6"]})
        if path == "/api/ifaces":
            return self._json({"ifaces": list_ifaces(), "auto": auto_iface()})
        if path == "/api/rdns":
            return self._json(rdns([x for x in qs.get("ips", [""])[0].split(",") if x]))
        if path == "/api/hosts":
            with STATE["lock"]:
                rif = STATE["iface"] if STATE["running"] else None
            li, gw = network_context(rif or (qs.get("iface", [""])[0] or None))
            try: cv = int(qs.get("v", ["-1"])[0])
            except ValueError: cv = -1
            ifc = rif or (qs.get("iface", [""])[0] or None) or auto_iface()
            read_neighbors(ifc); touch_local(ifc, li)
            out = {"v": HV[0], "scan": dict(SCAN), "local_ip": li, "gateway": gw}
            if cv != HV[0]: out["hosts"] = hosts_snapshot(gw)
            return self._json(out)
        if path == "/api/packets":
            try: after = max(0, int(qs.get("after", ["0"])[0]))
            except ValueError: after = 0
            with STATE["lock"]:
                cap = STATE["cap"]
                total = len(cap.packets)
                after = min(after, total)
                pkts = cap.packets[after:]
                epoch = STATE["epoch"]
            return self._json({"packets": pkts, "total": total, "epoch": epoch})
        if path.startswith("/api/stream/"):
            try: idx = int(path.rsplit("/", 1)[-1])
            except ValueError: return self._json({"error": "bad index"}, 400)
            with STATE["lock"]:
                cap = STATE["cap"]
                if not 0 <= idx < len(cap.packets):
                    return self._json({"error": "not found"}, 404)
                sid = cap.packets[idx]["sid"]
                frames = [p for p in cap.packets if p["sid"] == sid]
                pay = {p["i"]: cap.pay[p["i"]] for p in frames if p["i"] in cap.pay}
                cut = sid in cap.cut
            try:
                return self._json(build_stream(frames, pay, cut))
            except Exception as e:
                return self._json({"error": f"décodage impossible : {e}"}, 500)
        if path.startswith("/api/"):
            return self._json({"error": "unknown"}, 404)

        if path in ("/", "/index.html", ""):
            ip = _index_path()
            if not ip: return self._json({"error": "index.html introuvable"}, 404)
            with open(ip, "rb") as f: body = f.read()
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers(); self.wfile.write(body); return
        if not os.path.isdir(STATIC):
            return self._json({"error": "not found"}, 404)
        return super().do_GET()

    def do_POST(self):
        if not self._guard(): return
        try: length = int(self.headers.get("Content-Length", 0))
        except ValueError: return self._json({"error": "bad length"}, 400)
        u = urllib.parse.urlparse(self.path)
        path, qs = u.path, urllib.parse.parse_qs(u.query)
        if path == "/api/pcap":                                    # import en flux : traité à part
            return self._pcap_upload(length, qs.get("name", ["upload.pcap"])[0])
        if length > 1 << 20:
            self._drain(length); return self._json({"error": "requête trop grosse"}, 413)
        body = self.rfile.read(length) if length else b""

        if path == "/api/start":  return self._start(body)
        if path == "/api/stop":   return self._stop()
        if path == "/api/clear":
            with STATE["lock"]:
                STATE["cap"] = Capture(); STATE["epoch"] += 1
            return self._json({"ok": True})
        if path == "/api/scan":   return self._scan_start(body)
        if path == "/api/scan/stop":
            SCAN["stop"] = True; return self._json({"ok": True})
        if path == "/api/hosts/clear":
            with HLOCK: HOSTS.clear(); HV[0] += 1
            return self._json({"ok": True})
        if path == "/api/pcap_path": return self._pcap_path(body)
        return self._json({"error": "unknown"}, 404)

    # -- scan actif (cartographie)
    def _scan_start(self, body):
        if not HAVE_SCAPY: return self._json({"error": "scapy not installed"}, 500)
        if SCAN["running"]: return self._json({"error": "scan déjà en cours"}, 409)
        try:
            opts = json.loads(body or b"{}")
            iface = opts.get("iface") or auto_iface()
            txt = str(opts.get("cidr", "")).strip()
            net = ipaddress.ip_network(txt, strict=False) if txt else _lan_cidr(iface)
            if net is None: return self._json({"error": "réseau introuvable (choisissez l'interface)"}, 400)
            if not net.is_private or net.num_addresses > 1024:
                return self._json({"error": "plage privée de 1024 adresses maximum (ex. 192.168.1.0/24)"}, 400)
            ports = parse_ports(opts.get("ports"))
        except (ValueError, TypeError) as e:
            return self._json({"error": f"requête invalide : {e}"}, 400)
        SCAN.update(running=True, stop=False, error="", phase="Démarrage", done=0, total=0, cidr=str(net))
        threading.Thread(target=scan_worker, args=(iface, net, ports), daemon=True).start()
        return self._json({"ok": True, "cidr": str(net)})

    # -- capture
    def _start(self, body):
        if not HAVE_SCAPY: return self._json({"error": "scapy not installed"}, 500)
        try:
            opts = json.loads(body or b"{}")
            ipv6 = bool(opts.get("ipv6", False))
            bpf = build_bpf(opts.get("protocols", []), str(opts.get("host", "")).strip(), ipv6)
        except (ValueError, TypeError) as e:
            return self._json({"error": f"requête invalide : {e}"}, 400)
        iface = opts.get("iface") or auto_iface()   # jamais l'interface par défaut de scapy (tun0...)

        def cb(pkt):
            try:
                s = summarize(pkt)
            except Exception as e:            # un paquet bizarre ne doit jamais tuer la capture
                print("[summarize]", e); return
            pay = s.pop("_pay", None)
            with STATE["lock"]:
                STATE["cap"].add(s, pay)
            note_packet(s)

        with STATE["ctl"]:
            self._stop_locked()
            with STATE["lock"]:
                STATE["cap"] = Capture(); STATE["epoch"] += 1
            try:
                sn = AsyncSniffer(iface=iface, filter=bpf, prn=cb, store=False)
                sn.start()
                time.sleep(0.3)
                if not sn.running:
                    try: sn.stop()
                    except Exception: pass
                    return self._json({"error": "capture impossible (filtre BPF invalide ou droits root/admin manquants ?)"}, 400)
            except Exception as e:
                return self._json({"error": f"capture impossible : {e}"}, 400)
            STATE["sniffer"], STATE["iface"], STATE["running"], STATE["ipv6"] = sn, iface, True, ipv6
        return self._json({"ok": True, "bpf": bpf})

    def _stop_locked(self):
        sn = STATE["sniffer"]
        if sn is not None:
            try:
                if sn.running: sn.stop()
            except Exception as e:
                print("[stop]", e)
        STATE["sniffer"], STATE["running"] = None, False

    def _stop(self):
        with STATE["ctl"]:
            self._stop_locked()
        return self._json({"ok": True})

    def _drain(self, length, cap=64 * 1024 * 1024):
        """Lit et jette le corps d'une requête refusée : sinon le navigateur voit une connexion coupée (AbortError)."""
        n = min(length, cap)
        while n > 0:
            c = self.rfile.read(min(1 << 20, n))
            if not c: break
            n -= len(c)

    def _pcap_path(self, body):
        """Chargement d'un pcap par son chemin : lu par RézoLab lui-même (contourne les limites du navigateur)."""
        if not HAVE_SCAPY: return self._json({"error": "scapy not installed"}, 500)
        try: path = str(json.loads(body or b"{}").get("path", ""))
        except (ValueError, TypeError, AttributeError): return self._json({"error": "requête invalide"}, 400)
        code, out = load_pcap_path(path)
        return self._json(out, code)

    def _pcap_upload(self, length, name):
        """Reçoit le fichier par morceaux dans un fichier temporaire, puis le lit paquet par paquet (pcap et pcapng)."""
        if not HAVE_SCAPY:
            self._drain(length); return self._json({"error": "scapy not installed"}, 500)
        if length <= 0: return self._json({"error": "fichier vide"}, 400)
        if length > MAX_PCAP_BYTES:
            self._drain(length)
            return self._json({"error": f"fichier trop volumineux ({length // 1048576} Mo ; limite {MAX_PCAP_BYTES // 1048576} Mo)"}, 413)
        with STATE["ctl"]:
            if STATE["running"]:
                self._drain(length); return self._json({"error": "arrêtez la capture avant d'importer un pcap"}, 409)
            fd, tmp = tempfile.mkstemp(suffix=".pcap")
            try:
                with os.fdopen(fd, "wb") as f:
                    left = length
                    while left > 0:
                        c = self.rfile.read(min(1 << 20, left))
                        if not c: break
                        f.write(c); left -= len(c)
                if left: return self._json({"error": "envoi interrompu avant la fin du fichier"}, 400)
                code, out = ingest_pcap(tmp)
            finally:
                try: os.unlink(tmp)
                except OSError: pass
        out["name"] = name
        return self._json(out, code)

# ---------------------------------------------------------------- main
if __name__ == "__main__":
    if not HAVE_SCAPY:
        print("!! Scapy indisponible dans CET interpréteur. Cause réelle :\n")
        print(SCAPY_ERR)
        print(f"-> Python utilisé : {sys.executable}")
        print(f"-> Installez dedans : {sys.executable} -m pip install scapy")
        sys.exit(1)
    if not _index_path():
        print("!! index.html introuvable (placez-le à côté du script ou dans static/)")
        sys.exit(1)

    li, gw = network_context()
    print(f"\n  RézoLab {__version__} — http://{HOST}:{PORT}\n  IP locale : {li or '?'}   (lancez en root/administrateur pour capturer)\n")

    if len(sys.argv) > 1:                                      # python rezolab.py capture.pcap : chargé au démarrage
        code, out = load_pcap_path(os.path.abspath(os.path.expanduser(sys.argv[1])))
        print(f"  Pcap {sys.argv[1]} : " + (f"{out['count']} paquets chargés" if code == 200 else "ERREUR — " + out.get("error", "")))
    server = ThreadingHTTPServer((HOST, PORT), Handler)
    server.daemon_threads = True
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[*] Ctrl+C reçu — arrêt de RézoLab …")
    finally:
        with STATE["ctl"]:
            try:
                sn = STATE["sniffer"]
                if sn is not None and sn.running: sn.stop()
            except Exception:
                pass
            STATE["running"] = False
        try: server.server_close()
        except Exception: pass
        print("[✓] RézoLab arrêté proprement.")
    sys.exit(0)
