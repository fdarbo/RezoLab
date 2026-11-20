# SPDX-License-Identifier: GPL-2.0-only
"""Tests de RézoLab : ne nécessitent ni réseau, ni droits root, ni scapy.
Lancement :  python -m unittest discover -s tests -v   (ou : python -m pytest)"""
import base64, gzip, http.client, os, sys, tempfile, threading, types, unittest
from unittest import mock

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for _cand in (os.path.join(ROOT, "rezolab"), ROOT):             # rezolab/rezolab.py (organisation cible) ou rezolab.py à la racine
    if os.path.isfile(os.path.join(_cand, "rezolab.py")):
        sys.path.insert(0, _cand); break
else:
    raise SystemExit("rezolab.py introuvable")
import rezolab as rz


class Bpf(unittest.TestCase):
    def test_defaut_sans_ipv6(self):
        self.assertEqual(rz.build_bpf([], "", False), "(ip or arp) and not ip6")

    def test_defaut_avec_ipv6(self):
        self.assertEqual(rz.build_bpf([], "", True), "ip or ip6 or arp")

    def test_protocoles_ajoutes(self):
        b = rz.build_bpf(["telnet", "ftp", "ssh"], "", False)
        for p in ("tcp port 23", "tcp port 21", "tcp port 20", "tcp port 22"):
            self.assertIn(p, b)

    def test_hote_invalide_refuse(self):
        with self.assertRaises(ValueError):
            rz.build_bpf(["tcp"], "1.2.3.4; rm -rf /", False)

    def test_ports(self):
        self.assertEqual(rz.parse_ports("22,80,8000-8002"), [22, 80, 8000, 8001, 8002])
        self.assertEqual(rz.parse_ports(""), rz.COMMON_PORTS)
        with self.assertRaises(ValueError):
            rz.parse_ports("0,70000")


class Flux(unittest.TestCase):
    def test_reassemblage_desordre_et_retransmission(self):
        e = [(1, 103, b"def"), (2, 100, b"abc"), (3, 100, b"abc"), (4, 106, b"ghi")]
        segs, gaps = rz.reassemble(e)
        self.assertEqual(b"".join(b for _, b in segs), b"abcdefghi")
        self.assertFalse(gaps)

    def test_reassemblage_trou(self):
        _, gaps = rz.reassemble([(1, 100, b"abc"), (2, 200, b"xyz")])
        self.assertTrue(gaps)

    def test_http_chunked_gzip(self):
        body = gzip.compress("Bonjour é monde".encode())
        chunk = b"%x\r\n" % len(body) + body + b"\r\n0\r\n\r\n"
        rsp = (b"HTTP/1.1 200 OK\r\nContent-Type: text/plain; charset=utf-8\r\n"
               b"Content-Encoding: gzip\r\nTransfer-Encoding: chunked\r\n\r\n" + chunk)
        out = rz.http_decode(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n", rsp)
        self.assertEqual([m["d"] for m in out], [0, 1])
        self.assertIn("Bonjour é monde", out[1]["t"])

    def test_telnet_negociation_et_cr_nul(self):
        self.assertEqual(rz.telnet_decode(b"\xff\xfd\x01login: "), "⟨DO ECHO⟩login: ")
        self.assertEqual(rz.telnet_decode(b"pw\r\x00"), "pw\n")

    def test_detection_protocole(self):
        self.assertEqual(rz.guess_proto({1, 443}, b"\x16\x03\x01\x02", b""), "tls")
        self.assertEqual(rz.guess_proto({1, 8080}, b"GET / HTTP/1.1", b""), "http")
        self.assertEqual(rz.guess_proto({1, 23}, b"", b""), "telnet")
        self.assertEqual(rz.guess_proto({1, 2}, bytes(range(128, 200)), bytes(range(128, 200))), "binary")

    def _flux(self, c2s, s2c, port=80):
        C, S = ("10.0.0.2", 50000), ("10.0.0.9", port)
        def pk(i, a, b, fl, seq=None, data=b""):
            return {"i": i, "src": a[0], "sport": a[1], "dst": b[0], "dport": b[1], "fl": fl}, (seq, data)
        frames, pay = [], {}
        for i, (a, b, fl, seq, d) in enumerate([(C, S, "S", None, b""), (S, C, "SA", None, b""),
                                                (C, S, "PA", 1000, c2s), (S, C, "PA", 5000, s2c)]):
            f, p = pk(i, a, b, fl, seq, d); frames.append(f)
            if d: pay[i] = p
        return rz.build_stream(frames, pay, False)

    def test_flux_http_client_serveur(self):
        r = self._flux(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n", b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
        self.assertEqual(r["flow"]["label"], "HTTP")
        self.assertEqual(r["flow"]["client"], "10.0.0.2:50000")
        self.assertTrue(r["flow"]["clear"])


class Secrets(unittest.TestCase):
    def test_http(self):
        tok = base64.b64encode(b"alice:S3cret!").decode()
        req = (f"POST /l?token=abc HTTP/1.1\r\nAuthorization: Basic {tok}\r\nCookie: sid=XYZ\r\n\r\n"
               "user=bob&password=p%40ss+word").encode()
        v = {(s["kind"], s["value"]) for s in rz.find_secrets(
            "http", req, b"HTTP/1.1 200 OK\r\nSet-Cookie: s=1; Path=/\r\n\r\n", None)}
        self.assertIn(("HTTP Basic (identifiant:mot de passe)", "alice:S3cret!"), v)
        self.assertIn(("Cookie envoyé", "sid=XYZ"), v)
        self.assertIn(("Champ « password »", "p@ss word"), v)
        self.assertIn(("Cookie reçu", "s=1"), v)

    def test_telnet_echo_caractere_par_caractere(self):
        dec = [{"d": 1, "t": "login: "}, {"d": 0, "t": "r"}, {"d": 1, "t": "r"}, {"d": 0, "t": "\n"},
               {"d": 1, "t": "\nPassword: "}, {"d": 0, "t": "h"}, {"d": 0, "t": "unter2\n"}]
        v = [(s["kind"], s["value"]) for s in rz.find_secrets("telnet", b"", b"", dec)]
        self.assertEqual(v, [("Telnet : identifiant", "r"), ("Telnet : mot de passe", "hunter2")])

    def test_telnet_ignore_les_negociations(self):                  # régression : « ⟨WILL NAWS⟩…admin »
        neg = "⟨WILL NAWS⟩⟨WILL TSPEED⟩⟨WILL NEW-ENVIRON⟩⟨DO ECHO⟩"
        dec = [{"d": 1, "t": "User Access Verification\n\nUsername: "}, {"d": 0, "t": neg + "admin\n"},
               {"d": 1, "t": "Password: "}, {"d": 0, "t": "123456\n"}]
        v = [s["value"] for s in rz.find_secrets("telnet", b"", b"", dec)]
        self.assertEqual(v, ["admin", "123456"])

    def test_ftp(self):
        v = [s["value"] for s in rz.find_secrets("ftp", b"USER anon\r\nPASS guest@x\r\n", b"", None)]
        self.assertEqual(v, ["anon", "guest@x"])


class Cartographie(unittest.TestCase):
    def setUp(self):
        rz.HOSTS.clear()

    def test_filtres_adresses(self):
        for ip in ("8.8.8.8", "192.168.1.255", "224.0.0.1", "0.0.0.0", "169.254.1.1", "127.0.0.1", "pas-une-ip"):
            rz.touch_host(ip)
        self.assertEqual(rz.hosts_snapshot(""), [])

    def test_passif_et_confirmation(self):
        rz.note_packet({"src": "192.168.1.20", "fl": "SA", "sport": 443})
        rz.note_packet({"src": "192.168.1.1", "smac": "aa:bb:cc:00:11:22"})
        rz.touch_host("192.168.1.9", mac="3c:22:fb:01:02:03", via="voisins")
        h = {x["ip"]: x for x in rz.hosts_snapshot("192.168.1.1")}
        self.assertEqual(h["192.168.1.20"]["ports"], [443])
        self.assertEqual(h["192.168.1.20"]["kind"], "server")
        self.assertEqual(h["192.168.1.1"]["kind"], "router")
        self.assertTrue(h["192.168.1.20"]["confirmed"])
        self.assertFalse(h["192.168.1.9"]["confirmed"])          # cache ARP seul : non confirmé

    def test_proc_net_arp(self):
        with tempfile.NamedTemporaryFile("w", suffix=".arp", delete=False) as f:
            f.write("IP address HW type Flags HW address Mask Device\n"
                    "192.168.1.254 0x1 0x2 aa:bb:cc:00:11:22 * wlp2s0\n"
                    "192.168.1.40 0x1 0x0 00:00:00:00:00:00 * wlp2s0\n"
                    "10.8.0.5 0x1 0x2 de:ad:be:ef:00:01 * tun0\n")
        try:
            self.assertEqual(rz.read_neighbors("wlp2s0", f.name), 1)
        finally:
            os.unlink(f.name)

    def test_arp_a_macos_windows(self):
        sorties = {"macos": "? (192.168.1.1) at a:b:c:dd:ee:ff on en0 ifscope [ethernet]\n? (192.168.1.50) at (incomplete) on en0",
                   "windows": "Interface: 192.168.1.89 --- 0x5\n  192.168.1.254   3c-22-fb-01-02-03   dynamique\n  224.0.0.22   01-00-5e-00-00-16   statique"}
        for nom, sortie in sorties.items():
            rz.HOSTS.clear()
            faux = types.SimpleNamespace(stdout=sortie, returncode=1)
            with mock.patch.object(rz.subprocess, "run", return_value=faux):
                self.assertGreaterEqual(rz.read_neighbors(None), 1, nom)
            self.assertEqual(len(rz.hosts_snapshot("")), 1, nom)           # multicast et « incomplete » ignorés


class Serveur(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.srv = rz.ThreadingHTTPServer(("127.0.0.1", 0), rz.Handler)
        cls.port = cls.srv.server_address[1]
        threading.Thread(target=cls.srv.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown(); cls.srv.server_close()

    def get(self, path, host=None):
        c = http.client.HTTPConnection("127.0.0.1", self.port)
        c.request("GET", path, headers={"Host": host or f"127.0.0.1:{self.port}"})
        r = c.getresponse(); body = r.read(); c.close()
        return r.status, body

    def test_page_et_fichiers_statiques(self):
        st, body = self.get("/")
        self.assertEqual(st, 200); self.assertIn("RÉZO", body.decode())
        for f in ("/app.css", "/app.js"):
            self.assertEqual(self.get(f)[0], 200, f)

    def test_api_status_et_version(self):
        st, body = self.get("/api/status")
        self.assertEqual(st, 200); self.assertIn(rz.__version__, body.decode())

    def test_host_non_local_refuse(self):                       # protection contre le DNS rebinding
        self.assertEqual(self.get("/api/status", host="evil.example")[0], 403)

    def test_pas_de_sortie_du_dossier(self):
        self.assertEqual(self.get("/../rezolab.py")[0], 404)

    def test_api_hosts(self):
        self.assertEqual(self.get("/api/hosts?v=-1")[0], 200)


class ImportPcap(unittest.TestCase):
    """Envoi d'un pcap : lecture en flux, refus propres (le navigateur doit toujours recevoir une réponse)."""
    @classmethod
    def setUpClass(cls):
        cls.srv = rz.ThreadingHTTPServer(("127.0.0.1", 0), rz.Handler)
        cls.port = cls.srv.server_address[1]
        threading.Thread(target=cls.srv.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown(); cls.srv.server_close()

    def setUp(self):
        rz.STATE["running"] = False
        self.paquets = [{"t": float(i), "src": "10.0.0.2", "dst": "10.0.0.9", "proto": "TCP", "sport": 5000, "dport": 80,
                         "info": "x", "len": 60, "sid": "a|b|IP", "domains": [], "v6": False, "fl": "A"} for i in range(5)]
        self.patches = [mock.patch.object(rz, "HAVE_SCAPY", True), mock.patch.object(rz, "summarize", lambda p: dict(p)),
                        mock.patch.object(rz, "iter_pcap", lambda path: iter(self.paquets))]
        for m in self.patches: m.start()

    def tearDown(self):
        for m in self.patches: m.stop()

    def post(self, body, name="t.pcap"):
        c = http.client.HTTPConnection("127.0.0.1", self.port, timeout=20)
        c.request("POST", "/api/pcap?name=" + name, body=body,
                  headers={"Host": f"127.0.0.1:{self.port}", "Content-Type": "application/octet-stream"})
        r = c.getresponse(); data = r.read(); c.close()
        import json
        return r.status, json.loads(data)

    def test_import_ok(self):
        st, r = self.post(b"x" * 1000)
        self.assertEqual((st, r["count"]), (200, 5))
        self.assertEqual(len(rz.STATE["cap"].packets), 5)

    def test_gros_fichier_en_flux(self):                         # 30 Mo : pas de blocage ni de coupure
        st, r = self.post(b"x" * (30 * 1024 * 1024))
        self.assertEqual((st, r["count"]), (200, 5))

    def test_trop_gros_refuse_proprement(self):                  # le navigateur reçoit un 413, pas une coupure
        with mock.patch.object(rz, "MAX_PCAP_BYTES", 100):
            st, r = self.post(b"x" * 5000)
        self.assertEqual(st, 413); self.assertIn("volumineux", r["error"])

    def test_refuse_pendant_capture(self):
        rz.STATE["running"] = True
        st, r = self.post(b"x" * 100)
        self.assertEqual(st, 409); self.assertIn("arrêtez", r["error"])

    def test_fichier_sans_paquet(self):
        with mock.patch.object(rz, "iter_pcap", lambda path: iter([])):
            st, r = self.post(b"x" * 100)
        self.assertEqual(st, 400); self.assertIn("Aucun paquet", r["error"])

    def test_fichier_corrompu_garde_le_debut(self):
        def gen(path):
            yield self.paquets[0]; yield self.paquets[1]; raise ValueError("paquet tronqué")
        with mock.patch.object(rz, "iter_pcap", gen):
            st, r = self.post(b"x" * 100)
        self.assertEqual((st, r["count"]), (200, 2)); self.assertIn("incomplet", r["warning"])

    def test_corrompu_des_le_debut(self):
        def gen(path):
            raise ValueError("Not a supported capture file")
            yield
        with mock.patch.object(rz, "iter_pcap", gen):
            st, r = self.post(b"x" * 100)
        self.assertEqual(st, 400); self.assertIn("Not a supported", r["error"])


class PcapParChemin(ImportPcap):
    """Chargement par chemin (contourne le navigateur) : même comportement, avec ses propres refus."""
    def post_path(self, path):
        import json
        c = http.client.HTTPConnection("127.0.0.1", self.port, timeout=20)
        c.request("POST", "/api/pcap_path", body=json.dumps({"path": path}),
                  headers={"Host": f"127.0.0.1:{self.port}", "Content-Type": "application/json"})
        r = c.getresponse(); data = r.read(); c.close()
        return r.status, json.loads(data)

    def fichier(self, contenu):
        f = tempfile.NamedTemporaryFile("wb", suffix=".pcap", delete=False); f.write(contenu); f.close()
        self.addCleanup(os.unlink, f.name)
        return f.name

    def test_chemin_ok(self):
        st, r = self.post_path(self.fichier(b"\xd4\xc3\xb2\xa1" + b"0" * 50))
        self.assertEqual((st, r["count"]), (200, 5)); self.assertTrue(r["name"].endswith(".pcap"))

    def test_chemin_pcapng_ok(self):
        self.assertEqual(self.post_path(self.fichier(b"\x0a\x0d\x0d\x0a" + b"0" * 50))[0], 200)

    def test_chemin_introuvable(self):
        st, r = self.post_path("/tmp/n-existe-pas.pcap")
        self.assertEqual(st, 404); self.assertIn("introuvable", r["error"])

    def test_chemin_relatif_refuse(self):
        st, r = self.post_path("capture.pcap")
        self.assertEqual(st, 400); self.assertIn("chemin complet", r["error"])

    def test_chemin_pas_un_pcap(self):
        st, r = self.post_path(self.fichier(b"PK\x03\x04" + b"0" * 50))
        self.assertEqual(st, 400); self.assertIn("pas un pcap", r["error"])

    def test_chemin_refuse_pendant_capture(self):
        rz.STATE["running"] = True
        self.assertEqual(self.post_path(self.fichier(b"\xd4\xc3\xb2\xa1" + b"0" * 50))[0], 409)

    def test_chemin_guillemets_et_espaces(self):                  # chemin collé depuis un gestionnaire de fichiers
        self.assertEqual(self.post_path('  "' + self.fichier(b"\xd4\xc3\xb2\xa1" + b"0" * 50) + '"  ')[0], 200)

    def test_tilde_sans_sudo(self):
        with mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop("SUDO_USER", None)
            self.assertEqual(rz.expand_path("~/x.pcap"), os.path.expanduser("~/x.pcap"))


if __name__ == "__main__":
    unittest.main()
