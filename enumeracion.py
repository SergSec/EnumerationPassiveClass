#!/usr/bin/env python3
import requests
import socket
import json
import sys
import whois
import ssl
import certifi
import urllib3
from datetime import datetime, timezone

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
ssl._create_default_https_context = lambda: ssl.create_default_context(cafile=certifi.where())

CRT_SH_SLEEP = 0.5

def crt_sh_subdomains(domain):
    url = f"https://crt.sh/?q=%.{domain}&output=json"
    try:
        r = requests.get(url, timeout=20, verify=certifi.where())
        if r.status_code != 200:
            print(f"  [!] crt.sh devolvió status {r.status_code}")
            return set()
        data = r.json()
        subs = set()
        for entry in data:
            name = entry.get("name_value", "")
            for n in name.splitlines():
                n = n.strip()
                if n and "*" not in n:
                    subs.add(n)
        print(f"  [+] Encontrados {len(subs)} subdominios (crt.sh).")
        return subs
    except requests.exceptions.SSLError:
        try:
            r = requests.get(url, timeout=20, verify=False)
            data = r.json()
            subs = set()
            for entry in data:
                name = entry.get("name_value", "")
                for n in name.splitlines():
                    n = n.strip()
                    if n and "*" not in n:
                        subs.add(n)
            print(f"  [+] Encontrados {len(subs)} subdominios (crt.sh, sin verificación SSL).")
            return subs
        except Exception:
            print("  [!] No se pudieron obtener subdominios (crt.sh no disponible).")
            return set()
    except Exception:
        return set()

def resolve_host(host):
    try:
        infos = socket.getaddrinfo(host, None)
        ips = sorted({info[4][0] for info in infos})
        print(f"[+] {host} → {ips}")
        return ips
    except Exception:
        print(f"[!] No se pudo resolver {host}")
        return []

def whois_query(domain):
    try:
        w = whois.whois(domain)
        if w:
            return w
        return None
    except Exception:
        return None

def main(domain):
    print(f"\n=== Enum → {domain} ===\n")
    subs = crt_sh_subdomains(domain)
    results = {
        "domain": domain,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "subdomains": sorted(list(subs)),
        "hosts": {},
        "whois": None
    }

    targets = set(subs)
    targets.add(domain)
    for host in sorted(targets):
        ips = resolve_host(host)
        results["hosts"][host] = {"ips": ips}

    w = whois_query(domain)
    results["whois"] = str(w) if w else None

    filename = f"resultado_{domain}.json"
    with open(filename, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=4, ensure_ascii=False)

    print(f"\n[+] Hecho. Resultado guardado en {filename}\n")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Uso: python enumeracion_pasiva.py dominio.com")
        sys.exit(1)
    main(sys.argv[1])
