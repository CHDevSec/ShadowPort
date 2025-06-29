"""
Função de brute-force de subdomínios para ShadowPort Pro
"""

import dns.resolver
from utils.helpers import SUBDOMAINS

def subdomain_scan(target):
    """Realiza brute-force leve de subdomínios"""
    found_subdomains = []
    print(f"[*] Iniciando busca por subdomínios de {target}")
    for sub in SUBDOMAINS:
        full_domain = f"{sub}.{target}"
        try:
            answers = dns.resolver.resolve(full_domain, 'A')
            for rdata in answers:
                found_subdomains.append({
                    "subdomain": full_domain,
                    "ip": rdata.address
                })
                print(f"  [+] Subdomínio encontrado: {full_domain} -> {rdata.address}")
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.Timeout):
            continue
        except:
            continue
    print(f"[*] Busca por subdomínios concluída! Encontrados: {len(found_subdomains)}")
    return found_subdomains

# ... código será migrado aqui ... 