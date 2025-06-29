<<<<<<< HEAD
"""
Funções de varredura (stealth/agressivo) para ShadowPort Pro
"""

import random
import time
from scapy.all import IP, TCP, sr1, RandShort, conf
import socket
from utils.helpers import get_service_info, check_vulnerabilities, get_banner, detect_waf, get_web_headers, SERVICE_DB

conf.verb = 0  # Desativa logs do Scapy

def stealth_scan(target, port, scan_type, delay=0.1):
    """Realiza varredura furtiva usando Scapy com técnicas avançadas"""
    try:
        ip_pkt = IP(dst=target)
        if scan_type == "FIN":
            tcp_pkt = TCP(dport=port, flags="F", seq=RandShort())
        elif scan_type == "NULL":
            tcp_pkt = TCP(dport=port, flags="", seq=RandShort())
        elif scan_type == "XMAS":
            tcp_pkt = TCP(dport=port, flags="FPU", seq=RandShort())
        elif scan_type == "FRAG":
            ip_pkt.flags = 1
            ip_pkt.frag = 0
            tcp_pkt = TCP(dport=port, flags="S", seq=RandShort())
        ip_pkt.ttl = random.randint(64, 255)
        time.sleep(delay + random.uniform(-0.05, 0.1))
        response = sr1(ip_pkt/tcp_pkt, timeout=1, verbose=0)
        if response is None:
            return False
        elif response.haslayer(TCP):
            if response[TCP].flags == 0x14:
                return False
            elif response[TCP].flags == 0x4:
                return True
        return False
    except:
        return False

def tcp_connect_scan(target, port, timeout=1):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        result = s.connect_ex((target, port))
        s.close()
        return result == 0
    except:
        return False

def udp_scan(target, port, timeout=2):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(timeout)
        s.sendto(b'\x00' * 64, (target, port))
        data, addr = s.recvfrom(1024)
        if data:
            return True
    except socket.timeout:
        return False
    except:
        pass
    return False

def run_stealth_scan(target, port_range, speed="medium", verbose=False):
    open_ports = []
    start_port, end_port = map(int, port_range.split('-'))
    delays = {"fast": 0.05, "medium": 0.2, "slow": 0.5}
    delay = delays.get(speed, 0.2)
    print(f"[*] Iniciando varredura furtiva em {target} (portas {start_port}-{end_port})")
    print(f"[*] Técnicas: FIN, NULL, XMAS, Fragmented | Velocidade: {speed} (delay: {delay}s)")
    for port in range(start_port, end_port + 1):
        if verbose:
            print(f"  [+] Testando porta {port} com técnicas furtivas...")
        scan_types = ["FIN", "NULL", "XMAS", "FRAG"]
        for st in scan_types:
            if stealth_scan(target, port, st, delay):
                open_ports.append(port)
                if verbose:
                    print(f"  [+] Porta {port} aberta (técnica: {st})")
                break
    print(f"\n[*] Varredura furtiva concluída! Portas abertas: {len(open_ports)}")
    return open_ports

def run_aggressive_scan(target, port_range, speed="medium", verbose=False):
    results = []
    start_port, end_port = map(int, port_range.split('-'))
    timeouts = {"fast": 0.3, "medium": 1, "slow": 2}
    timeout = timeouts.get(speed, 1)
    print(f"[*] Iniciando varredura agressiva em {target} (portas {start_port}-{end_port})")
    print(f"[*] Técnicas: TCP Connect, UDP Scan | Velocidade: {speed}")
    for port in range(start_port, end_port + 1):
        if verbose:
            print(f"  [+] Testando porta TCP {port}...")
        if tcp_connect_scan(target, port, timeout):
            banner = get_banner(target, port)
            service, risk_level = get_service_info(port, banner)
            vulns = check_vulnerabilities(banner)
            waf = detect_waf(target, port) if port in [80, 443, 8080, 8443] else False
            web_tech = {}
            if port in [80, 443, 8080, 8443]:
                web_tech = get_web_headers(target, port)
                if any("PHP" in tech for tech in web_tech.get("tech", [])):
                    vulns.extend(check_vulnerabilities("PHP/7.4.0"))
            results.append({
                "port": port,
                "protocol": "TCP",
                "status": "open",
                "service": service,
                "risk_level": risk_level,
                "banner": banner,
                "vulnerabilities": vulns,
                "waf_detected": waf,
                "web_tech": web_tech
            })
            if verbose:
                vuln_info = f" | Vulnerabilidades: {', '.join(vulns)}" if vulns else ""
                waf_info = " | WAF Detectado" if waf else ""
                tech_info = f" | Tecnologias: {', '.join(web_tech.get('tech', []))}" if web_tech else ""
                print(f"  [+] TCP/{port} aberto | Serviço: {service}{vuln_info}{waf_info}{tech_info}")
    udp_ports = [53, 67, 68, 69, 123, 137, 161, 162, 500, 514, 520]
    for port in udp_ports:
        if start_port <= port <= end_port:
            if verbose:
                print(f"  [+] Testando porta UDP {port}...")
            if udp_scan(target, port):
                results.append({
                    "port": port,
                    "protocol": "UDP",
                    "status": "open",
                    "service": SERVICE_DB.get(port, {}).get("name", "Desconhecido"),
                    "risk_level": SERVICE_DB.get(port, {}).get("risk", "low"),
                    "banner": "",
                    "vulnerabilities": [],
                    "waf_detected": False,
                    "web_tech": {}
                })
                if verbose:
                    print(f"  [+] UDP/{port} aberto")
    print(f"\n[*] Varredura agressiva concluída! Serviços encontrados: {len(results)}")
=======
"""
Funções de varredura (stealth/agressivo) para ShadowPort Pro
"""

import random
import time
from scapy.all import IP, TCP, sr1, RandShort, conf
import socket
from utils.helpers import get_service_info, check_vulnerabilities, get_banner, detect_waf, get_web_headers, SERVICE_DB

conf.verb = 0  # Desativa logs do Scapy

def stealth_scan(target, port, scan_type, delay=0.1):
    """Realiza varredura furtiva usando Scapy com técnicas avançadas"""
    try:
        ip_pkt = IP(dst=target)
        if scan_type == "FIN":
            tcp_pkt = TCP(dport=port, flags="F", seq=RandShort())
        elif scan_type == "NULL":
            tcp_pkt = TCP(dport=port, flags="", seq=RandShort())
        elif scan_type == "XMAS":
            tcp_pkt = TCP(dport=port, flags="FPU", seq=RandShort())
        elif scan_type == "FRAG":
            ip_pkt.flags = 1
            ip_pkt.frag = 0
            tcp_pkt = TCP(dport=port, flags="S", seq=RandShort())
        ip_pkt.ttl = random.randint(64, 255)
        time.sleep(delay + random.uniform(-0.05, 0.1))
        response = sr1(ip_pkt/tcp_pkt, timeout=1, verbose=0)
        if response is None:
            return False
        elif response.haslayer(TCP):
            if response[TCP].flags == 0x14:
                return False
            elif response[TCP].flags == 0x4:
                return True
        return False
    except:
        return False

def tcp_connect_scan(target, port, timeout=1):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        result = s.connect_ex((target, port))
        s.close()
        return result == 0
    except:
        return False

def udp_scan(target, port, timeout=2):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(timeout)
        s.sendto(b'\x00' * 64, (target, port))
        data, addr = s.recvfrom(1024)
        if data:
            return True
    except socket.timeout:
        return False
    except:
        pass
    return False

def run_stealth_scan(target, port_range, speed="medium", verbose=False):
    open_ports = []
    start_port, end_port = map(int, port_range.split('-'))
    delays = {"fast": 0.05, "medium": 0.2, "slow": 0.5}
    delay = delays.get(speed, 0.2)
    print(f"[*] Iniciando varredura furtiva em {target} (portas {start_port}-{end_port})")
    print(f"[*] Técnicas: FIN, NULL, XMAS, Fragmented | Velocidade: {speed} (delay: {delay}s)")
    for port in range(start_port, end_port + 1):
        if verbose:
            print(f"  [+] Testando porta {port} com técnicas furtivas...")
        scan_types = ["FIN", "NULL", "XMAS", "FRAG"]
        for st in scan_types:
            if stealth_scan(target, port, st, delay):
                open_ports.append(port)
                if verbose:
                    print(f"  [+] Porta {port} aberta (técnica: {st})")
                break
    print(f"\n[*] Varredura furtiva concluída! Portas abertas: {len(open_ports)}")
    return open_ports

def run_aggressive_scan(target, port_range, speed="medium", verbose=False):
    results = []
    start_port, end_port = map(int, port_range.split('-'))
    timeouts = {"fast": 0.3, "medium": 1, "slow": 2}
    timeout = timeouts.get(speed, 1)
    print(f"[*] Iniciando varredura agressiva em {target} (portas {start_port}-{end_port})")
    print(f"[*] Técnicas: TCP Connect, UDP Scan | Velocidade: {speed}")
    for port in range(start_port, end_port + 1):
        if verbose:
            print(f"  [+] Testando porta TCP {port}...")
        if tcp_connect_scan(target, port, timeout):
            banner = get_banner(target, port)
            service, risk_level = get_service_info(port, banner)
            vulns = check_vulnerabilities(banner)
            waf = detect_waf(target, port) if port in [80, 443, 8080, 8443] else False
            web_tech = {}
            if port in [80, 443, 8080, 8443]:
                web_tech = get_web_headers(target, port)
                if any("PHP" in tech for tech in web_tech.get("tech", [])):
                    vulns.extend(check_vulnerabilities("PHP/7.4.0"))
            results.append({
                "port": port,
                "protocol": "TCP",
                "status": "open",
                "service": service,
                "risk_level": risk_level,
                "banner": banner,
                "vulnerabilities": vulns,
                "waf_detected": waf,
                "web_tech": web_tech
            })
            if verbose:
                vuln_info = f" | Vulnerabilidades: {', '.join(vulns)}" if vulns else ""
                waf_info = " | WAF Detectado" if waf else ""
                tech_info = f" | Tecnologias: {', '.join(web_tech.get('tech', []))}" if web_tech else ""
                print(f"  [+] TCP/{port} aberto | Serviço: {service}{vuln_info}{waf_info}{tech_info}")
    udp_ports = [53, 67, 68, 69, 123, 137, 161, 162, 500, 514, 520]
    for port in udp_ports:
        if start_port <= port <= end_port:
            if verbose:
                print(f"  [+] Testando porta UDP {port}...")
            if udp_scan(target, port):
                results.append({
                    "port": port,
                    "protocol": "UDP",
                    "status": "open",
                    "service": SERVICE_DB.get(port, {}).get("name", "Desconhecido"),
                    "risk_level": SERVICE_DB.get(port, {}).get("risk", "low"),
                    "banner": "",
                    "vulnerabilities": [],
                    "waf_detected": False,
                    "web_tech": {}
                })
                if verbose:
                    print(f"  [+] UDP/{port} aberto")
    print(f"\n[*] Varredura agressiva concluída! Serviços encontrados: {len(results)}")
>>>>>>> 56958d3ba797075cf568cf648c05165060f2aecb
    return results 