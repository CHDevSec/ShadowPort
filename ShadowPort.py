#!/usr/bin/env python3
"""
ShadowPort v2 - Ferramenta Avançada de Footprinting e Enumeração
Modo Passivo: Scans furtivos com técnicas de evasão avançadas
Modo Agressivo: Enumeração profunda de serviços e vulnerabilidades
"""

import argparse
import ipaddress
import socket
import sys
from utils.helpers import create_output_dir
from modules.scan import run_stealth_scan, run_aggressive_scan
from modules.subdomain import subdomain_scan
from modules.report import generate_report_html, generate_report_json, generate_report_txt
import random
import time
import json
import os
import re
import dns.resolver
from datetime import datetime
from scapy.all import IP, TCP, sr1, RandShort, conf
import requests
from requests.exceptions import RequestException
import importlib.util

# Configurações globais
OUTPUT_DIR = "output"
conf.verb = 0  # Desativa logs do Scapy

# Banco de dados de vulnerabilidades expandido
VULNERABILITY_DB = {
    r"Apache/2\.4\.(4[0-9]|5[0-3])": ["CVE-2021-41773", "CVE-2021-42013"],
    r"OpenSSH 8\.2p1": ["CVE-2020-15778"],
    r"ProFTPD 1\.3\.5": ["CVE-2020-9273"],
    r"Redis (6\.0\.(9|10))": ["CVE-2021-32761", "CVE-2021-41099"],
    r"MySQL (8\.0\.[0-2][0-9])": ["CVE-2021-2147", "CVE-2021-2158"],
    r"Elasticsearch 7\.(10|11|12)\.[0-9]": ["CVE-2021-22144"],
    r"Microsoft-IIS/10\.0": ["CVE-2021-31166", "CVE-2021-33742"],
    r"nginx/1\.(1[8-9]|20)\.0": ["CVE-2021-23017"],
    r"SMBv1": ["CVE-2017-0143", "CVE-2017-0144", "CVE-2017-0145", "CVE-2017-0146", "CVE-2017-0148"],
    r"Tomcat/9\.0\.[0-3][0-9]": ["CVE-2020-17527", "CVE-2020-13935"],
    r"PHP/7\.4\.[0-9]": ["CVE-2021-21703", "CVE-2021-21707"],
    r"WordPress 5\.[0-7]\.[0-9]": ["CVE-2021-29447", "CVE-2021-44223"]
}

# Mapeamento de serviços e níveis de risco
SERVICE_DB = {
    21: {"name": "FTP", "risk": "medium"},
    22: {"name": "SSH", "risk": "medium"},
    23: {"name": "Telnet", "risk": "high"},
    25: {"name": "SMTP", "risk": "low"},
    53: {"name": "DNS", "risk": "low"},
    80: {"name": "HTTP", "risk": "low"},
    110: {"name": "POP3", "risk": "low"},
    135: {"name": "MSRPC", "risk": "high"},
    139: {"name": "NetBIOS", "risk": "critical"},
    143: {"name": "IMAP", "risk": "low"},
    443: {"name": "HTTPS", "risk": "low"},
    445: {"name": "SMB", "risk": "critical"},
    1433: {"name": "MSSQL", "risk": "high"},
    3306: {"name": "MySQL", "risk": "medium"},
    3389: {"name": "RDP", "risk": "critical"},
    5432: {"name": "PostgreSQL", "risk": "medium"},
    5900: {"name": "VNC", "risk": "critical"},
    6379: {"name": "Redis", "risk": "high"},
    8080: {"name": "HTTP-Alt", "risk": "low"},
    8443: {"name": "HTTPS-Alt", "risk": "low"},
    9200: {"name": "Elasticsearch", "risk": "high"}
}

# Lista de subdomínios para brute-force
SUBDOMAINS = [
    'www', 'mail', 'webmail', 'admin', 'dashboard', 'portal', 
    'vpn', 'ftp', 'api', 'dev', 'test', 'staging', 'secure',
    'server', 'ns', 'ns1', 'ns2', 'dns', 'mx', 'owa', 'cpanel'
]

PLUGINS_DIR = os.path.join(os.path.dirname(__file__), 'modules', 'plugins')

def load_plugin(plugin_name):
    plugin_path = os.path.join(PLUGINS_DIR, f'{plugin_name}.py')
    if not os.path.isfile(plugin_path):
        print(f"[-] Plugin '{plugin_name}' não encontrado em {PLUGINS_DIR}")
        sys.exit(1)
    spec = importlib.util.spec_from_file_location(plugin_name, plugin_path)
    plugin = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(plugin)
    return plugin

def disclaimer():
    return """
    Ferramenta criada para fins educacionais e testes autorizados.
    O uso indevido é de responsabilidade do usuário.
    CHDevSec 2025 - Todos os direitos reservados.
    """

def get_service_info(port, banner):
    """Identifica serviços e níveis de risco com base na porta e banner"""
    service_info = SERVICE_DB.get(port, {"name": "Desconhecido", "risk": "low"})
    
    # Tenta identificar o serviço pelo banner
    banner_lower = banner.lower()
    if 'http' in banner_lower:
        service_info["name"] = "HTTP"
    elif 'ssh' in banner_lower:
        service_info["name"] = "SSH"
    elif 'ftp' in banner_lower:
        service_info["name"] = "FTP"
        service_info["risk"] = "medium"
    
    # Ajusta risco para serviços sensíveis
    if service_info["name"] in ["SMB", "RDP", "VNC", "NetBIOS"]:
        service_info["risk"] = "critical"
    
    return service_info["name"], service_info["risk"]

def check_vulnerabilities(banner):
    """Verifica vulnerabilidades conhecidas usando regex"""
    vulnerabilities = []
    for pattern, cves in VULNERABILITY_DB.items():
        if re.search(pattern, banner, re.IGNORECASE):
            vulnerabilities.extend(cves)
    return vulnerabilities

def stealth_scan(target, port, scan_type, delay=0.1):
    """Realiza varredura furtiva usando Scapy com técnicas avançadas"""
    try:
        # Configuração de pacote base
        ip_pkt = IP(dst=target)
        
        # Configurações de evasão
        if scan_type == "FIN":
            tcp_pkt = TCP(dport=port, flags="F", seq=RandShort())
        elif scan_type == "NULL":
            tcp_pkt = TCP(dport=port, flags="", seq=RandShort())
        elif scan_type == "XMAS":
            tcp_pkt = TCP(dport=port, flags="FPU", seq=RandShort())
        elif scan_type == "FRAG":
            # Fragmentação de pacotes
            ip_pkt.flags = 1  # Set MF flag
            ip_pkt.frag = 0
            tcp_pkt = TCP(dport=port, flags="S", seq=RandShort())
        
        # TTL randomizado
        ip_pkt.ttl = random.randint(64, 255)
        
        # Delay aleatório
        time.sleep(delay + random.uniform(-0.05, 0.1))
        
        # Envia pacote e captura resposta
        response = sr1(ip_pkt/tcp_pkt, timeout=1, verbose=0)
        
        # Análise de resposta
        if response is None:
            return False  # Sem resposta
        elif response.haslayer(TCP):
            if response[TCP].flags == 0x14:  # RST+ACK
                return False
            elif response[TCP].flags == 0x4:  # RST
                return True  # Porta aberta em alguns casos
        return False
    except:
        return False

def tcp_connect_scan(target, port, timeout=1):
    """Varredura TCP Connect tradicional"""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        result = s.connect_ex((target, port))
        s.close()
        return result == 0
    except:
        return False

def udp_scan(target, port, timeout=2):
    """Varredura básica UDP"""
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

def get_web_headers(target, port):
    """Coleta headers HTTP/HTTPS para detecção de tecnologias"""
    try:
        protocol = "https" if port in [443, 8443] else "http"
        url = f"{protocol}://{target}:{port}"
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8"
        }
        response = requests.head(url, headers=headers, timeout=3, verify=False)
        
        tech_info = {
            "server": response.headers.get("Server", ""),
            "x-powered-by": response.headers.get("X-Powered-By", ""),
            "x-backend": response.headers.get("X-Backend", ""),
            "via": response.headers.get("Via", ""),
            "tech": []
        }
        
        # Detecção de tecnologias por headers
        if "PHP" in tech_info["x-powered-by"]:
            tech_info["tech"].append("PHP")
        if "ASP.NET" in tech_info["x-powered-by"]:
            tech_info["tech"].append("ASP.NET")
        if "Node.js" in response.headers.get("X-Powered-By", ""):
            tech_info["tech"].append("Node.js")
        if "nginx" in tech_info["server"].lower():
            tech_info["tech"].append("Nginx")
        if "apache" in tech_info["server"].lower():
            tech_info["tech"].append("Apache")
        if "IIS" in tech_info["server"]:
            tech_info["tech"].append("IIS")
            
        return tech_info
    except RequestException:
        return {}
    except:
        return {}

def get_banner(target, port):
    """Coleta banner do serviço com timeout aprimorado"""
    try:
        s = socket.socket()
        s.settimeout(2)
        s.connect((target, port))
        banner = s.recv(1024).decode(errors="ignore").strip()
        s.close()
        return banner
    except:
        return ""

def detect_waf(target, port):
    """Detecção avançada de WAF baseada em múltiplos fatores"""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(2)
        s.connect((target, port))
        
        # Pacote de teste com payload malicioso
        payload = (
            b"GET /?id=1' OR 1=1-- HTTP/1.1\r\n"
            b"Host: badhost\r\n"
            b"User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)\r\n"
            b"Connection: close\r\n\r\n"
        )
        s.send(payload)
        response = s.recv(4096).decode(errors="ignore")
        s.close()
        
        # Padrões de WAF
        waf_patterns = [
            "cloudflare", "akamai", "incapsula", "barracuda", 
            "fortinet", "403 forbidden", "access denied", "waf",
            "blocked", "forbidden", "security policy", "mod_security"
        ]
        
        # Verificação de TTL inconsistente
        ttl_analysis = False
        if "TTL" in response:
            ttl_value = re.search(r"TTL=(\d+)", response)
            if ttl_value:
                ttl = int(ttl_value.group(1))
                if ttl < 50 or ttl > 200:  # TTL fora do padrão
                    ttl_analysis = True
        
        # Verificação de RST massivo
        rst_analysis = "RST" in response and response.count("RST") > 3
        
        return any(pattern in response.lower() for pattern in waf_patterns) or ttl_analysis or rst_analysis
    except:
        return False

def run_stealth_scan(target, port_range, speed="medium", verbose=False):
    """Executa varredura furtiva com técnicas de evasão avançadas"""
    open_ports = []
    start_port, end_port = map(int, port_range.split('-'))
    total_ports = end_port - start_port + 1
    
    # Configuração de velocidade
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
    """Executa varredura completa com enumeração avançada de serviços"""
    results = []
    start_port, end_port = map(int, port_range.split('-'))
    total_ports = end_port - start_port + 1
    
    # Configuração de velocidade
    timeouts = {"fast": 0.3, "medium": 1, "slow": 2}
    timeout = timeouts.get(speed, 1)
    
    print(f"[*] Iniciando varredura agressiva em {target} (portas {start_port}-{end_port})")
    print(f"[*] Técnicas: TCP Connect, UDP Scan | Velocidade: {speed}")
    
    # Varredura TCP
    for port in range(start_port, end_port + 1):
        if verbose:
            print(f"  [+] Testando porta TCP {port}...")
        
        if tcp_connect_scan(target, port, timeout):
            banner = get_banner(target, port)
            service, risk_level = get_service_info(port, banner)
            vulns = check_vulnerabilities(banner)
            waf = detect_waf(target, port) if port in [80, 443, 8080, 8443] else False
            
            # Coleta adicional para serviços web
            web_tech = {}
            if port in [80, 443, 8080, 8443]:
                web_tech = get_web_headers(target, port)
                # Atualiza vulnerabilidades com base nas tecnologias
                if any("PHP" in tech for tech in web_tech.get("tech", [])):
                    vulns.extend(VULNERABILITY_DB.get(r"PHP/7\.4\.[0-9]", []))
            
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
    
    # Varredura UDP (portas específicas)
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
    return results

def subdomain_scan(target):
    """Realiza brute-force leve de subdomínios"""
    found_subdomains = []
    print(f"[*] Iniciando busca por subdomínios de {target}")
    
    for sub in SUBDOMAINS:
        full_domain = f"{sub}.{target}"
        try:
            # Tenta resolver o subdomínio
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

def generate_report_html(target, scan_data, scan_mode, filename, subdomains=None):
    """Gera relatório HTML com estilo dark moderno e gráficos"""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    # Estatísticas para gráficos
    risk_levels = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    vulnerabilities_count = 0
    web_techs = {}
    
    for item in scan_data:
        risk_levels[item["risk_level"]] += 1
        vulnerabilities_count += len(item["vulnerabilities"])
        
        # Contabiliza tecnologias web
        for tech in item.get("web_tech", {}).get("tech", []):
            web_techs[tech] = web_techs.get(tech, 0) + 1
    
    # Ordena tecnologias por frequência
    sorted_techs = sorted(web_techs.items(), key=lambda x: x[1], reverse=True)
    
    # Prepara dados para gráfico de risco
    risk_chart_data = {
        "labels": list(risk_levels.keys()),
        "data": list(risk_levels.values()),
        "colors": ["#f85149", "#ff7b72", "#ffa657", "#d29922"]
    }
    
    html_content = f"""
    <!DOCTYPE html>
    <html lang="pt-BR">
    <head>
        <meta charset="UTF-8">
        <title>ShadowPort Report - {target}</title>
        <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
        <style>
            :root {{
                --bg-dark: #0d1117;
                --bg-darker: #06090f;
                --text-light: #c9d1d9;
                --accent: #58a6ff;
                --critical: #f85149;
                --high: #ff7b72;
                --medium: #ffa657;
                --low: #d29922;
            }}
            body {{
                background-color: var(--bg-dark);
                color: var(--text-light);
                font-family: 'Consolas', 'Monaco', monospace;
                line-height: 1.6;
                margin: 0;
                padding: 20px;
            }}
            .container {{
                max-width: 1200px;
                margin: 0 auto;
            }}
            header {{
                border-bottom: 1px solid #30363d;
                padding-bottom: 20px;
                margin-bottom: 30px;
            }}
            h1, h2, h3 {{
                color: var(--accent);
            }}
            .card {{
                background-color: var(--bg-darker);
                border-radius: 6px;
                border: 1px solid #30363d;
                padding: 20px;
                margin-bottom: 20px;
            }}
            .summary {{
                display: grid;
                grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
                gap: 15px;
                margin-bottom: 30px;
            }}
            .summary-item {{
                text-align: center;
                padding: 15px;
                border-radius: 6px;
                background-color: #161b22;
            }}
            .critical {{ color: var(--critical); }}
            .high {{ color: var(--high); }}
            .medium {{ color: var(--medium); }}
            .low {{ color: var(--low); }}
            .risk-badge {{
                display: inline-block;
                padding: 3px 8px;
                border-radius: 4px;
                font-size: 0.8em;
                font-weight: bold;
            }}
            .badge-critical {{ background-color: var(--critical); }}
            .badge-high {{ background-color: var(--high); }}
            .badge-medium {{ background-color: var(--medium); }}
            .badge-low {{ background-color: var(--low); }}
            table {{
                width: 100%;
                border-collapse: collapse;
                margin-top: 20px;
            }}
            th, td {{
                padding: 12px 15px;
                text-align: left;
                border-bottom: 1px solid #30363d;
            }}
            th {{
                background-color: #161b22;
            }}
            tr:hover {{
                background-color: #161b22;
            }}
            .chart-container {{
                display: grid;
                grid-template-columns: repeat(auto-fit, minmax(400px, 1fr));
                gap: 20px;
                margin: 30px 0;
            }}
            .chart-box {{
                background-color: #161b22;
                border-radius: 6px;
                padding: 15px;
            }}
            .btn-download {{
                display: inline-block;
                background-color: #238636;
                color: white;
                padding: 10px 15px;
                border-radius: 4px;
                text-decoration: none;
                margin: 10px 5px;
                transition: all 0.3s;
            }}
            .btn-download:hover {{
                background-color: #2ea043;
                transform: translateY(-2px);
            }}
            .subdomain-list {{
                display: grid;
                grid-template-columns: repeat(auto-fill, minmax(250px, 1fr));
                gap: 10px;
            }}
            .subdomain-item {{
                background-color: #161b22;
                padding: 10px;
                border-radius: 4px;
                border-left: 3px solid var(--accent);
            }}
            .disclaimer {{
                margin-top: 40px;
                padding-top: 20px;
                border-top: 1px solid #30363d;
                font-size: 0.9em;
                text-align: center;
                color: #8b949e;
            }}
        </style>
    </head>
    <body>
        <div class="container">
            <header>
                <h1>ShadowPort Report</h1>
                <p>Alvo: <strong>{target}</strong> | Modo: <strong>{scan_mode}</strong></p>
                <p>Data: {timestamp}</p>
                
                <div class="summary">
                    <div class="summary-item">
                        <h3>Portas Abertas</h3>
                        <p>{len(scan_data)}</p>
                    </div>
                    <div class="summary-item">
                        <h3>Vulnerabilidades</h3>
                        <p class="high">{vulnerabilities_count}</p>
                    </div>
                    <div class="summary-item">
                        <h3>Risco Crítico</h3>
                        <p class="critical">{risk_levels['critical']}</p>
                    </div>
                    <div class="summary-item">
                        <h3>WAF Detectado</h3>
                        <p>{'Sim' if any(item.get('waf_detected') for item in scan_data) else 'Não'}</p>
                    </div>
                </div>
                
                <div>
                    <a href="{filename.replace('.html', '.json')}" class="btn-download" download>
                        📥 Baixar JSON
                    </a>
                    <a href="{filename.replace('.html', '.txt')}" class="btn-download" download>
                        📥 Baixar TXT
                    </a>
                </div>
            </header>
            
            <div class="chart-container">
                <div class="chart-box">
                    <h3>Distribuição de Níveis de Risco</h3>
                    <canvas id="riskChart"></canvas>
                </div>
                <div class="chart-box">
                    <h3>Tecnologias Web Detectadas</h3>
                    <canvas id="techChart"></canvas>
                </div>
            </div>
            
            <div class="card">
                <h2>Resultados Detalhados</h2>
                <table>
                    <thead>
                        <tr>
                            <th>Porta</th>
                            <th>Protocolo</th>
                            <th>Serviço</th>
                            <th>Risco</th>
                            <th>Banner</th>
                            <th>Vulnerabilidades</th>
                            <th>WAF</th>
                        </tr>
                    </thead>
                    <tbody>
    """
    
    for item in scan_data:
        vulns = ', '.join(item['vulnerabilities']) if item['vulnerabilities'] else 'Nenhuma'
        waf = "Sim" if item.get('waf_detected') else "Não"
        
        html_content += f"""
                        <tr>
                            <td>{item['port']}</td>
                            <td>{item['protocol']}</td>
                            <td>{item['service']}</td>
                            <td><span class="risk-badge badge-{item['risk_level']}">{item['risk_level'].capitalize()}</span></td>
                            <td>{item['banner'] or '-'}</td>
                            <td>{vulns}</td>
                            <td>{waf}</td>
                        </tr>
        """
    
    html_content += f"""
                    </tbody>
                </table>
            </div>
    """
    
    # Seção de subdomínios (se encontrados)
    if subdomains:
        html_content += f"""
            <div class="card">
                <h2>Subdomínios Encontrados</h2>
                <div class="subdomain-list">
        """
        
        for sub in subdomains:
            html_content += f"""
                    <div class="subdomain-item">
                        <strong>{sub['subdomain']}</strong>
                        <div>{sub['ip']}</div>
                    </div>
            """
        
        html_content += """
                </div>
            </div>
        """
    
    html_content += f"""
            <div class="card">
                <h2>Recomendações de Segurança</h2>
                <ul>
                    <li>Fechar todas as portas não essenciais</li>
                    <li>Atualizar imediatamente serviços com vulnerabilidades críticas</li>
                    <li>Implementar regras de firewall restritivas</li>
                    <li>Monitorar logs de acesso regularmente</li>
                    <li>Realizar testes de penetração regulares</li>
                </ul>
            </div>
            
            <div class="disclaimer">
                <p>{disclaimer()}</p>
            </div>
        </div>
        
        <script>
            // Gráfico de distribuição de risco
            const riskCtx = document.getElementById('riskChart').getContext('2d');
            const riskChart = new Chart(riskCtx, {{
                type: 'doughnut',
                data: {{
                    labels: {json.dumps(risk_chart_data['labels'])},
                    datasets: [{{
                        data: {json.dumps(risk_chart_data['data'])},
                        backgroundColor: {json.dumps(risk_chart_data['colors'])},
                        borderWidth: 0
                    }}]
                }},
                options: {{
                    responsive: true,
                    plugins: {{
                        legend: {{ position: 'right' }}
                    }}
                }}
            }});
            
            // Gráfico de tecnologias web
            const techCtx = document.getElementById('techChart').getContext('2d');
            const techChart = new Chart(techCtx, {{
                type: 'bar',
                data: {{
                    labels: {json.dumps([t[0] for t in sorted_techs])},
                    datasets: [{{
                        label: 'Tecnologias Detectadas',
                        data: {json.dumps([t[1] for t in sorted_techs])},
                        backgroundColor: '#58a6ff',
                        borderWidth: 0
                    }}]
                }},
                options: {{
                    responsive: true,
                    scales: {{
                        y: {{ beginAtZero: true }}
                    }}
                }}
            }});
        </script>
    </body>
    </html>
    """
    
    with open(os.path.join(OUTPUT_DIR, filename), "w") as f:
        f.write(html_content)
    
    print(f"[+] Relatório HTML gerado: {filename}")

def generate_report_json(scan_data, filename):
    """Gera relatório em formato JSON"""
    report = {
        "scan_data": scan_data,
        "disclaimer": disclaimer().strip()
    }
    
    with open(os.path.join(OUTPUT_DIR, filename), "w") as f:
        json.dump(report, f, indent=4)
    
    print(f"[+] Relatório JSON gerado: {filename}")

def generate_report_txt(target, scan_data, scan_mode, filename):
    """Gera relatório simplificado em TXT"""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    report = f"""
    ShadowPort Scan Report
    =====================
    
    Alvo: {target}
    Modo: {scan_mode}
    Data: {timestamp}
    Portas abertas: {len(scan_data)}
    
    Resultados:
    """
    
    for item in scan_data:
        vulns = '\n      - ' + '\n      - '.join(item['vulnerabilities']) if item['vulnerabilities'] else 'Nenhuma'
        waf = "Sim" if item.get('waf_detected') else "Não"
        tech = '\n      - ' + '\n      - '.join(item.get('web_tech', {}).get('tech', [])) if item.get('web_tech', {}).get('tech') else 'Nenhuma'
        
        report += f"""
    Porta: {item['port']}/{item['protocol']}
    Serviço: {item['service']}
    Nível de Risco: {item['risk_level'].capitalize()}
    Banner: {item['banner'] or '-'}
    Tecnologias: {tech}
    Vulnerabilidades: {vulns}
    WAF Detectado: {waf}
    {'-'*50}
        """
    
    report += f"""
    Recomendações:
    - Fechar portas desnecessárias
    - Atualizar serviços vulneráveis
    - Revisar configurações de firewall
    - Implementar monitoramento contínuo
    
    {disclaimer()}
    """
    
    with open(os.path.join(OUTPUT_DIR, filename), "w") as f:
        f.write(report)
    
    print(f"[+] Relatório TXT gerado: {filename}")

def main():
    parser = argparse.ArgumentParser(
        description="ShadowPort Pro - Footprinting, Enumeração e Exploração Modular",
        epilog="Exemplos:\n  python ShadowPort.py scan -t alvo.com --range 1-1000 --html\n  python ShadowPort.py audit -t alvo.com --json\n  python ShadowPort.py exec -t alvo.com --plugin brute_ssh",
        formatter_class=argparse.RawTextHelpFormatter
    )
    subparsers = parser.add_subparsers(dest='mode', required=True, help='Modo de operação')

    # Subcomando: scan
    scan_parser = subparsers.add_parser('scan', help='Scan padrão (stealth/agressivo)')
    scan_parser.add_argument('-t', '--target', required=True, help='IP ou domínio alvo')
    scan_parser.add_argument('--range', default='1-1000', help='Range de portas (ex: 1-1000)')
    scan_parser.add_argument('--aggressive', action='store_true', help='Ativa modo agressivo')
    scan_parser.add_argument('--html', action='store_true', help='Gera relatório HTML')
    scan_parser.add_argument('--json', action='store_true', help='Gera relatório JSON')
    scan_parser.add_argument('--verbose', action='store_true', help='Mostra detalhes da execução')
    scan_parser.add_argument('--output-name', help='Nome personalizado para arquivos de saída')
    scan_parser.add_argument('--speed', choices=['slow', 'medium', 'fast'], default='medium', help='Velocidade do scan (padrão: medium)')

    # Subcomando: audit
    audit_parser = subparsers.add_parser('audit', help='Modo auditoria (apenas detecção, sem exploração)')
    audit_parser.add_argument('-t', '--target', required=True, help='IP ou domínio alvo')
    audit_parser.add_argument('--range', default='1-1000', help='Range de portas (ex: 1-1000)')
    audit_parser.add_argument('--html', action='store_true', help='Gera relatório HTML')
    audit_parser.add_argument('--json', action='store_true', help='Gera relatório JSON')
    audit_parser.add_argument('--verbose', action='store_true', help='Mostra detalhes da execução')
    audit_parser.add_argument('--output-name', help='Nome personalizado para arquivos de saída')
    audit_parser.add_argument('--speed', choices=['slow', 'medium', 'fast'], default='medium', help='Velocidade do scan (padrão: medium)')

    # Subcomando: exec
    exec_parser = subparsers.add_parser('exec', help='Modo execução (exploração controlada, plugins)')
    exec_parser.add_argument('-t', '--target', required=True, help='IP ou domínio alvo')
    exec_parser.add_argument('--plugin', required=True, help='Nome do plugin de exploração (ex: brute_ssh)')
    exec_parser.add_argument('--plugin-args', nargs=argparse.REMAINDER, help='Argumentos extras para o plugin')
    exec_parser.add_argument('--verbose', action='store_true', help='Mostra detalhes da execução')

    args = parser.parse_args()

    # Resolução de alvo
    try:
        ipaddress.ip_address(args.target)
        resolved_target = args.target
        is_domain = False
    except ValueError:
        print(f"[*] Resolvendo domínio: {args.target}")
        try:
            resolved_target = socket.gethostbyname(args.target)
            is_domain = True
            print(f"[+] Resolvido para IP: {resolved_target}")
        except socket.gaierror:
            print("[-] Erro: Não foi possível resolver o domínio")
            sys.exit(1)

    create_output_dir()
    base_filename = args.output_name if hasattr(args, 'output_name') and args.output_name else f"shadowport_{args.target.replace('.', '_')}"
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    full_filename = f"{base_filename}_{timestamp}"

    if args.mode == 'scan':
        subdomains = []
        if args.aggressive and is_domain:
            subdomains = subdomain_scan(args.target)
        if args.aggressive:
            scan_mode = "Agressivo"
            scan_data = run_aggressive_scan(resolved_target, args.range, args.speed, args.verbose)
        else:
            scan_mode = "Passivo"
            open_ports = run_stealth_scan(resolved_target, args.range, args.speed, args.verbose)
            scan_data = [{
                "port": p,
                "protocol": "TCP",
                "status": "open",
                "service": SERVICE_DB.get(p, {}).get("name", "Desconhecido"),
                "risk_level": SERVICE_DB.get(p, {}).get("risk", "low"),
                "banner": "",
                "vulnerabilities": [],
                "waf_detected": False,
                "web_tech": {}
            } for p in open_ports]
        if args.html:
            generate_report_html(args.target, scan_data, scan_mode, f"{full_filename}.html", subdomains)
        if args.json:
            generate_report_json(scan_data, f"{full_filename}.json")
        generate_report_txt(args.target, scan_data, scan_mode, f"{full_filename}.txt")

    elif args.mode == 'audit':
        # Audit: sempre modo passivo, nunca executa exploits/plugins
        print("[*] Modo AUDIT: apenas detecção, sem exploração!")
        open_ports = run_stealth_scan(resolved_target, args.range, args.speed, args.verbose)
        scan_data = [{
            "port": p,
            "protocol": "TCP",
            "status": "open",
            "service": SERVICE_DB.get(p, {}).get("name", "Desconhecido"),
            "risk_level": SERVICE_DB.get(p, {}).get("risk", "low"),
            "banner": "",
            "vulnerabilities": [],
            "waf_detected": False,
            "web_tech": {}
        } for p in open_ports]
        if args.html:
            generate_report_html(args.target, scan_data, "Audit", f"{full_filename}.html")
        if args.json:
            generate_report_json(scan_data, f"{full_filename}.json")
        generate_report_txt(args.target, scan_data, "Audit", f"{full_filename}.txt")

    elif args.mode == 'exec':
        print(f"[*] Modo EXEC: execução de plugin '{args.plugin}'!")
        plugin = load_plugin(args.plugin)
        plugin_args = args.plugin_args if args.plugin_args else []
        # Plugins devem implementar: run(target, options)
        result = plugin.run(resolved_target, plugin_args)
        print(f"[+] Resultado do plugin '{args.plugin}':\n{result}")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[-] Execução interrompida pelo usuário")
        sys.exit(0)
    except Exception as e:
        print(f"[-] Erro inesperado: {str(e)}")
        sys.exit(1)