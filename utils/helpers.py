"""
Helpers e utilitários para ShadowPort Pro
"""

import os
import re
import socket
import requests
from requests.exceptions import RequestException

OUTPUT_DIR = "output"

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

SUBDOMAINS = [
    'www', 'mail', 'webmail', 'admin', 'dashboard', 'portal', 
    'vpn', 'ftp', 'api', 'dev', 'test', 'staging', 'secure',
    'server', 'ns', 'ns1', 'ns2', 'dns', 'mx', 'owa', 'cpanel'
]

def disclaimer():
    return """
    Ferramenta criada para fins educacionais e testes autorizados.
    O uso indevido é de responsabilidade do usuário.
    CHDevSec 2025 - Todos os direitos reservados.
    """

def create_output_dir():
    if not os.path.exists(OUTPUT_DIR):
        os.makedirs(OUTPUT_DIR)

def get_service_info(port, banner):
    service_info = SERVICE_DB.get(port, {"name": "Desconhecido", "risk": "low"})
    banner_lower = banner.lower()
    if 'http' in banner_lower:
        service_info["name"] = "HTTP"
    elif 'ssh' in banner_lower:
        service_info["name"] = "SSH"
    elif 'ftp' in banner_lower:
        service_info["name"] = "FTP"
        service_info["risk"] = "medium"
    if service_info["name"] in ["SMB", "RDP", "VNC", "NetBIOS"]:
        service_info["risk"] = "critical"
    return service_info["name"], service_info["risk"]

def check_vulnerabilities(banner):
    vulnerabilities = []
    for pattern, cves in VULNERABILITY_DB.items():
        if re.search(pattern, banner, re.IGNORECASE):
            vulnerabilities.extend(cves)
    return vulnerabilities

def get_banner(target, port):
    try:
        s = socket.socket()
        s.settimeout(2)
        s.connect((target, port))
        banner = s.recv(1024).decode(errors="ignore").strip()
        s.close()
        return banner
    except:
        return ""

def get_web_headers(target, port):
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

def detect_waf(target, port):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(2)
        s.connect((target, port))
        payload = (
            b"GET /?id=1' OR 1=1-- HTTP/1.1\r\n"
            b"Host: badhost\r\n"
            b"User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)\r\n"
            b"Connection: close\r\n\r\n"
        )
        s.send(payload)
        response = s.recv(4096).decode(errors="ignore")
        s.close()
        waf_patterns = [
            "cloudflare", "akamai", "incapsula", "barracuda", 
            "fortinet", "403 forbidden", "access denied", "waf",
            "blocked", "forbidden", "security policy", "mod_security"
        ]
        ttl_analysis = False
        if "TTL" in response:
            ttl_value = re.search(r"TTL=(\d+)", response)
            if ttl_value:
                ttl = int(ttl_value.group(1))
                if ttl < 50 or ttl > 200:
                    ttl_analysis = True
        rst_analysis = "RST" in response and response.count("RST") > 3
        return any(pattern in response.lower() for pattern in waf_patterns) or ttl_analysis or rst_analysis
    except:
        return False

# ... código será migrado aqui ... 