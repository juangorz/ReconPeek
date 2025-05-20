# ReconPeek v3 - Advanced Domain Intelligence Scanner
# Más potente y detallado: análisis de seguridad avanzado, detección de vulnerabilidades comunes,
# inteligencia de amenazas, recomendaciones de auditoría y reporte profesional
# Dependencias: requests, termcolor, socket, json, urllib3, ssl, dns.resolver, whois

import requests
import socket
import sys
import urllib3
import ssl
import json
import dns.resolver
import whois
from termcolor import colored
from datetime import datetime
from urllib.parse import urlparse

# Disable insecure warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Configuración
IPINFO_API = "https://ipinfo.io/"
SHODAN_API = "https://api.shodan.io/shodan/host/"  # Necesita API key
HEADERS = {"User-Agent": "ReconPeek/3.0"}
TIMEOUT = 10
TECH_DB = "technologies.json"  # Base de datos local de tecnologías

def goodprint(obj):
    if isinstance(obj, dict):
        items = [f"{k}: {v}" for k, v in obj.items()]
        print(", ".join(items))
    else:
        print(obj)

# ASCII Banner mejorado
def print_banner():
    banner = r"""
  _____                           _____             _    
 |  __ \                         |  __ \           | |   
 | |__) | ___   ___  ___   _ __  | |__) |___   ___ | | __
 |  _  / / _ \ / __|/ _ \ | '_ \ |  ___// _ \ / _ \| |/ /
 | | \ \|  __/| (__| (_) || | | || |   |  __/|  __/|   < 
 |_|  \_\\___| \___|\___/ |_| |_||_|    \___| \___||_|\_\
    v3 - Advanced Reconnaissance Toolkit
                      
"""
    print(colored(banner, 'cyan'))
    print(colored("="*60, 'blue'))
    print(colored("🔍 Domain Intelligence | Threat Assessment | Audit Prep", 'yellow'))
    print(colored("="*60, 'blue') + "\n")


def get_ip(domain):
    """Resuelve un dominio a su dirección IP"""
    try:
        return socket.gethostbyname(domain)
    except (socket.gaierror, socket.timeout) as e:
        print(colored(f"[!] Error resolviendo DNS para {domain}: {str(e)}", "red"))
        return None

def get_ipinfo(ip):
    """Obtiene información de geolocalización y ASN de una IP"""
    try:
        response = requests.get(f"{IPINFO_API}{ip}/json", headers=HEADERS, timeout=TIMEOUT)
        return response.json()
    except Exception as e:
        print(colored(f"[!] Error obteniendo información de IP: {str(e)}", "yellow"))
        return {}

def fetch_site(domain):
    """Intenta conectarse al sitio via HTTPS y HTTP"""
    for scheme in ['https', 'http']:
        url = f"{scheme}://{domain}"
        try:
            response = requests.get(url, headers=HEADERS, timeout=TIMEOUT, verify=False)
            return response
        except Exception as e:
            print(colored(f"[*] Falló {scheme}://, intentando otro esquema...", "yellow"))
            continue
    return None

# Resolución DNS avanzada
def dns_enumeration(domain):
    records = {}
    record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME', 'SOA']
    
    for rtype in record_types:
        try:
            answers = dns.resolver.resolve(domain, rtype)
            records[rtype] = [str(r) for r in answers]
        except:
            continue
    
    # Check for SPF/DKIM/DMARC
    try:
        answers = dns.resolver.resolve(f'_dmarc.{domain}', 'TXT')
        records['DMARC'] = [str(r) for r in answers]
    except:
        records['DMARC'] = "No configurado"
    
    return records

# WHOIS lookup con análisis
def whois_lookup(domain):
    try:
        w = whois.whois(domain)
        
        # Análisis básico de privacidad
        privacy_red_flags = []
        if w.get('registrar', '').lower() in ['godaddy', 'namecheap'] and not any(t in str(w.name_servers).lower() for t in ['privacy', 'protected']):
            privacy_red_flags.append("Registrante visible (considerar protección de privacidad)")
        
        if w.get('creation_date'):
            if isinstance(w.creation_date, list):
                age = (datetime.now() - w.creation_date[0]).days
            else:
                age = (datetime.now() - w.creation_date).days
        else:
            age = "Desconocido"
        
        return {
            'Registrar': w.registrar,
            'Creation Date': w.creation_date,
            'Domain Age': f"{age} días" if isinstance(age, int) else age,
            'Expiration': w.expiration_date,
            'Name Servers': w.name_servers,
            'Privacy Issues': ', '.join(privacy_red_flags) if privacy_red_flags else 'Ninguno detectado'
        }
    except Exception as e:
        return {"Error": str(e)}

# Detección de tecnologías mejorada
def load_tech_db():
    try:
        with open(TECH_DB, 'r') as f:
            return json.load(f)
    except:
        return {}

def detect_tech_advanced(html, headers):
    tech_db = load_tech_db()
    detected = set()
    
    # Convert headers to serializable dict
    headers_dict = dict(headers)
    text = (html or "").lower() + json.dumps(headers_dict).lower()
    
    # Check for technologies in database
    for tech, patterns in tech_db.items():
        for pattern in patterns.get('patterns', []):
            if re.search(pattern.lower(), text):
                detected.add(tech)
    
    # Special checks
    if 'x-powered-by' in headers_dict:
        detected.add(headers_dict['x-powered-by'].split('/')[0])
    
    if 'server' in headers_dict:
        detected.add(headers_dict['server'].split('/')[0])
    
    # Framework detection
    if 'wp-content' in text:
        detected.add('WordPress')
    if '/_next/' in text:
        detected.add('Next.js')
    if 'laravel' in text:
        detected.add('Laravel')
    
    return sorted(detected) if detected else ['No detectado']

# Análisis de seguridad de cabeceras
def analyze_security_headers(headers):
    analysis = {}
    headers = {k.lower(): v for k, v in headers.items()}
    
    # HSTS
    hsts = headers.get('strict-transport-security', '')
    analysis['HSTS'] = {
        'status': '✅ Presente' if hsts else '❌ Ausente (CRÍTICO)',
        'max-age': 'No configurado',
        'includesSubDomains': False,
        'preload': False
    }
    if hsts:
        if 'max-age=' in hsts:
            analysis['HSTS']['max-age'] = hsts.split('max-age=')[1].split(';')[0]
        analysis['HSTS']['includesSubDomains'] = 'includesubdomains' in hsts.lower()
        analysis['HSTS']['preload'] = 'preload' in hsts.lower()
    
    # CSP
    csp = headers.get('content-security-policy', '')
    analysis['CSP'] = {
        'status': '✅ Presente' if csp else '❌ Ausente (CRÍTICO)',
        'unsafe-inline': 'unsafe-inline' in csp,
        'unsafe-eval': 'unsafe-eval' in csp,
        'script-src': 'script-src' in csp
    }
    
    # XSS Protection
    xss = headers.get('x-xss-protection', '')
    analysis['XSS Protection'] = {
        'status': '✅ Presente' if xss else '❌ Ausente',
        'mode': 'block' if 'mode=block' in xss else 'No bloqueo activo'
    }
    
    # Frame Options
    frame = headers.get('x-frame-options', '')
    analysis['Clickjacking Protection'] = {
        'status': '✅ Presente' if frame else '❌ Ausente (VULNERABLE)',
        'value': frame if frame else 'No configurado'
    }
    
    # Content Type Options
    cto = headers.get('x-content-type-options', '')
    analysis['MIME Sniffing'] = {
        'status': '✅ Presente (nosniff)' if cto else '❌ Ausente (VULNERABLE)'
    }
    
    # Feature Policy / Permissions Policy
    fp = headers.get('feature-policy', '') or headers.get('permissions-policy', '')
    analysis['Feature Policy'] = {
        'status': '✅ Presente' if fp else '⚠️ Ausente (recomendado)'
    }
    
    return analysis

# Análisis de vulnerabilidades comunes
def vulnerability_scan(domain, techs, headers):
    vulns = []
    
    # WordPress
    if 'WordPress' in techs:
        vulns.append({
            'name': 'WordPress Detected',
            'risk': 'Medium',
            'description': 'WordPress es un CMS popular con vulnerabilidades frecuentes',
            'recommendation': 'Verificar versión y plugins, asegurar wp-admin'
        })
    
    # PHP
    if any(t.lower().startswith('php') for t in techs):
        vulns.append({
            'name': 'PHP Detected',
            'risk': 'Medium',
            'description': 'Versiones antiguas de PHP pueden tener vulnerabilidades críticas',
            'recommendation': 'Actualizar a la última versión estable de PHP'
        })
    
    # Missing security headers
    headers_analysis = analyze_security_headers(headers)
    if headers_analysis['HSTS']['status'].startswith('❌'):
        vulns.append({
            'name': 'Missing HSTS Header',
            'risk': 'High',
            'description': 'HSTS previene ataques SSL stripping y downgrade',
            'recommendation': 'Implementar HSTS con max-age mínimo de 6 meses'
        })
    
    if headers_analysis['CSP']['status'].startswith('❌'):
        vulns.append({
            'name': 'Missing CSP Header',
            'risk': 'Medium',
            'description': 'CSP previene XSS y ataques de inyección',
            'recommendation': 'Implementar CSP con política restrictiva'
        })
    
    # SSL issues
    ssl_info = get_ssl_info(domain)
    if ssl_info.get('protocols', {}).get('tls1.0', False):
        vulns.append({
            'name': 'TLS 1.0 Enabled',
            'risk': 'Critical',
            'description': 'TLS 1.0 es obsoleto y vulnerable a ataques POODLE',
            'recommendation': 'Deshabilitar TLS 1.0 y 1.1, usar TLS 1.2+'
        })
    
    return vulns

# Información SSL avanzada
def get_ssl_info(domain):
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=domain) as s:
            s.settimeout(TIMEOUT)
            s.connect((domain, 443))
            cert = s.getpeercert()
            
            # Protocolos soportados
            protocols = {
                'tls1.0': False,
                'tls1.1': False,
                'tls1.2': False,
                'tls1.3': False
            }
            
            try:
                for proto in ['TLSv1', 'TLSv1.1', 'TLSv1.2', 'TLSv1.3']:
                    test_ctx = ssl.SSLContext(protocol=getattr(ssl, f"PROTOCOL_{proto}"))
                    with test_ctx.wrap_socket(socket.socket(), server_hostname=domain) as test_s:
                        test_s.connect((domain, 443))
                        protocols[proto.lower().replace('v','')] = True
            except:
                pass
            
            # Cipher analysis
            cipher = s.cipher()
            
            return {
                'issuer': dict(x[0] for x in cert['issuer']),
                'subject': dict(x[0] for x in cert['subject']),
                'version': cert.get('version'),
                'serialNumber': cert.get('serialNumber'),
                'notBefore': cert.get('notBefore'),
                'notAfter': cert.get('notAfter'),
                'protocols': protocols,
                'cipher': {
                    'name': cipher[0],
                    'version': cipher[1],
                    'bits': cipher[2]
                }
            }
    except Exception as e:
        return {'error': str(e)}

# Generar recomendaciones de auditoría
def generate_audit_recommendations(data):
    recs = []
    
    # Seguridad básica
    if not data['security_headers']['HSTS']['status'].startswith('✅'):
        recs.append("Implementar HSTS para seguridad SSL/TLS")
    
    if not data['security_headers']['CSP']['status'].startswith('✅'):
        recs.append("Implementar Content Security Policy para mitigar XSS")
    
    # Tecnologías
    if 'WordPress' in data['technologies']:
        recs.append("Realizar escaneo de plugins y temas de WordPress vulnerables")
    
    if any(t.lower().startswith('php') for t in data['technologies']):
        recs.append("Verificar versión de PHP por vulnerabilidades conocidas")
    
    # SSL
    if data['ssl_info'].get('protocols', {}).get('tls1.0', False):
        recs.append("Deshabilitar TLS 1.0 y 1.1 inmediatamente")
    
    # DNS
    if data['dns_records'].get('DMARC', '') == 'No configurado':
        recs.append("Configurar DMARC para protección contra spoofing de email")
    
    return recs

# Visualización de resultados mejorada
def print_results(data):
    # Información básica
    print(colored("\n[🔍 INFORMACIÓN BÁSICA]", 'yellow'))
    basic_info = {
        'Dominio': data['domain'],
        'IP': data['ip'],
        'País': f"{data['ip_info'].get('country','?')} {country_flag(data['ip_info'].get('country',''))}",
        'Ciudad': data['ip_info'].get('city', '-'),
        'Proveedor': data['ip_info'].get('org', '-'),
        'ASN': data['ip_info'].get('asn',{}).get('asn','-') if isinstance(data['ip_info'].get('asn'), dict) else '-',
        'Servidor Web': data['response'].headers.get('Server', '-'),
        'Tecnologías': ', '.join(data['technologies'])
    }
    print(basic_info)
    
    # WHOIS
    print(colored("\n[📝 REGISTRO WHOIS]", 'yellow'))
    goodprint(data['whois'])
    
    # DNS
    print(colored("\n[🌐 REGISTROS DNS]", 'yellow'))
    dns_data = {k: '\n'.join(v) if isinstance(v, list) else v for k, v in data['dns_records'].items()}
    goodprint(dns_data)
    
    # SSL
    print(colored("\n[🔒 CERTIFICADO SSL]", 'yellow'))
    ssl_data = {
        'Emisor': data['ssl_info'].get('issuer', {}).get('organizationName', '-'),
        'Válido desde': data['ssl_info'].get('notBefore', '-'),
        'Expira': data['ssl_info'].get('notAfter', '-'),
        'Protocolos': ', '.join([k for k, v in data['ssl_info'].get('protocols', {}).items() if v]),
        'Cipher': f"{data['ssl_info'].get('cipher', {}).get('name', '-')} ({data['ssl_info'].get('cipher', {}).get('bits', '?')} bits)"
    }
    goodprint(ssl_data)
    
    # Cabeceras de seguridad
    print(colored("\n[🛡️ CABECERAS DE SEGURIDAD]", 'yellow'))
    sec_headers = {
        'HSTS': data['security_headers']['HSTS']['status'],
        'Max Age': data['security_headers']['HSTS']['max-age'],
        'CSP': data['security_headers']['CSP']['status'],
        'XSS Protection': data['security_headers']['XSS Protection']['status'],
        'Clickjacking': data['security_headers']['Clickjacking Protection']['status'],
        'MIME Sniffing': data['security_headers']['MIME Sniffing']['status']
    }
    goodprint(sec_headers)
    
    # Vulnerabilidades
    if data['vulnerabilities']:
        print(colored("\n[⚠️ VULNERABILIDADES DETECTADAS]", 'red'))
        for i, vuln in enumerate(data['vulnerabilities'], 1):
            print(colored(f"\nVULN {i}: {vuln['name']} ({vuln['risk']})", 'red'))
            print(f"Descripción: {vuln['description']}")
            print(f"Recomendación: {vuln['recommendation']}")
    
    # Recomendaciones para auditoría
    goodprint(colored("\n[📋 RECOMENDACIONES PARA AUDITORÍA]", 'green'))
    for i, rec in enumerate(data['audit_recommendations'], 1):
        print(f"{i}. {rec}")

# Country flag helper
def country_flag(code):
    if not code: return ''
    OFFSET = 127397
    return ''.join([chr(ord(c) + OFFSET) for c in code.upper()])




# Main recon function
def recon_domain(domain):
    print_banner()
    print(colored(f"[+] Iniciando análisis avanzado de {domain}...\n", "cyan"))
    
    # Resolución básica
    ip = get_ip(domain)
    if not ip:
        print(colored("[!] No se pudo resolver el dominio.", "red"))
        return
    
    # Recolección de datos
    goodprint(colored("[*] Recolectando información básica...", 'yellow'))
    ip_info = get_ipinfo(ip)
    response = fetch_site(domain)
    if not response:
        print(colored("[!] No se pudo conectar al sitio.", "red"))
        return
    
    goodprint(colored("[*] Realizando enumeración DNS...", 'yellow'))
    dns_records = dns_enumeration(domain)
    
    goodprint(colored("[*] Consultando información WHOIS...", 'yellow'))
    whois_info = whois_lookup(domain)
    
    goodprint(colored("[*] Analizando certificado SSL...", 'yellow'))
    ssl_info = get_ssl_info(domain)
    
    goodprint(colored("[*] Detectando tecnologías...", 'yellow'))
    technologies = detect_tech_advanced(response.text, response.headers)
    
    goodprint(colored("[*] Evaluando cabeceras de seguridad...", 'yellow'))
    security_headers = analyze_security_headers(response.headers)
    
    goodprint(colored("[*] Escaneando vulnerabilidades comunes...", 'yellow'))
    vulnerabilities = vulnerability_scan(domain, technologies, response.headers)
    
    goodprint(colored("[*] Generando recomendaciones...", 'yellow'))
    audit_recommendations = generate_audit_recommendations({
        'security_headers': security_headers,
        'technologies': technologies,
        'ssl_info': ssl_info,
        'dns_records': dns_records
    })
    
    # Compilar resultados
    results = {
        'domain': domain,
        'ip': ip,
        'ip_info': ip_info,
        'response': response,
        'dns_records': dns_records,
        'whois': whois_info,
        'ssl_info': ssl_info,
        'technologies': technologies,
        'security_headers': security_headers,
        'vulnerabilities': vulnerabilities,
        'audit_recommendations': audit_recommendations
    }
    
    # Mostrar resultados
    print_results(results)
    
    # Guardar informe
    save_report(domain, results)

# Guardar informe en JSON
def save_report(domain, data):
    filename = f"reconpeek_{domain}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    try:
        with open(filename, 'w') as f:
            json.dump(data, f, indent=2, default=str)
        print(colored(f"\n[+] Informe guardado como {filename}", 'green'))
    except Exception as e:
        print(colored(f"\n[!] Error guardando informe: {str(e)}", 'red'))

# Entry point
if __name__ == '__main__':
    if len(sys.argv) != 2:
        print(colored("Uso: python3 reconpeek.py dominio.com", 'red'))
        sys.exit(1)
    
    domain = urlparse(sys.argv[1]).netloc or sys.argv[1]
    recon_domain(domain)