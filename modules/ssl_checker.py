import ssl
import socket
import OpenSSL
from datetime import datetime
import logging
from typing import Dict, Optional, List
import requests

class SSLChecker:
    def __init__(self):
        self.timeout = 10
        self.weak_ciphers = [
            'RC4', 'DES', '3DES', 'MD5', 'SHA1', 'NULL', 'EXPORT', 'LOW'
        ]
        
    def validate_host(self, host: str) -> bool:
        """Validate host format."""
        try:
            # Remove protocol if present
            if host.startswith(('http://', 'https://')):
                host = host.split('://')[1]
                
            # Remove path if present
            host = host.split('/')[0]
            
            # Check if it's a valid host
            socket.gethostbyname(host)
            return True
        except:
            return False
            
    def get_certificate(self, host: str, port: int = 443) -> Optional[OpenSSL.crypto.X509]:
        """Get SSL certificate from host."""
        try:
            context = ssl.create_default_context()
            with socket.create_connection((host, port)) as sock:
                with context.wrap_socket(sock, server_hostname=host) as ssock:
                    cert = ssock.getpeercert(binary_form=True)
                    return OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_ASN1, cert)
        except Exception as e:
            logging.error(f"Error getting certificate: {str(e)}")
            return None
            
    def check_certificate_validity(self, cert: OpenSSL.crypto.X509) -> Dict:
        """Check certificate validity period."""
        try:
            not_before = datetime.strptime(cert.get_notBefore().decode('ascii'), '%Y%m%d%H%M%SZ')
            not_after = datetime.strptime(cert.get_notAfter().decode('ascii'), '%Y%m%d%H%M%SZ')
            now = datetime.now()
            
            return {
                "valid_from": not_before,
                "valid_until": not_after,
                "is_valid": not_before <= now <= not_after,
                "days_remaining": (not_after - now).days if now <= not_after else 0
            }
        except Exception as e:
            logging.error(f"Error checking certificate validity: {str(e)}")
            return {
                "valid_from": None,
                "valid_until": None,
                "is_valid": False,
                "days_remaining": 0
            }
            
    def check_certificate_issuer(self, cert: OpenSSL.crypto.X509) -> Dict:
        """Get certificate issuer information."""
        try:
            issuer = {}
            for component in cert.get_issuer().get_components():
                key = component[0].decode('ascii')
                value = component[1].decode('ascii')
                issuer[key] = value
            return issuer
        except Exception as e:
            logging.error(f"Error checking certificate issuer: {str(e)}")
            return {}
            
    def check_certificate_subject(self, cert: OpenSSL.crypto.X509) -> Dict:
        """Get certificate subject information."""
        try:
            subject = {}
            for component in cert.get_subject().get_components():
                key = component[0].decode('ascii')
                value = component[1].decode('ascii')
                subject[key] = value
            return subject
        except Exception as e:
            logging.error(f"Error checking certificate subject: {str(e)}")
            return {}
            
    def check_weak_ciphers(self, host: str) -> List[str]:
        """Check for weak SSL/TLS ciphers."""
        weak_ciphers_found = []
        try:
            context = ssl.create_default_context()
            with socket.create_connection((host, 443)) as sock:
                with context.wrap_socket(sock, server_hostname=host) as ssock:
                    cipher = ssock.cipher()
                    if cipher:
                        for weak_cipher in self.weak_ciphers:
                            if weak_cipher in cipher[0].upper():
                                weak_ciphers_found.append(cipher[0])
        except Exception as e:
            logging.error(f"Error checking weak ciphers: {str(e)}")
            
        return weak_ciphers_found
        
    def check_http_redirect(self, host: str) -> bool:
        """Check if HTTP redirects to HTTPS."""
        try:
            url = f"http://{host}"
            response = requests.get(url, allow_redirects=True, timeout=self.timeout)
            return response.url.startswith('https://')
        except:
            return False
            
    def check_hsts(self, host: str) -> bool:
        """Check if HSTS is enabled."""
        try:
            url = f"https://{host}"
            response = requests.get(url, timeout=self.timeout)
            return 'Strict-Transport-Security' in response.headers
        except:
            return False
            
    def scan(self, host: str) -> Dict:
        """Main scanning function."""
        if not self.validate_host(host):
            raise ValueError("Invalid host format")
            
        try:
            # Get certificate
            cert = self.get_certificate(host)
            if not cert:
                raise ValueError("Could not retrieve SSL certificate")
                
            # Check certificate validity
            validity = self.check_certificate_validity(cert)
            
            # Get certificate details
            issuer = self.check_certificate_issuer(cert)
            subject = self.check_certificate_subject(cert)
            
            # Check for weak ciphers
            weak_ciphers = self.check_weak_ciphers(host)
            
            # Check security headers
            http_redirect = self.check_http_redirect(host)
            hsts_enabled = self.check_hsts(host)
            
            return {
                "host": host,
                "validity": validity,
                "issuer": issuer,
                "subject": subject,
                "weak_ciphers": weak_ciphers,
                "security": {
                    "http_redirects_to_https": http_redirect,
                    "hsts_enabled": hsts_enabled
                }
            }
        except Exception as e:
            logging.error(f"Error during SSL scan: {str(e)}")
            raise 