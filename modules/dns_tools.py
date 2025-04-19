import dns.resolver
import dns.zone
import dns.query
import dns.name
import dns.message
import dns.rdatatype
import dns.rdataclass
import dns.exception
import logging
from typing import Dict, List, Optional
import requests
import concurrent.futures
import socket
import re

class DNSTools:
    def __init__(self):
        self.resolver = dns.resolver.Resolver()
        self.resolver.timeout = 2
        self.resolver.lifetime = 2
        self.common_subdomains = [
            'www', 'mail', 'ftp', 'smtp', 'pop', 'ns1', 'ns2', 'ns3', 'ns4',
            'admin', 'blog', 'dev', 'test', 'stage', 'staging', 'api', 'cdn',
            'cloud', 'shop', 'store', 'app', 'beta', 'secure', 'vpn', 'remote',
            'internal', 'external', 'corp', 'corporate', 'intranet', 'portal',
            'support', 'help', 'docs', 'wiki', 'git', 'svn', 'jenkins', 'jira',
            'confluence', 'monitor', 'status', 'stats', 'analytics', 'tracker'
        ]
        
    def find_subdomains(self, domain: str) -> Dict:
        """
        Find subdomains using multiple techniques.
        
        Args:
            domain: Target domain
            
        Returns:
            Dictionary containing found subdomains and metadata
        """
        try:
            results = {
                "domain": domain,
                "subdomains": [],
                "techniques": [],
                "errors": []
            }
            
            # Technique 1: DNS Zone Transfer
            try:
                results["techniques"].append("DNS Zone Transfer")
                zone_results = self._try_zone_transfer(domain)
                if zone_results:
                    results["subdomains"].extend(zone_results)
            except Exception as e:
                results["errors"].append(f"Zone Transfer failed: {str(e)}")
                
            # Technique 2: Common Subdomain Enumeration
            try:
                results["techniques"].append("Common Subdomain Enumeration")
                common_results = self._check_common_subdomains(domain)
                results["subdomains"].extend(common_results)
            except Exception as e:
                results["errors"].append(f"Common subdomain check failed: {str(e)}")
                
            # Technique 3: Certificate Transparency Logs
            try:
                results["techniques"].append("Certificate Transparency Logs")
                ct_results = self._check_ct_logs(domain)
                results["subdomains"].extend(ct_results)
            except Exception as e:
                results["errors"].append(f"CT logs check failed: {str(e)}")
                
            # Remove duplicates and sort
            results["subdomains"] = sorted(list(set(results["subdomains"])))
            
            return results
            
        except Exception as e:
            logging.error(f"Error in subdomain enumeration: {str(e)}")
            return {
                "error": f"Subdomain enumeration failed: {str(e)}",
                "domain": domain
            }
            
    def _try_zone_transfer(self, domain: str) -> List[str]:
        """Attempt DNS zone transfer."""
        subdomains = []
        try:
            # Get nameservers
            ns_records = self.resolver.resolve(domain, 'NS')
            for ns in ns_records:
                try:
                    zone = dns.zone.from_xfr(dns.query.xfr(str(ns), domain))
                    for name, _ in zone.nodes.items():
                        subdomains.append(f"{name}.{domain}")
                except:
                    continue
        except:
            pass
        return subdomains
        
    def _check_common_subdomains(self, domain: str) -> List[str]:
        """Check for common subdomains."""
        found_subdomains = []
        
        def check_subdomain(subdomain):
            try:
                full_domain = f"{subdomain}.{domain}"
                socket.gethostbyname(full_domain)
                return full_domain
            except:
                return None
                
        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            futures = [executor.submit(check_subdomain, sub) for sub in self.common_subdomains]
            for future in concurrent.futures.as_completed(futures):
                result = future.result()
                if result:
                    found_subdomains.append(result)
                    
        return found_subdomains
        
    def _check_ct_logs(self, domain: str) -> List[str]:
        """Check Certificate Transparency logs."""
        subdomains = []
        try:
            # Using crt.sh API
            url = f"https://crt.sh/?q=%.{domain}&output=json"
            response = requests.get(url, timeout=5)
            if response.status_code == 200:
                data = response.json()
                for entry in data:
                    name_value = entry.get('name_value', '')
                    if name_value and domain in name_value:
                        subdomains.append(name_value)
        except:
            pass
        return subdomains
        
    def get_all_dns_records(self, domain: str) -> Dict:
        """
        Get all DNS records for a domain.
        
        Args:
            domain: Target domain
            
        Returns:
            Dictionary containing DNS records
        """
        try:
            results = {
                "domain": domain,
                "records": {},
                "errors": []
            }
            
            record_types = ['A', 'AAAA', 'CNAME', 'MX', 'NS', 'TXT', 'SOA', 'SRV']
            
            for record_type in record_types:
                try:
                    answers = self.resolver.resolve(domain, record_type)
                    results["records"][record_type] = [str(rdata) for rdata in answers]
                except dns.resolver.NoAnswer:
                    results["records"][record_type] = []
                except dns.resolver.NXDOMAIN:
                    results["errors"].append(f"Domain {domain} does not exist")
                    break
                except Exception as e:
                    results["errors"].append(f"Error resolving {record_type} records: {str(e)}")
                    
            return results
            
        except Exception as e:
            logging.error(f"Error getting DNS records: {str(e)}")
            return {
                "error": f"DNS record lookup failed: {str(e)}",
                "domain": domain
            }
            
    def get_reverse_dns(self, ip: str) -> Dict:
        """
        Perform reverse DNS lookup.
        
        Args:
            ip: IP address
            
        Returns:
            Dictionary containing reverse DNS information
        """
        try:
            # Validate IP address
            try:
                socket.inet_aton(ip)
            except socket.error:
                return {"error": f"Invalid IP address: {ip}"}
                
            results = {
                "ip": ip,
                "hostnames": [],
                "errors": []
            }
            
            try:
                hostnames = socket.gethostbyaddr(ip)
                results["hostnames"] = hostnames[0]
            except socket.herror as e:
                results["errors"].append(f"Reverse DNS lookup failed: {str(e)}")
                
            return results
            
        except Exception as e:
            logging.error(f"Error in reverse DNS lookup: {str(e)}")
            return {
                "error": f"Reverse DNS lookup failed: {str(e)}",
                "ip": ip
            }
            
    def validate_domain(self, domain: str) -> bool:
        """Validate domain name format."""
        pattern = r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
        return bool(re.match(pattern, domain))
        
    def get_dns_servers(self, domain: str) -> Dict:
        """
        Get DNS servers for a domain.
        
        Args:
            domain: Target domain
            
        Returns:
            Dictionary containing DNS server information
        """
        try:
            results = {
                "domain": domain,
                "nameservers": [],
                "errors": []
            }
            
            try:
                answers = self.resolver.resolve(domain, 'NS')
                results["nameservers"] = [str(ns) for ns in answers]
            except dns.resolver.NXDOMAIN:
                results["errors"].append(f"Domain {domain} does not exist")
            except Exception as e:
                results["errors"].append(f"Error resolving nameservers: {str(e)}")
                
            return results
            
        except Exception as e:
            logging.error(f"Error getting DNS servers: {str(e)}")
            return {
                "error": f"DNS server lookup failed: {str(e)}",
                "domain": domain
            }
        
    def scan(self, domain: str) -> Dict:
        """Main scanning function."""
        if not self.validate_domain(domain):
            raise ValueError("Invalid domain format")
            
        try:
            # Get all DNS records
            dns_records = self.get_all_dns_records(domain)
            
            # Find subdomains
            subdomains = self.find_subdomains(domain)
            
            # Get IP addresses
            ip_addresses = []
            for record in dns_records['records']['A'] + dns_records['records']['AAAA']:
                ip_addresses.append(record)
                
            # Get reverse DNS for IPs
            reverse_dns = {}
            for ip in ip_addresses:
                reverse_dns[ip] = self.get_reverse_dns(ip)
                
            return {
                "domain": domain,
                "dns_records": dns_records,
                "subdomains": subdomains,
                "ip_addresses": ip_addresses,
                "reverse_dns": reverse_dns
            }
        except Exception as e:
            logging.error(f"Error during DNS scan: {str(e)}")
            raise 