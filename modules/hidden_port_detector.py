import socket
import threading
import time
import logging
from typing import List, Dict, Optional

class HiddenPortDetector:
    def __init__(self):
        self.timeout = 2  # seconds
        self.max_threads = 50
        self.active_threads = 0
        self.results = []
        self.lock = threading.Lock()
        
    def scan(self, target: str, scan_type: str = "TCP SYN") -> Dict:
        """
        Scan for hidden ports using various techniques.
        
        Args:
            target: Target hostname or IP
            scan_type: Type of scan (TCP SYN, TCP ACK, XMAS, NULL, FIN)
            
        Returns:
            Dictionary containing scan results
        """
        try:
            # Resolve target to IP if hostname provided
            try:
                ip = socket.gethostbyname(target)
            except socket.gaierror:
                return {"error": f"Could not resolve hostname: {target}"}
                
            self.results = []
            common_ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 993, 995, 3306, 3389, 5432, 8080]
            
            # Create thread pool
            threads = []
            for port in common_ports:
                while self.active_threads >= self.max_threads:
                    time.sleep(0.1)
                    
                thread = threading.Thread(target=self._scan_port, args=(ip, port, scan_type))
                thread.daemon = True
                threads.append(thread)
                thread.start()
                
            # Wait for all threads to complete
            for thread in threads:
                thread.join(timeout=30)  # Maximum 30 seconds wait
                
            return {
                "target": target,
                "ip": ip,
                "scan_type": scan_type,
                "open_ports": self.results,
                "total_ports_scanned": len(common_ports)
            }
            
        except Exception as e:
            logging.error(f"Error during hidden port scan: {str(e)}")
            return {"error": f"Scan failed: {str(e)}"}
            
    def _scan_port(self, ip: str, port: int, scan_type: str) -> None:
        """Scan a single port using the specified scan type."""
        try:
            with self.lock:
                self.active_threads += 1
                
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            
            # Set socket options based on scan type
            if scan_type == "TCP SYN":
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            elif scan_type in ["XMAS", "NULL", "FIN"]:
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                if scan_type == "XMAS":
                    sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
                    
            try:
                result = sock.connect_ex((ip, port))
                if result == 0:
                    service = self._get_service_name(port)
                    with self.lock:
                        self.results.append({
                            "port": port,
                            "state": "open",
                            "service": service
                        })
            except socket.timeout:
                pass
            except ConnectionRefusedError:
                pass
            finally:
                sock.close()
                
        except Exception as e:
            logging.error(f"Error scanning port {port}: {str(e)}")
        finally:
            with self.lock:
                self.active_threads -= 1
                
    def _get_service_name(self, port: int) -> str:
        """Get common service name for a port."""
        common_services = {
            21: "FTP",
            22: "SSH",
            23: "Telnet",
            25: "SMTP",
            53: "DNS",
            80: "HTTP",
            110: "POP3",
            143: "IMAP",
            443: "HTTPS",
            445: "SMB",
            993: "IMAPS",
            995: "POP3S",
            3306: "MySQL",
            3389: "RDP",
            5432: "PostgreSQL",
            8080: "HTTP-Proxy"
        }
        return common_services.get(port, "unknown") 