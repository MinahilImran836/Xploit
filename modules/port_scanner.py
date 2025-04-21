import socket
import threading
from queue import Queue
from typing import Tuple, Dict

class PortScanner:
    def __init__(self):
        self.threads = 100
        self.timeout = 1
        self.ports = Queue()
        self.open_ports = []
        self.closed_ports = []
        self.filtered_ports = []
        self.scanning = False
        
    def validate_ip(self, ip: str) -> bool:
        """Validate IP address format."""
        try:
            parts = ip.split('.')
            if len(parts) != 4:
                return False
            for part in parts:
                if not part.isdigit() or not 0 <= int(part) <= 255:
                    return False
            return True
        except:
            return False
            
    def validate_hostname(self, hostname: str) -> bool:
        """Validate hostname format."""
        try:
            socket.gethostbyname(hostname)
            return True
        except socket.gaierror:
            return False
            
    def validate_port_range(self, start: int, end: int) -> bool:
        """Validate port range."""
        try:
            if not (1 <= start <= 65535 and 1 <= end <= 65535):
                return False
            if start > end:
                return False
            return True
        except:
            return False
            
    def scan_port(self, target: str, port: int) -> Tuple[int, str]:
        """Scan a single port."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            result = sock.connect_ex((target, port))
            sock.close()
            
            if result == 0:
                return (port, "open")
            elif result == 111:  # Connection refused
                return (port, "closed")
            else:
                return (port, "filtered")
        except:
            return (port, "error")
            
    def worker(self, target: str) -> None:
        """Worker thread for port scanning."""
        while not self.ports.empty() and self.scanning:
            port = self.ports.get()
            result = self.scan_port(target, port)
            
            if result[1] == "open":
                self.open_ports.append(result[0])
            elif result[1] == "closed":
                self.closed_ports.append(result[0])
            elif result[1] == "filtered":
                self.filtered_ports.append(result[0])
                
            self.ports.task_done()
            
    def scan(self, target: str, start_port: int = 1, end_port: int = 1024) -> Dict:
        """Main scanning function."""
        # Reset results
        self.open_ports = []
        self.closed_ports = []
        self.filtered_ports = []
        
        # Validate inputs
        if not (self.validate_ip(target) or self.validate_hostname(target)):
            raise ValueError("Invalid target IP or hostname")
            
        if not self.validate_port_range(start_port, end_port):
            raise ValueError("Invalid port range")
            
        # Fill queue with ports to scan
        for port in range(start_port, end_port + 1):
            self.ports.put(port)
            
        # Start scanning
        self.scanning = True
        threads = []
        
        for _ in range(self.threads):
            thread = threading.Thread(target=self.worker, args=(target,))
            thread.daemon = True
            thread.start()
            threads.append(thread)
            
        # Wait for all ports to be scanned
        self.ports.join()
        self.scanning = False
        
        # Wait for all threads to complete
        for thread in threads:
            thread.join()
            
        # Return results
        return {
            "open": sorted(self.open_ports),
            "closed": sorted(self.closed_ports),
            "filtered": sorted(self.filtered_ports)
        } 