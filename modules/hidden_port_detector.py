import socket
import threading
import time
import logging
import os
import sys
import platform
from typing import Dict
from scapy.all import (
    IP,
    TCP,
    sr1,
    send,
    conf,
    get_if_list,
    get_if_addr,
    get_if_hwaddr,
    get_if_addr,
    get_if_list,
    get_working_ifaces,
)
from scapy.sendrecv import sr1
from scapy.layers.l2 import ARP, Ether


class HiddenPortDetector:
    def __init__(self):
        self.timeout = 2  # seconds
        self.max_threads = 50
        self.active_threads = 0
        self.results = []
        self.lock = threading.Lock()
        # Disable Scapy warnings
        conf.verb = 0
        # Set default timeout
        conf.timeout = self.timeout
        # Define supported scan types
        self.supported_scan_types = ["TCP SYN", "TCP ACK", "XMAS", "NULL", "FIN"]
        # Check if running with admin privileges
        self.is_admin = self._check_admin_privileges()
        # Check for Npcap
        self.npcap_installed = self._check_npcap()
        # Get working interface
        self.working_iface = self._get_working_interface()

        if (
            not self.is_admin
            and platform.system() == "Windows"
            and not self.npcap_installed
        ):
            logging.warning(
                "Not running with administrator privileges and Npcap not detected. Some scan types may not work properly."
            )

    def _check_admin_privileges(self):
        """Check if the application is running with administrator privileges."""
        try:
            if platform.system() == "Windows":
                import ctypes

                return ctypes.windll.shell32.IsUserAnAdmin() != 0
            else:
                return os.geteuid() == 0
        except:
            return False

    def _check_npcap(self):
        """Check if Npcap is installed and available."""
        try:
            # Try to get network interfaces - this will fail if Npcap is not installed
            interfaces = get_if_list()
            if interfaces:
                # Try to get an IP address from one of the interfaces
                for iface in interfaces:
                    if get_if_addr(iface):
                        return True
            return False
        except Exception as e:
            logging.error(f"Error checking for Npcap: {str(e)}")
            return False

    def _get_working_interface(self):
        """Get a working network interface for packet sending."""
        try:
            # Try to get working interfaces
            working_ifaces = get_working_ifaces()
            if working_ifaces:
                # Use the first working interface
                return working_ifaces[0]

            # Fallback to getting all interfaces
            ifaces = get_if_list()
            for iface in ifaces:
                # Check if interface has an IP address
                if get_if_addr(iface):
                    return iface

            # If no interface with IP found, return None
            return None
        except Exception as e:
            logging.error(f"Error getting working interface: {str(e)}")
            return None

    def scan(self, target: str, scan_type: str = "TCP SYN") -> Dict:
        try:
            # Validate scan type
            if scan_type not in self.supported_scan_types:
                return {
                    "error": f"Unsupported scan type: {scan_type}. Supported types are: {', '.join(self.supported_scan_types)}"
                }

            # Check for admin privileges or Npcap on Windows
            if (
                platform.system() == "Windows"
                and not self.is_admin
                and not self.npcap_installed
            ):
                return {
                    "error": "Administrator privileges or Npcap required for stealth scanning on Windows. "
                    "Please run the application as administrator or install Npcap. "
                    "For more information, visit: https://npcap.com/#download"
                }

            try:
                ip = socket.gethostbyname(target)
            except socket.gaierror:
                return {"error": f"Could not resolve hostname: {target}"}

            # Check if we have a working interface
            if not self.working_iface:
                return {
                    "error": "No working network interface found. Please check your network connection."
                }

            # Try to resolve MAC address for the target
            try:
                # Use ARP to get the MAC address
                arp_request = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip)
                arp_response = sr1(arp_request, timeout=1, verbose=0)

                if arp_response and arp_response.haslayer(ARP):
                    target_mac = arp_response[ARP].hwsrc
                    logging.info(f"Resolved MAC address for {ip}: {target_mac}")
                else:
                    logging.warning(
                        f"Could not resolve MAC address for {ip}. Using broadcast."
                    )
            except Exception as e:
                logging.warning(f"Error resolving MAC address: {str(e)}")

            self.results = []
            common_ports = [
                21,
                22,
                23,
                25,
                53,
                80,
                110,
                143,
                443,
                445,
                993,
                995,
                3306,
                3389,
                5432,
                8080,
            ]
            threads = []
            for port in common_ports:
                while self.active_threads >= self.max_threads:
                    time.sleep(0.1)

                thread = threading.Thread(
                    target=self._scan_port, args=(ip, port, scan_type)
                )
                thread.daemon = True
                threads.append(thread)
                thread.start()
            for thread in threads:
                thread.join(timeout=30)

            return {
                "target": target,
                "ip": ip,
                "scan_type": scan_type,
                "open_ports": self.results,
                "total_ports_scanned": len(common_ports),
            }

        except Exception as e:
            logging.error(f"Error during hidden port scan: {str(e)}")
            return {"error": f"Scan failed: {str(e)}"}

    def _scan_port(self, ip: str, port: int, scan_type: str) -> None:
        try:
            with self.lock:
                self.active_threads += 1

            # Create IP packet
            ip_packet = IP(dst=ip)

            # Create TCP packet based on scan type
            if scan_type == "TCP SYN":
                # SYN scan - send SYN packet, expect SYN-ACK
                tcp_packet = TCP(dport=port, flags="S")
                try:
                    # Use the working interface if available
                    if self.working_iface:
                        response = sr1(
                            ip_packet / tcp_packet,
                            timeout=self.timeout,
                            verbose=0,
                            iface=self.working_iface,
                        )
                    else:
                        response = sr1(
                            ip_packet / tcp_packet, timeout=self.timeout, verbose=0
                        )

                    if response and response.haslayer(TCP):
                        tcp_layer = response.getlayer(TCP)
                        if tcp_layer.flags == 0x12:  # SYN-ACK
                            service = self._get_service_name(port)
                            with self.lock:
                                self.results.append(
                                    {"port": port, "state": "open", "service": service}
                                )
                        elif tcp_layer.flags == 0x14:  # RST-ACK
                            # Port is closed
                            pass

                    # Send RST to close the connection
                    rst_packet = TCP(dport=port, flags="R")
                    if self.working_iface:
                        send(
                            ip_packet / rst_packet, verbose=0, iface=self.working_iface
                        )
                    else:
                        send(ip_packet / rst_packet, verbose=0)
                except Exception as e:
                    logging.error(f"Error during SYN scan on port {port}: {str(e)}")

            elif scan_type == "FIN":
                # FIN scan - send FIN packet, expect RST if closed, no response if open
                tcp_packet = TCP(dport=port, flags="F")
                try:
                    # Use the working interface if available
                    if self.working_iface:
                        response = sr1(
                            ip_packet / tcp_packet,
                            timeout=self.timeout,
                            verbose=0,
                            iface=self.working_iface,
                        )
                    else:
                        response = sr1(
                            ip_packet / tcp_packet, timeout=self.timeout, verbose=0
                        )

                    if not response:
                        # No response means port might be open
                        service = self._get_service_name(port)
                        with self.lock:
                            self.results.append(
                                {
                                    "port": port,
                                    "state": "open|filtered",
                                    "service": service,
                                }
                            )
                except Exception as e:
                    logging.error(f"Error during FIN scan on port {port}: {str(e)}")

            elif scan_type == "NULL":
                # NULL scan - send packet with no flags, expect RST if closed, no response if open
                tcp_packet = TCP(dport=port, flags="")
                try:
                    # Use the working interface if available
                    if self.working_iface:
                        response = sr1(
                            ip_packet / tcp_packet,
                            timeout=self.timeout,
                            verbose=0,
                            iface=self.working_iface,
                        )
                    else:
                        response = sr1(
                            ip_packet / tcp_packet, timeout=self.timeout, verbose=0
                        )

                    if not response:
                        # No response means port might be open
                        service = self._get_service_name(port)
                        with self.lock:
                            self.results.append(
                                {
                                    "port": port,
                                    "state": "open|filtered",
                                    "service": service,
                                }
                            )
                except Exception as e:
                    logging.error(f"Error during NULL scan on port {port}: {str(e)}")

            elif scan_type == "XMAS":
                # XMAS scan - send packet with FIN, PSH, URG flags, expect RST if closed, no response if open
                tcp_packet = TCP(dport=port, flags="FPU")
                try:
                    # Use the working interface if available
                    if self.working_iface:
                        response = sr1(
                            ip_packet / tcp_packet,
                            timeout=self.timeout,
                            verbose=0,
                            iface=self.working_iface,
                        )
                    else:
                        response = sr1(
                            ip_packet / tcp_packet, timeout=self.timeout, verbose=0
                        )

                    if not response:
                        # No response means port might be open
                        service = self._get_service_name(port)
                        with self.lock:
                            self.results.append(
                                {
                                    "port": port,
                                    "state": "open|filtered",
                                    "service": service,
                                }
                            )
                except Exception as e:
                    logging.error(f"Error during XMAS scan on port {port}: {str(e)}")

            elif scan_type == "TCP ACK":
                # ACK scan - send ACK packet, expect RST if unfiltered, no response if filtered
                tcp_packet = TCP(dport=port, flags="A")
                try:
                    # Use the working interface if available
                    if self.working_iface:
                        response = sr1(
                            ip_packet / tcp_packet,
                            timeout=self.timeout,
                            verbose=0,
                            iface=self.working_iface,
                        )
                    else:
                        response = sr1(
                            ip_packet / tcp_packet, timeout=self.timeout, verbose=0
                        )

                    if response and response.haslayer(TCP):
                        tcp_layer = response.getlayer(TCP)
                        if tcp_layer.flags == 0x14:  # RST-ACK
                            # Port is unfiltered
                            service = self._get_service_name(port)
                            with self.lock:
                                self.results.append(
                                    {
                                        "port": port,
                                        "state": "unfiltered",
                                        "service": service,
                                    }
                                )
                except Exception as e:
                    logging.error(f"Error during ACK scan on port {port}: {str(e)}")

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
            8080: "HTTP-Proxy",
        }
        return common_services.get(port, "unknown")
