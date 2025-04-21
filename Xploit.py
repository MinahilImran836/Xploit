# !/usr/bin/env python3
import sys
import logging
import os
from PyQt5.QtWidgets import (
    QApplication,
    QMainWindow,
    QTabWidget,
    QWidget,
    QVBoxLayout,
    QHBoxLayout,
    QPushButton,
    QLabel,
    QLineEdit,
    QTextEdit,
    QProgressBar,
    QMessageBox,
    QComboBox,
    QGroupBox,
    QCheckBox,
    QSpinBox,
    QFileDialog,
    QStyleFactory,
)
from PyQt5.QtCore import Qt
from PyQt5.QtGui import QPalette, QColor
from PyQt5.QtWidgets import QApplication

from modules.port_scanner import PortScanner
from modules.web_scanner import WebScanner
from modules.dns_tools import DNSTools
from modules.ssl_checker import SSLChecker
from modules.hidden_port_detector import HiddenPortDetector
from modules.password_cracker import PasswordCracker
from modules.exploit_launcher import ExploitLauncher
from modules.report_generator import ReportGenerator

logging.basicConfig(
    filename="Xploit.log",
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
)


class Xploit(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Xploit - Penetration Testing Tool")
        self.setGeometry(100, 100, 1200, 800)

        self.port_scanner = PortScanner()
        self.web_scanner = WebScanner()
        self.dns_tools = DNSTools()
        self.ssl_checker = SSLChecker()
        self.hidden_port_detector = HiddenPortDetector()
        self.password_cracker = PasswordCracker()
        self.exploit_launcher = ExploitLauncher()
        self.report_generator = ReportGenerator()

        self.dark_mode = True
        self.init_ui()

    def init_ui(self):
        self.tabs = QTabWidget()

        self.tabs.addTab(self.create_port_scanner_tab(), "🔍 Port Scanner")
        self.tabs.addTab(self.create_web_scanner_tab(), "🌐 Web Scanner")
        self.tabs.addTab(self.create_dns_tools_tab(), "📡 DNS Tools")
        self.tabs.addTab(self.create_ssl_checker_tab(), "🔐 SSL Checker")
        self.tabs.addTab(self.create_hidden_port_tab(), "👻 Hidden Port Detector")
        self.tabs.addTab(self.create_password_cracker_tab(), "🔓 Password Cracker")
        self.tabs.addTab(self.create_exploit_launcher_tab(), "💥 Exploit Launcher")
        self.tabs.addTab(self.create_report_generator_tab(), "📝 Report Generator")

        theme_button = QPushButton("🌙 Toggle Dark Mode")
        theme_button.clicked.connect(self.toggle_theme)

        main_layout = QVBoxLayout()
        main_layout.addWidget(self.tabs)
        main_layout.addWidget(theme_button)
        central_widget = QWidget()
        central_widget.setLayout(main_layout)
        self.setCentralWidget(central_widget)

        self.apply_theme()

    def toggle_theme(self):
        """Toggle theme with validation."""
        try:
            self.dark_mode = not self.dark_mode
            self.apply_theme()
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Theme toggle failed: {str(e)}")

    def apply_theme(self):
        """Apply theme with validation."""
        try:
            if self.dark_mode:
                palette = QPalette()
                palette.setColor(QPalette.Window, QColor(53, 53, 53))
                palette.setColor(QPalette.WindowText, Qt.white)
                palette.setColor(QPalette.Base, QColor(25, 25, 25))
                palette.setColor(QPalette.AlternateBase, QColor(53, 53, 53))
                palette.setColor(QPalette.ToolTipBase, Qt.white)
                palette.setColor(QPalette.ToolTipText, Qt.white)
                palette.setColor(QPalette.Text, Qt.white)
                palette.setColor(QPalette.Button, QColor(53, 53, 53))
                palette.setColor(QPalette.ButtonText, Qt.white)
                palette.setColor(QPalette.BrightText, Qt.red)
                palette.setColor(QPalette.Link, QColor(42, 130, 218))
                palette.setColor(QPalette.Highlight, QColor(42, 130, 218))
                palette.setColor(QPalette.HighlightedText, Qt.black)
            else:

                palette = QPalette()
                palette.setColor(QPalette.Window, Qt.white)
                palette.setColor(QPalette.WindowText, Qt.black)
                palette.setColor(QPalette.Base, Qt.white)
                palette.setColor(QPalette.AlternateBase, QColor(240, 240, 240))
                palette.setColor(QPalette.ToolTipBase, Qt.white)
                palette.setColor(QPalette.ToolTipText, Qt.black)
                palette.setColor(QPalette.Text, Qt.black)
                palette.setColor(QPalette.Button, QColor(240, 240, 240))
                palette.setColor(QPalette.ButtonText, Qt.black)
                palette.setColor(QPalette.BrightText, Qt.red)
                palette.setColor(QPalette.Link, QColor(0, 0, 255))
                palette.setColor(QPalette.Highlight, QColor(0, 120, 215))
                palette.setColor(QPalette.HighlightedText, Qt.white)

            QApplication.setPalette(palette)
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Theme application failed: {str(e)}")

    def create_port_scanner_tab(self):
        tab = QWidget()
        layout = QVBoxLayout()

        input_group = QGroupBox("Scan Configuration")
        input_layout = QVBoxLayout()

        target_layout = QHBoxLayout()
        target_label = QLabel("Target IP/Hostname:")
        self.target_input = QLineEdit()
        self.target_input.setPlaceholderText("e.g., 192.168.1.1 or example.com")
        target_layout.addWidget(target_label)
        target_layout.addWidget(self.target_input)
        input_layout.addLayout(target_layout)

        port_layout = QHBoxLayout()
        port_label = QLabel("Port Range:")
        self.start_port = QSpinBox()
        self.start_port.setRange(1, 65535)
        self.start_port.setValue(1)
        self.end_port = QSpinBox()
        self.end_port.setRange(1, 65535)
        self.end_port.setValue(1024)
        port_layout.addWidget(port_label)
        port_layout.addWidget(self.start_port)
        port_layout.addWidget(QLabel("to"))
        port_layout.addWidget(self.end_port)
        input_layout.addLayout(port_layout)

        thread_layout = QHBoxLayout()
        thread_label = QLabel("Threads:")
        self.thread_count = QSpinBox()
        self.thread_count.setRange(1, 100)
        self.thread_count.setValue(50)
        thread_layout.addWidget(thread_label)
        thread_layout.addWidget(self.thread_count)
        input_layout.addLayout(thread_layout)

        input_group.setLayout(input_layout)
        layout.addWidget(input_group)

        scan_button = QPushButton("Start Scan")
        scan_button.clicked.connect(self.start_port_scan)
        layout.addWidget(scan_button)

        self.progress_bar = QProgressBar()
        layout.addWidget(self.progress_bar)

        self.scan_results = QTextEdit()
        self.scan_results.setReadOnly(True)
        layout.addWidget(self.scan_results)

        tab.setLayout(layout)
        return tab

    def create_web_scanner_tab(self):
        tab = QWidget()
        layout = QVBoxLayout()

        input_group = QGroupBox("Scan Configuration")
        input_layout = QVBoxLayout()

        url_layout = QHBoxLayout()
        url_label = QLabel("Target URL:")
        self.url_input = QLineEdit()
        self.url_input.setPlaceholderText("e.g., https://example.com")
        url_layout.addWidget(url_label)
        url_layout.addWidget(self.url_input)
        input_layout.addLayout(url_layout)

        options_layout = QHBoxLayout()
        self.xss_check = QCheckBox("XSS Detection")
        self.xss_check.setChecked(True)
        self.sql_check = QCheckBox("SQL Injection")
        self.sql_check.setChecked(True)
        options_layout.addWidget(self.xss_check)
        options_layout.addWidget(self.sql_check)
        input_layout.addLayout(options_layout)

        input_group.setLayout(input_layout)
        layout.addWidget(input_group)

        scan_button = QPushButton("Start Scan")
        scan_button.clicked.connect(self.start_web_scan)
        layout.addWidget(scan_button)

        self.web_progress = QProgressBar()
        layout.addWidget(self.web_progress)

        self.web_results = QTextEdit()
        self.web_results.setReadOnly(True)
        layout.addWidget(self.web_results)

        tab.setLayout(layout)
        return tab

    def create_dns_tools_tab(self):
        tab = QWidget()
        layout = QVBoxLayout()

        input_group = QGroupBox("DNS Tools")
        input_layout = QVBoxLayout()

        domain_layout = QHBoxLayout()
        domain_label = QLabel("Domain:")
        self.domain_input = QLineEdit()
        self.domain_input.setPlaceholderText("e.g., example.com")
        domain_layout.addWidget(domain_label)
        domain_layout.addWidget(self.domain_input)
        input_layout.addLayout(domain_layout)

        tool_layout = QHBoxLayout()
        tool_label = QLabel("Tool:")
        self.tool_select = QComboBox()
        self.tool_select.addItems(
            ["Subdomain Enumeration", "DNS Records", "Reverse DNS"]
        )
        tool_layout.addWidget(tool_label)
        tool_layout.addWidget(self.tool_select)
        input_layout.addLayout(tool_layout)

        input_group.setLayout(input_layout)
        layout.addWidget(input_group)

        scan_button = QPushButton("Start Scan")
        scan_button.clicked.connect(self.start_dns_scan)
        layout.addWidget(scan_button)

        self.dns_results = QTextEdit()
        self.dns_results.setReadOnly(True)
        layout.addWidget(self.dns_results)

        tab.setLayout(layout)
        return tab

    def create_ssl_checker_tab(self):
        tab = QWidget()
        layout = QVBoxLayout()

        input_group = QGroupBox("SSL Check")
        input_layout = QVBoxLayout()

        host_layout = QHBoxLayout()
        host_label = QLabel("Host:")
        self.host_input = QLineEdit()
        self.host_input.setPlaceholderText("e.g., example.com")
        host_layout.addWidget(host_label)
        host_layout.addWidget(self.host_input)
        input_layout.addLayout(host_layout)

        options_layout = QHBoxLayout()
        self.cert_check = QCheckBox("Certificate Check")
        self.cert_check.setChecked(True)
        self.cipher_check = QCheckBox("Cipher Check")
        self.cipher_check.setChecked(True)
        self.hsts_check = QCheckBox("HSTS Check")
        self.hsts_check.setChecked(True)
        options_layout.addWidget(self.cert_check)
        options_layout.addWidget(self.cipher_check)
        options_layout.addWidget(self.hsts_check)
        input_layout.addLayout(options_layout)

        input_group.setLayout(input_layout)
        layout.addWidget(input_group)

        check_button = QPushButton("Check SSL")
        check_button.clicked.connect(self.start_ssl_check)
        layout.addWidget(check_button)

        self.ssl_results = QTextEdit()
        self.ssl_results.setReadOnly(True)
        layout.addWidget(self.ssl_results)

        tab.setLayout(layout)
        return tab

    def create_hidden_port_tab(self):
        tab = QWidget()
        layout = QVBoxLayout()

        input_group = QGroupBox("Hidden Port Detection")
        input_layout = QVBoxLayout()

        target_layout = QHBoxLayout()
        target_label = QLabel("Target IP/Hostname:")
        self.hidden_target_input = QLineEdit()
        self.hidden_target_input.setPlaceholderText("e.g., 192.168.1.1 or example.com")
        target_layout.addWidget(target_label)
        target_layout.addWidget(self.hidden_target_input)
        input_layout.addLayout(target_layout)

        scan_layout = QHBoxLayout()
        scan_label = QLabel("Scan Type:")
        self.scan_type = QComboBox()
        self.scan_type.addItems(["TCP SYN", "TCP ACK", "XMAS", "NULL", "FIN"])
        scan_layout.addWidget(scan_label)
        scan_layout.addWidget(self.scan_type)
        input_layout.addLayout(scan_layout)
        
        # Add description of scan types
        scan_info = QLabel("Scan Types:\n"
                          "• TCP SYN: Stealthy scan that doesn't complete connections\n"
                          "• TCP ACK: Determines if ports are filtered\n"
                          "• XMAS: Sends FIN, PSH, URG flags (stealthy)\n"
                          "• NULL: Sends no flags (stealthy)\n"
                          "• FIN: Sends FIN flag (stealthy)")
        scan_info.setStyleSheet("font-size: 10pt; color: gray;")
        input_layout.addWidget(scan_info)
        
        # Add admin privileges warning
        admin_warning = QLabel("⚠️ Note: Stealth scanning requires administrator privileges on Windows.\n"
                              "Please run the application as administrator or install Npcap.")
        admin_warning.setStyleSheet("font-size: 10pt; color: orange; font-weight: bold;")
        input_layout.addWidget(admin_warning)
        
        # Add Npcap troubleshooting info
        npcap_info = QLabel("Npcap Troubleshooting:\n"
                           "• Make sure Npcap is installed with WinPcap compatibility mode\n"
                           "• Restart the application after installing Npcap\n"
                           "• If still having issues, try running as administrator")
        npcap_info.setStyleSheet("font-size: 10pt; color: gray;")
        input_layout.addWidget(npcap_info)

        input_group.setLayout(input_layout)
        layout.addWidget(input_group)

        scan_button = QPushButton("Detect Hidden Ports")
        scan_button.clicked.connect(self.start_hidden_port_scan)
        layout.addWidget(scan_button)

        self.hidden_results = QTextEdit()
        self.hidden_results.setReadOnly(True)
        layout.addWidget(self.hidden_results)

        tab.setLayout(layout)
        return tab

    def create_password_cracker_tab(self):
        tab = QWidget()
        layout = QVBoxLayout()

        input_group = QGroupBox("Password Cracking")
        input_layout = QVBoxLayout()

        hash_layout = QHBoxLayout()
        hash_label = QLabel("Hash:")
        self.hash_input = QLineEdit()
        self.hash_input.setPlaceholderText("e.g., 5f4dcc3b5aa765d61d8327deb882cf99")
        hash_layout.addWidget(hash_label)
        hash_layout.addWidget(self.hash_input)
        input_layout.addLayout(hash_layout)

        type_layout = QHBoxLayout()
        type_label = QLabel("Hash Type:")
        self.hash_type = QComboBox()
        self.hash_type.addItems(["MD5", "SHA1", "SHA256", "SHA512"])
        type_layout.addWidget(type_label)
        type_layout.addWidget(self.hash_type)
        input_layout.addLayout(type_layout)

        wordlist_layout = QHBoxLayout()
        wordlist_label = QLabel("Wordlist:")
        self.wordlist_input = QLineEdit()
        self.wordlist_input.setPlaceholderText("Path to wordlist file")
        wordlist_button = QPushButton("Browse")
        wordlist_button.clicked.connect(self.browse_wordlist)
        wordlist_layout.addWidget(wordlist_label)
        wordlist_layout.addWidget(self.wordlist_input)
        wordlist_layout.addWidget(wordlist_button)
        input_layout.addLayout(wordlist_layout)

        input_group.setLayout(input_layout)
        layout.addWidget(input_group)

        crack_button = QPushButton("Crack Password")
        crack_button.clicked.connect(self.start_password_crack)
        layout.addWidget(crack_button)

        self.crack_results = QTextEdit()
        self.crack_results.setReadOnly(True)
        layout.addWidget(self.crack_results)

        tab.setLayout(layout)
        return tab

    def create_exploit_launcher_tab(self):
        tab = QWidget()
        layout = QVBoxLayout()

        input_group = QGroupBox("Exploit Launcher")
        input_layout = QVBoxLayout()

        target_layout = QHBoxLayout()
        target_label = QLabel("Target:")
        self.exploit_target_input = QLineEdit()
        self.exploit_target_input.setPlaceholderText("e.g., 192.168.1.1 or example.com")
        target_layout.addWidget(target_label)
        target_layout.addWidget(self.exploit_target_input)
        input_layout.addLayout(target_layout)

        exploit_layout = QHBoxLayout()
        exploit_label = QLabel("Exploit:")
        self.exploit_select = QComboBox()
        self.exploit_select.addItems(["Heartbleed", "Shellshock"])
        exploit_layout.addWidget(exploit_label)
        exploit_layout.addWidget(self.exploit_select)
        input_layout.addLayout(exploit_layout)

        input_group.setLayout(input_layout)
        layout.addWidget(input_group)

        launch_button = QPushButton("Launch Exploit")
        launch_button.clicked.connect(self.launch_exploit)
        layout.addWidget(launch_button)

        self.exploit_results = QTextEdit()
        self.exploit_results.setReadOnly(True)
        layout.addWidget(self.exploit_results)

        tab.setLayout(layout)
        return tab

    def create_report_generator_tab(self):
        tab = QWidget()
        layout = QVBoxLayout()

        input_group = QGroupBox("Report Generation")
        input_layout = QVBoxLayout()

        type_layout = QHBoxLayout()
        type_label = QLabel("Report Type:")
        self.report_type = QComboBox()
        self.report_type.addItems(["PDF", "HTML", "JSON"])
        type_layout.addWidget(type_label)
        type_layout.addWidget(self.report_type)
        input_layout.addLayout(type_layout)

        path_layout = QHBoxLayout()
        path_label = QLabel("Output Path:")
        self.report_path = QLineEdit()
        self.report_path.setPlaceholderText("Path to save report")
        path_button = QPushButton("Browse")
        path_button.clicked.connect(self.browse_report_path)
        path_layout.addWidget(path_label)
        path_layout.addWidget(self.report_path)
        path_layout.addWidget(path_button)
        input_layout.addLayout(path_layout)

        input_group.setLayout(input_layout)
        layout.addWidget(input_group)

        generate_button = QPushButton("Generate Report")
        generate_button.clicked.connect(self.generate_report)
        layout.addWidget(generate_button)

        self.report_results = QTextEdit()
        self.report_results.setReadOnly(True)
        layout.addWidget(self.report_results)

        tab.setLayout(layout)
        return tab

    def browse_wordlist(self):
        """Browse for wordlist file with validation."""
        try:
            file_name, _ = QFileDialog.getOpenFileName(
                self, "Select Wordlist", "", "Text Files (*.txt);;All Files (*)"
            )
            if file_name:
                if os.path.exists(file_name):
                    self.wordlist_input.setText(file_name)
                else:
                    QMessageBox.warning(self, "Error", "Selected file does not exist")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"File selection failed: {str(e)}")

    def browse_report_path(self):
        """Browse for report output path with validation."""
        try:
            report_type = self.report_type.currentText().lower()
            file_filter = ""
            if report_type == "pdf":
                file_filter = "PDF Files (*.pdf)"
            elif report_type == "html":
                file_filter = "HTML Files (*.html)"
            else:
                file_filter = "JSON Files (*.json)"

            file_name, _ = QFileDialog.getSaveFileName(
                self, "Save Report", "", f"{file_filter};;All Files (*)"
            )

            if file_name:

                if report_type == "pdf" and not file_name.lower().endswith(".pdf"):
                    file_name += ".pdf"
                elif report_type == "html" and not file_name.lower().endswith(".html"):
                    file_name += ".html"
                elif report_type == "json" and not file_name.lower().endswith(".json"):
                    file_name += ".json"

                self.report_path.setText(file_name)

        except Exception as e:
            QMessageBox.critical(self, "Error", f"Path selection failed: {str(e)}")

    def start_port_scan(self):
        """Start port scan with validation."""
        try:
            target = self.target_input.text().strip()
            if not target:
                QMessageBox.warning(
                    self, "Input Error", "Please enter a target IP/hostname"
                )
                return

            start_port = self.start_port.value()
            end_port = self.end_port.value()
            if start_port > end_port:
                QMessageBox.warning(
                    self, "Input Error", "Start port must be less than end port"
                )
                return

            threads = self.thread_count.value()

            self.target_input.setEnabled(False)
            self.start_port.setEnabled(False)
            self.end_port.setEnabled(False)
            self.thread_count.setEnabled(False)

            try:
                self.progress_bar.setValue(0)
                results = self.port_scanner.scan(target, start_port, end_port)
                self.scan_results.setText(str(results))
                self.progress_bar.setValue(100)

                self.report_generator.add_scan_data(
                    "port_scan",
                    {
                        "target": target,
                        "port_range": f"{start_port}-{end_port}",
                        "threads": threads,
                        "results": results,
                    },
                )

            except Exception as e:
                QMessageBox.critical(self, "Error", f"Scan failed: {str(e)}")
            finally:

                self.target_input.setEnabled(True)
                self.start_port.setEnabled(True)
                self.end_port.setEnabled(True)
                self.thread_count.setEnabled(True)

        except Exception as e:
            QMessageBox.critical(self, "Error", f"Unexpected error: {str(e)}")

    def start_web_scan(self):
        """Start web scan with validation."""
        try:
            url = self.url_input.text().strip()
            if not url:
                QMessageBox.warning(self, "Input Error", "Please enter a target URL")
                return

            if not url.startswith(("http://", "https://")):
                url = "http://" + url

            check_xss = self.xss_check.isChecked()
            check_sql = self.sql_check.isChecked()

            self.url_input.setEnabled(False)
            self.xss_check.setEnabled(False)
            self.sql_check.setEnabled(False)

            try:
                self.web_progress.setValue(0)
                results = self.web_scanner.scan(url)
                self.web_results.setText(str(results))
                self.web_progress.setValue(100)

                self.report_generator.add_scan_data(
                    "web_scan",
                    {
                        "url": url,
                        "options": {"xss": check_xss, "sql": check_sql},
                        "results": results,
                    },
                )

            except Exception as e:
                QMessageBox.critical(self, "Error", f"Scan failed: {str(e)}")
            finally:

                self.url_input.setEnabled(True)
                self.xss_check.setEnabled(True)
                self.sql_check.setEnabled(True)

        except Exception as e:
            QMessageBox.critical(self, "Error", f"Unexpected error: {str(e)}")

    def start_dns_scan(self):
        """Start DNS scan with validation."""
        try:
            domain = self.domain_input.text().strip()
            if not domain:
                QMessageBox.warning(self, "Input Error", "Please enter a domain")
                return

            tool = self.tool_select.currentText()

            self.domain_input.setEnabled(False)
            self.tool_select.setEnabled(False)

            try:
                if tool == "Subdomain Enumeration":
                    results = self.dns_tools.find_subdomains(domain)
                elif tool == "DNS Records":
                    results = self.dns_tools.get_all_dns_records(domain)
                else:
                    results = self.dns_tools.get_reverse_dns(domain)

                self.dns_results.setText(str(results))

                self.report_generator.add_scan_data(
                    "dns_scan", {"domain": domain, "tool": tool, "results": results}
                )

            except Exception as e:
                QMessageBox.critical(self, "Error", f"Scan failed: {str(e)}")
            finally:

                self.domain_input.setEnabled(True)
                self.tool_select.setEnabled(True)

        except Exception as e:
            QMessageBox.critical(self, "Error", f"Unexpected error: {str(e)}")

    def start_ssl_check(self):
        """Start SSL check with validation."""
        try:
            host = self.host_input.text().strip()
            if not host:
                QMessageBox.warning(self, "Input Error", "Please enter a host")
                return

            self.host_input.setEnabled(False)
            self.cert_check.setEnabled(False)
            self.cipher_check.setEnabled(False)
            self.hsts_check.setEnabled(False)

            try:
                results = self.ssl_checker.scan(host)
                self.ssl_results.setText(str(results))

                self.report_generator.add_scan_data(
                    "ssl_scan", {"host": host, "results": results}
                )

            except Exception as e:
                QMessageBox.critical(self, "Error", f"Check failed: {str(e)}")
            finally:

                self.host_input.setEnabled(True)
                self.cert_check.setEnabled(True)
                self.cipher_check.setEnabled(True)
                self.hsts_check.setEnabled(True)

        except Exception as e:
            QMessageBox.critical(self, "Error", f"Unexpected error: {str(e)}")

    def start_hidden_port_scan(self):
        """Start hidden port scan with validation."""
        try:
            target = self.hidden_target_input.text().strip()
            if not target:
                QMessageBox.warning(
                    self, "Input Error", "Please enter a target IP/hostname"
                )
                return

            scan_type = self.scan_type.currentText()

            # Disable UI elements during scan
            self.hidden_target_input.setEnabled(False)
            self.scan_type.setEnabled(False)

            try:
                # Pass the selected scan type to the scanner
                results = self.hidden_port_detector.scan(target, scan_type)
                
                # Format results for display
                if "error" in results:
                    error_msg = results['error']
                    self.hidden_results.setText(f"Error: {error_msg}")
                    
                    # Show special message for admin privileges error
                    if "Administrator privileges or Npcap required" in error_msg:
                        QMessageBox.warning(
                            self, 
                            "Administrator Privileges or Npcap Required", 
                            "Stealth scanning requires administrator privileges or Npcap on Windows.\n\n"
                            "To fix this issue, you can:\n"
                            "1. Run the application as administrator\n"
                            "2. Install Npcap from https://npcap.com/#download\n"
                            "3. Make sure Npcap is installed with WinPcap compatibility mode\n"
                            "4. Restart the application after installing Npcap\n\n"
                            "Would you like to open the Npcap download page?"
                        )
                else:
                    formatted_results = f"Target: {results['target']} ({results['ip']})\n"
                    formatted_results += f"Scan Type: {results['scan_type']}\n"
                    formatted_results += f"Total Ports Scanned: {results['total_ports_scanned']}\n\n"
                    
                    if results['open_ports']:
                        formatted_results += "Open Ports:\n"
                        for port_info in results['open_ports']:
                            formatted_results += f"  Port {port_info['port']}: {port_info['state']} ({port_info['service']})\n"
                    else:
                        formatted_results += "No open ports found.\n"
                    
                    self.hidden_results.setText(formatted_results)

                # Add scan data to report generator
                self.report_generator.add_scan_data(
                    "hidden_port",
                    {"target": target, "scan_type": scan_type, "results": results},
                )

            except Exception as e:
                error_msg = str(e)
                self.hidden_results.setText(f"Error: {error_msg}")
                
                # Check for common Scapy errors
                if "Windows native L3 Raw sockets" in error_msg:
                    QMessageBox.warning(
                        self, 
                        "Npcap Configuration Issue", 
                        "There seems to be an issue with Npcap configuration.\n\n"
                        "Please try the following:\n"
                        "1. Reinstall Npcap with WinPcap compatibility mode\n"
                        "2. Restart your computer\n"
                        "3. Run the application as administrator\n\n"
                        "Would you like to open the Npcap download page?"
                    )
                else:
                    QMessageBox.critical(self, "Error", f"Scan failed: {error_msg}")
            finally:
                # Re-enable UI elements after scan
                self.hidden_target_input.setEnabled(True)
                self.scan_type.setEnabled(True)

        except Exception as e:
            QMessageBox.critical(self, "Error", f"Unexpected error: {str(e)}")

    def start_password_crack(self):
        """Start password cracking with validation."""
        try:
            hash_str = self.hash_input.text().strip()
            if not hash_str:
                QMessageBox.warning(self, "Input Error", "Please enter a hash")
                return

            hash_type = self.hash_type.currentText().lower()
            wordlist = self.wordlist_input.text().strip()
            if not wordlist:
                QMessageBox.warning(self, "Input Error", "Please select a wordlist")
                return

            if not os.path.exists(wordlist):
                QMessageBox.warning(self, "Input Error", "Wordlist file not found")
                return

            self.hash_input.setEnabled(False)
            self.hash_type.setEnabled(False)
            self.wordlist_input.setEnabled(False)

            try:
                results = self.password_cracker.crack(hash_str, wordlist, hash_type)
                self.crack_results.setText(str(results))

                self.report_generator.add_scan_data(
                    "password_crack",
                    {"hash_type": hash_type, "wordlist": wordlist, "results": results},
                )

            except Exception as e:
                QMessageBox.critical(self, "Error", f"Cracking failed: {str(e)}")
            finally:

                self.hash_input.setEnabled(True)
                self.hash_type.setEnabled(True)
                self.wordlist_input.setEnabled(True)

        except Exception as e:
            QMessageBox.critical(self, "Error", f"Unexpected error: {str(e)}")

    def launch_exploit(self):
        """Launch exploit with validation."""
        try:
            target = self.exploit_target_input.text().strip()
            if not target:
                QMessageBox.warning(self, "Input Error", "Please enter a target")
                return

            exploit = self.exploit_select.currentText().lower()

            self.exploit_target_input.setEnabled(False)
            self.exploit_select.setEnabled(False)

            try:
                results = self.exploit_launcher.launch_exploit(exploit, target)
                self.exploit_results.setText(str(results))

                self.report_generator.add_scan_data(
                    "exploit",
                    {"target": target, "exploit": exploit, "results": results},
                )

            except Exception as e:
                QMessageBox.critical(self, "Error", f"Exploit failed: {str(e)}")
            finally:

                self.exploit_target_input.setEnabled(True)
                self.exploit_select.setEnabled(True)

        except Exception as e:
            QMessageBox.critical(self, "Error", f"Unexpected error: {str(e)}")

    def generate_report(self):
        """Generate report with validation."""
        try:
            report_type = self.report_type.currentText().lower()
            output_path = self.report_path.text().strip()

            if not output_path:
                QMessageBox.warning(self, "Input Error", "Please select an output path")
                return

            if not self.report_generator.has_data():
                QMessageBox.warning(
                    self,
                    "No Data",
                    "No scan data available. Please perform some scans before generating a report.",
                )
                return

            self.report_type.setEnabled(False)
            self.report_path.setEnabled(False)

            try:
                success = False
                if report_type == "pdf":
                    success = self.report_generator.generate_pdf(output_path)
                elif report_type == "html":
                    success = self.report_generator.generate_html(output_path)
                else:
                    success = self.report_generator.generate_json(output_path)

                if success:
                    self.report_results.setText(
                        f"Report generated successfully!\n\n"
                        f"Location: {output_path}\n\n"
                        f"The report includes results from all scans performed in this session."
                    )

                    QMessageBox.information(
                        self,
                        "Success",
                        f"Report generated successfully at:\n{output_path}",
                    )
                else:
                    self.report_results.setText(
                        "Failed to generate report. Please check the application logs for details."
                    )
                    QMessageBox.warning(
                        self,
                        "Error",
                        "Failed to generate report. Please check the application logs for details.",
                    )
            except Exception as e:
                self.report_results.setText(f"Error generating report: {str(e)}")
                QMessageBox.critical(
                    self, "Error", f"Report generation failed: {str(e)}"
                )
            finally:

                self.report_type.setEnabled(True)
                self.report_path.setEnabled(True)

        except Exception as e:
            QMessageBox.critical(self, "Error", f"Unexpected error: {str(e)}")


def main():
    app = QApplication(sys.argv)
    app.setStyle(QStyleFactory.create("Fusion"))
    window = Xploit()
    window.show()
    sys.exit(app.exec_())


if __name__ == "__main__":
    main()
