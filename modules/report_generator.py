from fpdf import FPDF
import logging
from typing import Dict
import os
from datetime import datetime
import json
import html

class ReportGenerator:
    def __init__(self):
        self.scan_data = {
            'port_scan': [],
            'web_scan': [],
            'dns_scan': [],
            'ssl_scan': [],
            'hidden_port': [],
            'password_crack': [],
            'exploit': []
        }
        self.logger = logging.getLogger('Xploit')
        
    def add_scan_data(self, scan_type, data):
        """Add scan results to the data store."""
        try:
            if scan_type in self.scan_data:
                if isinstance(data, dict):
                    for key, value in data.items():
                        if not isinstance(value, (str, int, float, bool, list, dict)):
                            data[key] = str(value)
                
                self.scan_data[scan_type].append({
                    'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                    'data': data
                })
                self.logger.info(f"Added {scan_type} data to report generator")
                return True
            else:
                self.logger.error(f"Invalid scan type: {scan_type}")
                return False
        except Exception as e:
            self.logger.error(f"Error adding scan data: {str(e)}")
            return False
        
    def generate_pdf(self, output_path):
        """Generate PDF report with all scan results."""
        try:
            if not any(results for results in self.scan_data.values()):
                self.logger.warning("No scan data available to generate PDF report")
                return False

            os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)

            pdf = FPDF(orientation='P', unit='mm', format='A4')
            pdf.set_auto_page_break(auto=True, margin=15)
            
            pdf.set_margins(15, 15, 15)
            
            pdf.add_page()
            pdf.set_font('Times', 'B', 24)
            pdf.cell(0, 40, 'Xploit Security Report', ln=True, align='C')
            
            pdf.set_font('Times', '', 12)
            pdf.cell(0, 10, f'Generated on: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}', ln=True, align='C')
            pdf.ln(20)

            for scan_type, results in self.scan_data.items():
                if results: 
                    pdf.add_page()
                    
                    pdf.set_font('Times', 'B', 16)
                    pdf.cell(0, 10, f'{scan_type.replace("_", " ").title()}', ln=True)
                    pdf.ln(5)

                    for result in results:
                        pdf.set_font('Times', 'I', 10)
                        pdf.cell(0, 8, f"Scan Time: {result['timestamp']}", ln=True)
                        pdf.ln(3)

                        data = result['data']
                        if isinstance(data, dict):
                            for key, value in data.items():
                                pdf.set_font('Times', 'B', 10)
                                pdf.cell(30, 8, f"{key}:", ln=False)
                                
                                pdf.set_font('Times', '', 10)
                                value_text = str(value)
                                
                                if len(value_text) > 60:
                                    lines = [value_text[i:i+60] for i in range(0, len(value_text), 60)]
                                    first_line = True
                                    for line in lines:
                                        if first_line:
                                            pdf.cell(0, 8, line, ln=True)
                                            first_line = False
                                        else:
                                            pdf.cell(30, 8, "", ln=False)  
                                            pdf.cell(0, 8, line, ln=True)
                                else:
                                    pdf.cell(0, 8, value_text, ln=True)
                                
                                pdf.ln(2)
                        else:
                            pdf.set_font('Times', '', 10)
                            value_text = str(data)
                            
                            if len(value_text) > 60:
                                lines = [value_text[i:i+60] for i in range(0, len(value_text), 60)]
                                for line in lines:
                                    pdf.multi_cell(0, 8, line)
                            else:
                                pdf.multi_cell(0, 8, value_text)
                            
                            pdf.ln(3)

            pdf.output(output_path)
            self.logger.info(f"Generated PDF report: {output_path}")
            return True

        except Exception as e:
            self.logger.error(f"Error generating PDF report: {str(e)}")
            return False
            
    def generate_html(self, output_path):
        """Generate HTML report with all scan results."""
        try:
            if not any(results for results in self.scan_data.values()):
                self.logger.warning("No scan data available to generate HTML report")
                return False
                
            os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
            
            html_content = """
            <!DOCTYPE html>
            <html>
            <head>
                <title>Xploit Security Report</title>
                <meta charset="utf-8">
                <style>
                    body { 
                        font-family: Times, sans-serif; 
                        margin: 20px;
                        line-height: 1.6;
                        color: #333;
                    }
                    h1 { 
                        color: #333; 
                        text-align: center;
                        border-bottom: 2px solid #eee;
                        padding-bottom: 10px;
                    }
                    h2 { 
                        color: #666; 
                        margin-top: 20px;
                        border-bottom: 1px solid #eee;
                        padding-bottom: 5px;
                    }
                    .scan-result { 
                        margin: 15px 0; 
                        padding: 15px; 
                        border: 1px solid #ddd; 
                        border-radius: 4px;
                        background-color: #f9f9f9;
                    }
                    .timestamp { 
                        color: #888; 
                        font-size: 0.9em;
                        margin-bottom: 10px;
                    }
                    .result-data { 
                        margin-top: 10px;
                    }
                    .key { 
                        font-weight: bold;
                        color: #555;
                    }
                    .value {
                        word-break: break-word;
                    }
                    pre {
                        background-color: #f5f5f5;
                        padding: 10px;
                        border-radius: 3px;
                        overflow-x: auto;
                        white-space: pre-wrap;
                    }
                    .section {
                        margin-bottom: 30px;
                    }
                    .footer {
                        text-align: center;
                        margin-top: 30px;
                        padding-top: 20px;
                        border-top: 1px solid #eee;
                        color: #888;
                        font-size: 0.8em;
                    }
                </style>
            </head>
            <body>
                <h1>Xploit Security Report</h1>
                <p style="text-align: center;">Generated on: """ + datetime.now().strftime('%Y-%m-%d %H:%M:%S') + """</p>
            """
            
            for scan_type, results in self.scan_data.items():
                if results:  # Only add sections with data
                    html_content += f"""
                    <div class="section">
                        <h2>{scan_type.replace('_', ' ').title()}</h2>
                    """
                    
                    for result in results:
                        html_content += f"""
                        <div class="scan-result">
                            <div class="timestamp">Scan Time: {result['timestamp']}</div>
                            <div class="result-data">
                        """
                        
                        if isinstance(result['data'], dict):
                            for key, value in result['data'].items():
                                if isinstance(value, (list, dict)):
                                    html_content += f'<p><span class="key">{key}:</span></p>'
                                    html_content += f'<pre class="value">{html.escape(str(value))}</pre>'
                                else:
                                    html_content += f'<p><span class="key">{key}:</span> <span class="value">{html.escape(str(value))}</span></p>'
                        else:
                            html_content += f'<pre class="value">{html.escape(str(result["data"]))}</pre>'
                            
                        html_content += """
                            </div>
                        </div>
                        """
                    
                    html_content += "</div>"
            
            html_content += """
                <div class="footer">
                    <p>Xploit Security Report - Generated by Xploit Penetration Testing Tool</p>
                </div>
            </body>
            </html>
            """
            
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write(html_content)
                
            self.logger.info(f"Generated HTML report: {output_path}")
            return True
            
        except Exception as e:
            self.logger.error(f"Error generating HTML report: {str(e)}")
            return False
            
    def generate_json(self, output_path):
        """Generate JSON report with all scan results."""
        try:
            if not any(results for results in self.scan_data.values()):
                self.logger.warning("No scan data available to generate JSON report")
                return False

            os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
            
            data_to_save = {
                "report_info": {
                    "title": "Xploit Security Report",
                    "generated_at": datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                    "version": "1.0"
                },
                "scan_data": {}
            }
            
            for scan_type, results in self.scan_data.items():
                data_to_save["scan_data"][scan_type] = []
                
                for result in results:
                    serializable_result = {
                        "timestamp": result["timestamp"],
                        "data": self._make_serializable(result["data"])
                    }
                    data_to_save["scan_data"][scan_type].append(serializable_result)

            with open(output_path, 'w', encoding='utf-8') as f:
                json.dump(data_to_save, f, indent=4, ensure_ascii=False)
                
            self.logger.info(f"Generated JSON report: {output_path}")
            return True
            
        except Exception as e:
            self.logger.error(f"Error generating JSON report: {str(e)}")
            return False
            
    def _make_serializable(self, obj):
        """Convert an object to a JSON-serializable format."""
        if isinstance(obj, (str, int, float, bool, type(None))):
            return obj
        elif isinstance(obj, (list, tuple)):
            return [self._make_serializable(item) for item in obj]
        elif isinstance(obj, dict):
            return {str(k): self._make_serializable(v) for k, v in obj.items()}
        else:
            return str(obj)
            
    def clear_data(self):
        """Clear all stored scan data."""
        try:
            self.scan_data = {k: [] for k in self.scan_data}
            self.logger.info("Cleared all scan data")
        except Exception as e:
            self.logger.error(f"Error clearing scan data: {str(e)}")
            
    def get_scan_summary(self):
        """Get a summary of all scan results."""
        try:
            summary = {}
            for scan_type, results in self.scan_data.items():
                if results:
                    summary[scan_type] = {
                        'total_scans': len(results),
                        'latest_scan': results[-1]['timestamp'],
                        'latest_results': results[-1]['data']
                    }
            return summary
        except Exception as e:
            self.logger.error(f"Error generating scan summary: {str(e)}")
            return {}
            
    def has_data(self):
        """Check if there is any scan data available."""
        return any(results for results in self.scan_data.values())
            
    def get_report_data(self) -> Dict:
        """Get current report data."""
        return self.scan_data 