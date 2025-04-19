import requests
from bs4 import BeautifulSoup
import logging
from typing import List, Dict
from urllib.parse import urljoin, urlparse

class WebScanner:
    def __init__(self):
        self.session = requests.Session()
        self.timeout = 10
        self.xss_payloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "<svg onload=alert('XSS')>",
            "javascript:alert('XSS')",
            "<body onload=alert('XSS')>"
        ]
        self.sql_payloads = [
            "' OR '1'='1",
            "' OR '1'='1' --",
            "' OR '1'='1' #",
            "' OR '1'='1'/*",
            "admin' --",
            "admin' #",
            "admin'/*"
        ]
        
    def validate_url(self, url: str) -> bool:
        """Validate URL format."""
        try:
            result = urlparse(url)
            return all([result.scheme, result.netloc])
        except:
            return False
            
    def get_forms(self, url: str) -> List[BeautifulSoup]:
        """Extract all forms from a webpage."""
        try:
            response = self.session.get(url, timeout=self.timeout)
            soup = BeautifulSoup(response.content, 'html.parser')
            return soup.find_all('form')
        except Exception as e:
            logging.error(f"Error getting forms: {str(e)}")
            return []
            
    def submit_form(self, form: BeautifulSoup, url: str, payload: str) -> requests.Response:
        """Submit a form with a payload."""
        try:
            form_details = {}
            action = form.attrs.get("action", "").lower()
            method = form.attrs.get("method", "get").lower()
            
            inputs = form.find_all("input")
            for input_tag in inputs:
                input_name = input_tag.attrs.get("name")
                input_type = input_tag.attrs.get("type", "text")
                input_value = input_tag.attrs.get("value", "")
                
                if input_type == "submit":
                    form_details[input_name] = input_value
                else:
                    form_details[input_name] = payload
                    
            if action:
                target_url = urljoin(url, action)
            else:
                target_url = url
                
            if method == "post":
                return self.session.post(target_url, data=form_details, timeout=self.timeout)
            else:
                return self.session.get(target_url, params=form_details, timeout=self.timeout)
        except Exception as e:
            logging.error(f"Error submitting form: {str(e)}")
            return None
            
    def test_xss(self, url: str) -> List[Dict]:
        """Test for XSS vulnerabilities."""
        vulnerabilities = []
        forms = self.get_forms(url)
        
        for form in forms:
            for payload in self.xss_payloads:
                response = self.submit_form(form, url, payload)
                if response and payload in response.text:
                    vulnerabilities.append({
                        "type": "XSS",
                        "form": str(form),
                        "payload": payload,
                        "url": response.url
                    })
                    
        return vulnerabilities
        
    def test_sql_injection(self, url: str) -> List[Dict]:
        """Test for SQL injection vulnerabilities."""
        vulnerabilities = []
        forms = self.get_forms(url)
        
        for form in forms:
            for payload in self.sql_payloads:
                response = self.submit_form(form, url, payload)
                if response and any(error in response.text.lower() for error in [
                    "sql syntax",
                    "mysql",
                    "oracle",
                    "sql server",
                    "postgresql",
                    "sqlite"
                ]):
                    vulnerabilities.append({
                        "type": "SQL Injection",
                        "form": str(form),
                        "payload": payload,
                        "url": response.url
                    })
                    
        return vulnerabilities
        
    def scan(self, url: str) -> Dict:
        """Main scanning function."""
        if not self.validate_url(url):
            raise ValueError("Invalid URL format")
            
        try:
            xss_vulnerabilities = self.test_xss(url)
            sql_vulnerabilities = self.test_sql_injection(url)
            
            return {
                "xss": xss_vulnerabilities,
                "sql_injection": sql_vulnerabilities
            }
        except Exception as e:
            logging.error(f"Error during web scan: {str(e)}")
            raise 