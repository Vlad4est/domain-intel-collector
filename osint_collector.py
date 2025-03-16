import whois
import dns.resolver
import requests
from bs4 import BeautifulSoup
import json
import socket
import time
import argparse
from datetime import datetime
import os
import sys

class OSINTCollector:
    def __init__(self, api_key=None):
        self.vt_api_key = api_key
        self.results = {}
        self.output_dir = "osint_results"
        
        if not os.path.exists(self.output_dir):
            os.makedirs(self.output_dir)
    
    def gather_domain_info(self, domain):
        self.results = {
            "domain": domain,
            "scan_date": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }
        
        # Get domain IP
        try:
            ip = socket.gethostbyname(domain)
            self.results["ip"] = ip
        except Exception as e:
            self.results["ip"] = f"Error: {str(e)}"
        
        # WHOIS information
        try:
            whois_info = whois.whois(domain)
            self.results["whois"] = {
                "registrar": whois_info.registrar,
                "creation_date": str(whois_info.creation_date),
                "expiration_date": str(whois_info.expiration_date),
                "name_servers": whois_info.name_servers,
                "registrant": whois_info.registrant,
                "admin_email": whois_info.admin_email
            }
        except Exception as e:
            self.results["whois"] = {"error": str(e)}
        
        # DNS information
        try:
            self.results["dns"] = {}
            for record_type in ["A", "AAAA", "MX", "NS", "TXT", "SOA"]:
                try:
                    answers = dns.resolver.resolve(domain, record_type)
                    self.results["dns"][record_type] = [str(answer) for answer in answers]
                except Exception:
                    self.results["dns"][record_type] = []
        except Exception as e:
            self.results["dns"] = {"error": str(e)}
        
        # Web information
        try:
            self.get_website_info(domain)
        except Exception as e:
            self.results["web"] = {"error": str(e)}
        
        # VirusTotal information
        if self.vt_api_key:
            try:
                vt_results = self.check_virustotal(domain)
                self.results["virustotal"] = vt_results
            except Exception as e:
                self.results["virustotal"] = {"error": str(e)}
        
        return self.results
    
    def get_website_info(self, domain):
        try:
            http_response = requests.get(f"http://{domain}", timeout=10)
            use_https = False
        except Exception:
            try:
                http_response = requests.get(f"https://{domain}", timeout=10)
                use_https = True
            except Exception as e:
                self.results["web"] = {"error": f"Could not connect: {str(e)}"}
                return
        
        protocol = "https" if use_https else "http"
        response = http_response
        
        soup = BeautifulSoup(response.text, "html.parser")
        
        self.results["web"] = {
            "title": soup.title.string.strip() if soup.title else "No title",
            "meta_description": soup.find("meta", attrs={"name": "description"})["content"].strip() 
                if soup.find("meta", attrs={"name": "description"}) else "No description",
            "server": response.headers.get("Server", "Unknown"),
            "technologies": [],
            "status_code": response.status_code,
            "headers": dict(response.headers),
            "protocol": protocol
        }
        

        tech_indicators = {
            "WordPress": ["wp-content", "wp-includes"],
            "Drupal": ["Drupal", "drupal"],
            "Joomla": ["joomla", "Joomla"],
            "Bootstrap": ["bootstrap.min.css", "bootstrap.css"],
            "jQuery": ["jquery.min.js", "jquery.js"],
            "Google Analytics": ["google-analytics.com", "ga.js", "analytics.js"],
            "CloudFlare": ["cloudflare", "__cf", "Cloudflare"],
            "PHP": ["PHP", "X-Powered-By: PHP"],
            "Apache": ["Apache"],
            "Nginx": ["nginx"],
            "IIS": ["IIS", "X-Powered-By: ASP.NET"]
        }
        
        for tech, indicators in tech_indicators.items():
            for indicator in indicators:
                if indicator in str(response.headers) or indicator in response.text:
                    self.results["web"]["technologies"].append(tech)
                    break
        
        self.results["web"]["technologies"] = list(set(self.results["web"]["technologies"]))
        
        emails = set()
        for link in soup.find_all("a"):
            href = link.get("href", "")
            if href.startswith("mailto:"):
                emails.add(href[7:])
        self.results["web"]["emails"] = list(emails)
    
    def check_virustotal(self, domain):
        url = f"https://www.virustotal.com/api/v3/domains/{domain}"
        headers = {"x-apikey": self.vt_api_key}
        
        response = requests.get(url, headers=headers)
        
        # rate limiting
        if response.status_code == 429:  
            print("Rate limit hit. Waiting 60 seconds...")
            time.sleep(60)
            return self.check_virustotal(domain)  
        
        if response.status_code != 200:
            return {"error": f"API returned status code {response.status_code}"}
        
        vt_data = response.json()
        

        attributes = vt_data.get("data", {}).get("attributes", {})
        last_analysis = attributes.get("last_analysis_stats", {})
        
        return {
            "reputation": attributes.get("reputation", 0),
            "last_analysis_date": attributes.get("last_analysis_date", "Unknown"),
            "analysis_stats": last_analysis,
            "malicious": last_analysis.get("malicious", 0),
            "suspicious": last_analysis.get("suspicious", 0),
            "harmless": last_analysis.get("harmless", 0),
            "undetected": last_analysis.get("undetected", 0),
            "categories": attributes.get("categories", {}),
            "total_votes": attributes.get("total_votes", {})
        }
    
    def save_results(self, filename=None):
        if not filename:
            domain = self.results.get("domain", "unknown")
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"{self.output_dir}/{domain}_{timestamp}.json"
        
        with open(filename, "w") as f:
            json.dump(self.results, f, indent=4)
        
        return filename
    
    def display_summary(self):
        domain = self.results.get("domain", "unknown")
        ip = self.results.get("ip", "unknown")
        
        print(f"\n{'=' * 60}")
        print(f"OSINT SUMMARY FOR: {domain}")
        print(f"{'=' * 60}")
        print(f"IP Address: {ip}")
        
        if "whois" in self.results and not isinstance(self.results["whois"], dict) or "error" not in self.results["whois"]:
            print(f"\n--- WHOIS Information ---")
            print(f"Registrar: {self.results['whois'].get('registrar', 'Unknown')}")
            print(f"Creation Date: {self.results['whois'].get('creation_date', 'Unknown')}")
            print(f"Expiration Date: {self.results['whois'].get('expiration_date', 'Unknown')}")
        
        if "dns" in self.results and not isinstance(self.results["dns"], dict) or "error" not in self.results["dns"]:
            print(f"\n--- DNS Information ---")
            for record_type, records in self.results["dns"].items():
                if records:
                    print(f"{record_type} Records: {', '.join(records)}")
        
        if "web" in self.results and not isinstance(self.results["web"], dict) or "error" not in self.results["web"]:
            print(f"\n--- Website Information ---")
            print(f"Title: {self.results['web'].get('title', 'Unknown')}")
            print(f"Server: {self.results['web'].get('server', 'Unknown')}")
            technologies = self.results['web'].get('technologies', [])
            if technologies:
                print(f"Technologies: {', '.join(technologies)}")
            emails = self.results['web'].get('emails', [])
            if emails:
                print(f"Emails: {', '.join(emails)}")
        
        if "virustotal" in self.results and not isinstance(self.results["virustotal"], dict) or "error" not in self.results["virustotal"]:
            print(f"\n--- VirusTotal Information ---")
            vt = self.results["virustotal"]
            print(f"Reputation: {vt.get('reputation', 'Unknown')}")
            print(f"Malicious: {vt.get('malicious', 0)}")
            print(f"Suspicious: {vt.get('suspicious', 0)}")
            print(f"Harmless: {vt.get('harmless', 0)}")
        
        print(f"\nFull results saved to: {self.output_file}")
        print(f"{'=' * 60}\n")

def main():
    parser = argparse.ArgumentParser(description="OSINT Data Collector")
    parser.add_argument("domain", help="Domain to investigate")
    parser.add_argument("--api-key", help="VirusTotal API key")
    args = parser.parse_args()
    
    print(f"Starting OSINT collection for {args.domain}...")
    
    collector = OSINTCollector(api_key=args.api_key)
    collector.gather_domain_info(args.domain)
    collector.output_file = collector.save_results()
    collector.display_summary()
    
    print(f"OSINT collection completed. Results saved to {collector.output_file}")

if __name__ == "__main__":
    main()