"""
IOC Reputation & Validation Module

This module integrates with AbuseIPDB and VirusTotal APIs to check
the reputation of extracted IOCs (IPs, URLs, domains, hashes).

All API calls are server-side only for security.
"""

import os
import time
import requests
from typing import Dict, List, Optional, Any
from urllib.parse import urlparse
from dotenv import load_dotenv

load_dotenv()

# API Configuration
ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY", "")
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "")

ABUSEIPDB_URL = "https://api.abuseipdb.com/api/v2/check"
VIRUSTOTAL_URL = "https://www.virustotal.com/vtapi/v2"


class IOCReputationChecker:
    """
    Checks IOC reputation using AbuseIPDB (for IPs) and VirusTotal (for URLs, domains, hashes).
    """
    
    def __init__(self):
        self.abuseipdb_key = ABUSEIPDB_API_KEY
        self.virustotal_key = VIRUSTOTAL_API_KEY
        self.rate_limit_delay = 0.25  # 4 requests per second for VirusTotal free tier
    
    def check_ip_reputation(self, ip: str) -> Dict[str, Any]:
        """
        Check IP reputation using AbuseIPDB.
        
        Returns:
            {
                "status": "malicious" | "suspicious" | "clean" | "error",
                "abuse_confidence": int (0-100),
                "usage_type": str,
                "isp": str,
                "country": str,
                "is_public": bool,
                "is_whitelisted": bool,
                "reports": int,
                "last_reported": str,
                "error": str (if status is "error")
            }
        """
        if not self.abuseipdb_key:
            return {
                "status": "error",
                "error": "AbuseIPDB API key not configured. Set ABUSEIPDB_API_KEY in .env file."
            }
        
        try:
            headers = {
                "Key": self.abuseipdb_key,
                "Accept": "application/json"
            }
            params = {
                "ipAddress": ip,
                "maxAgeInDays": 90,
                "verbose": ""
            }
            
            response = requests.get(ABUSEIPDB_URL, headers=headers, params=params, timeout=10)
            response.raise_for_status()
            data = response.json()
            
            if "data" in data:
                result = data["data"]
                abuse_confidence = result.get("abuseConfidencePercentage", 0)
                reports = result.get("totalReports", 0)
                
                # Determine status
                if abuse_confidence >= 75 or reports >= 5:
                    status = "malicious"
                elif abuse_confidence >= 25 or reports >= 1:
                    status = "suspicious"
                else:
                    status = "clean"
                
                return {
                    "status": status,
                    "abuse_confidence": abuse_confidence,
                    "usage_type": result.get("usageType", "Unknown"),
                    "isp": result.get("isp", "Unknown"),
                    "country": result.get("countryCode", "Unknown"),
                    "is_public": result.get("isPublic", False),
                    "is_whitelisted": result.get("isWhitelisted", False),
                    "reports": reports,
                    "last_reported": result.get("lastReportedAt", "Never")
                }
            else:
                return {
                    "status": "error",
                    "error": "Unexpected response format from AbuseIPDB"
                }
                
        except requests.exceptions.RequestException as e:
            return {
                "status": "error",
                "error": f"AbuseIPDB API error: {str(e)}"
            }
        except Exception as e:
            return {
                "status": "error",
                "error": f"Unexpected error: {str(e)}"
            }
    
    def check_virustotal(self, resource: str, resource_type: str) -> Dict[str, Any]:
        """
        Check URL, domain, or hash reputation using VirusTotal.
        
        Args:
            resource: The URL, domain, or hash to check
            resource_type: "url", "domain", or "hash"
        
        Returns:
            {
                "status": "malicious" | "suspicious" | "clean" | "error",
                "positives": int (number of engines detecting threat),
                "total": int (total engines scanned),
                "scan_date": str,
                "permalink": str,
                "error": str (if status is "error")
            }
        """
        if not self.virustotal_key:
            return {
                "status": "error",
                "error": "VirusTotal API key not configured. Set VIRUSTOTAL_API_KEY in .env file."
            }
        
        try:
            # Rate limiting for free tier
            time.sleep(self.rate_limit_delay)
            
            if resource_type == "url":
                # URL needs to be encoded
                url_endpoint = f"{VIRUSTOTAL_URL}/url/report"
                params = {
                    "apikey": self.virustotal_key,
                    "resource": resource
                }
            elif resource_type == "domain":
                # VirusTotal v2 API doesn't have a direct domain endpoint
                # Use URL report with http:// prefix as workaround
                url_endpoint = f"{VIRUSTOTAL_URL}/url/report"
                # Convert domain to URL format for checking
                domain_url = f"http://{resource}" if not resource.startswith(("http://", "https://")) else resource
                params = {
                    "apikey": self.virustotal_key,
                    "resource": domain_url
                }
            elif resource_type == "hash":
                url_endpoint = f"{VIRUSTOTAL_URL}/file/report"
                params = {
                    "apikey": self.virustotal_key,
                    "resource": resource
                }
            else:
                return {
                    "status": "error",
                    "error": f"Unsupported resource type: {resource_type}"
                }
            
            response = requests.get(url_endpoint, params=params, timeout=15)
            
            # Check if response has content
            if not response.text or not response.text.strip():
                return {
                    "status": "error",
                    "error": "VirusTotal API returned empty response. This may indicate rate limiting, invalid API key, or API issues."
                }
            
            # Check if response is HTML (error page) instead of JSON
            if response.text.strip().startswith('<') or '<html' in response.text.lower()[:100]:
                return {
                    "status": "error",
                    "error": "VirusTotal API returned HTML instead of JSON. This may indicate an invalid endpoint or API key issue."
                }
            
            # Try to parse JSON
            try:
                data = response.json()
            except ValueError as e:
                # JSON decode error - response is not valid JSON
                error_preview = response.text[:200] if len(response.text) > 200 else response.text
                return {
                    "status": "error",
                    "error": f"VirusTotal API returned invalid JSON (may be rate limited or API key issue). Response preview: {error_preview}"
                }
            
            # Check HTTP status code
            if response.status_code != 200:
                return {
                    "status": "error",
                    "error": f"VirusTotal API returned status {response.status_code}: {response.text[:200]}"
                }
            
            # Check response code
            response_code = data.get("response_code", -1)
            
            if response_code == 0:
                # Not found in VirusTotal database
                return {
                    "status": "clean",
                    "positives": 0,
                    "total": 0,
                    "scan_date": None,
                    "permalink": None,
                    "message": "Resource not found in VirusTotal database"
                }
            elif response_code == 1:
                # Found
                positives = data.get("positives", 0)
                total = data.get("total", 0)
                
                # Determine status
                if positives >= 5:
                    status = "malicious"
                elif positives >= 1:
                    status = "suspicious"
                else:
                    status = "clean"
                
                return {
                    "status": status,
                    "positives": positives,
                    "total": total,
                    "scan_date": data.get("scan_date", "Unknown"),
                    "permalink": data.get("permalink", ""),
                    "sha256": data.get("sha256"),
                    "md5": data.get("md5")
                }
            else:
                return {
                    "status": "error",
                    "error": f"VirusTotal API returned code: {response_code}"
                }
                
        except requests.exceptions.Timeout:
            return {
                "status": "error",
                "error": "VirusTotal API request timed out. Please try again later."
            }
        except requests.exceptions.RequestException as e:
            return {
                "status": "error",
                "error": f"VirusTotal API error: {str(e)}"
            }
        except ValueError as e:
            # JSON decode errors are caught above, but catch any other value errors
            return {
                "status": "error",
                "error": f"VirusTotal response parsing error: {str(e)}"
            }
        except Exception as e:
            return {
                "status": "error",
                "error": f"Unexpected error: {str(e)}"
            }
    
    def check_all_iocs(self, iocs: Dict[str, List[str]]) -> Dict[str, Dict[str, Any]]:
        """
        Check reputation for all IOCs in the provided dictionary.
        
        Args:
            iocs: Dictionary with keys: ip_addresses, urls, emails, hashes
        
        Returns:
            {
                "ip_addresses": {ip: {...reputation_data...}, ...},
                "urls": {url: {...reputation_data...}, ...},
                "domains": {domain: {...reputation_data...}, ...},
                "hashes": {hash: {...reputation_data...}, ...}
            }
        """
        results = {
            "ip_addresses": {},
            "urls": {},
            "domains": {},
            "hashes": {}
        }
        
        # Check IPs with AbuseIPDB
        for ip in iocs.get("ip_addresses", []):
            results["ip_addresses"][ip] = self.check_ip_reputation(ip)
        
        # Check URLs with VirusTotal
        for url in iocs.get("urls", []):
            results["urls"][url] = self.check_virustotal(url, "url")
        
        # Extract domains from emails and check them
        domains_to_check = set()
        for email in iocs.get("emails", []):
            domain = email.split("@")[-1] if "@" in email else None
            if domain:
                domains_to_check.add(domain)
        
        # Also check any domains that might be in URLs
        for url in iocs.get("urls", []):
            try:
                parsed = urlparse(url)
                if parsed.netloc:
                    domains_to_check.add(parsed.netloc)
            except:
                pass
        
        # Check domains with VirusTotal
        for domain in domains_to_check:
            results["domains"][domain] = self.check_virustotal(domain, "domain")
        
        # Check hashes with VirusTotal
        for hash_val in iocs.get("hashes", []):
            # Only check if it looks like a valid hash (MD5, SHA1, SHA256)
            if len(hash_val) in [32, 40, 64]:  # MD5, SHA1, SHA256 lengths
                results["hashes"][hash_val] = self.check_virustotal(hash_val, "hash")
        
        return results


if __name__ == "__main__":
    # Test the reputation checker
    checker = IOCReputationChecker()
    
    # Test IP
    print("Testing IP reputation check...")
    ip_result = checker.check_ip_reputation("8.8.8.8")
    print(f"IP Result: {ip_result}")
    
    # Test URL
    print("\nTesting URL reputation check...")
    url_result = checker.check_virustotal("https://example.com", "url")
    print(f"URL Result: {url_result}")

