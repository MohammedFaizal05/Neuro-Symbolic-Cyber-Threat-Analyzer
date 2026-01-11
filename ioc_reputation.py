"""
IOC Reputation & Validation Module

This module integrates with AbuseIPDB and VirusTotal APIs to check
the reputation of extracted IOCs (IPs, URLs, domains, hashes).

All API calls are server-side only for security.
"""

import os
import time
import base64
import requests
from typing import Dict, List, Optional, Any
from urllib.parse import urlparse
from dotenv import load_dotenv

load_dotenv()

# API Configuration - Support multiple API keys for fallback
def _load_api_keys(prefix: str, max_keys: int = 3) -> List[str]:
    """Load multiple API keys from environment variables."""
    keys = []
    for i in range(1, max_keys + 1):
        if i == 1:
            # First key can be without number or with _1
            key = os.getenv(f"{prefix}_API_KEY", "") or os.getenv(f"{prefix}_API_KEY_1", "")
        else:
            key = os.getenv(f"{prefix}_API_KEY_{i}", "")
        if key:
            keys.append(key)
    return keys

ABUSEIPDB_KEYS = _load_api_keys("ABUSEIPDB", max_keys=3)
VIRUSTOTAL_KEYS = _load_api_keys("VIRUSTOTAL", max_keys=3)

# Backward compatibility - keep old variable names for reference
ABUSEIPDB_API_KEY = ABUSEIPDB_KEYS[0] if ABUSEIPDB_KEYS else ""
VIRUSTOTAL_API_KEY = VIRUSTOTAL_KEYS[0] if VIRUSTOTAL_KEYS else ""

ABUSEIPDB_URL = "https://api.abuseipdb.com/api/v2/check"
VIRUSTOTAL_URL = "https://www.virustotal.com/vtapi/v2"

# Note: VirusTotal API v2 has rate limits:
# - Free tier: 4 requests per minute
# - Domain reports may return empty if not scanned before


class IOCReputationChecker:
    """
    Checks IOC reputation using AbuseIPDB (for IPs) and VirusTotal (for URLs, domains, hashes).
    """
    
    def __init__(self):
        self.abuseipdb_keys = ABUSEIPDB_KEYS
        self.virustotal_keys = VIRUSTOTAL_KEYS
        self.current_abuseipdb_key_index = 0
        self.current_virustotal_key_index = 0
        # VirusTotal free tier: 4 requests per MINUTE (not per second!)
        # So we need 15 seconds delay between requests (60/4 = 15)
        self.rate_limit_delay = 15.0  # 15 seconds between requests for VirusTotal free tier
        self.last_vt_request_time = 0  # Track last request time for rate limiting
        # Track last request time per key for better rate limiting
        self.last_vt_request_times = {i: 0 for i in range(len(self.virustotal_keys))}
    
    def _get_current_abuseipdb_key(self) -> Optional[str]:
        """Get current AbuseIPDB API key."""
        if not self.abuseipdb_keys:
            return None
        return self.abuseipdb_keys[self.current_abuseipdb_key_index % len(self.abuseipdb_keys)]
    
    def _get_current_virustotal_key(self) -> Optional[str]:
        """Get current VirusTotal API key."""
        if not self.virustotal_keys:
            return None
        return self.virustotal_keys[self.current_virustotal_key_index % len(self.virustotal_keys)]
    
    def _rotate_abuseipdb_key(self):
        """Rotate to next AbuseIPDB API key."""
        if len(self.abuseipdb_keys) > 1:
            self.current_abuseipdb_key_index = (self.current_abuseipdb_key_index + 1) % len(self.abuseipdb_keys)
    
    def _rotate_virustotal_key(self):
        """Rotate to next VirusTotal API key."""
        if len(self.virustotal_keys) > 1:
            self.current_virustotal_key_index = (self.current_virustotal_key_index + 1) % len(self.virustotal_keys)
    
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
        if not self.abuseipdb_keys:
            return {
                "status": "error",
                "error": "AbuseIPDB API key not configured. Set ABUSEIPDB_API_KEY in .env file."
            }
        
        # Try all keys in sequence if one fails
        last_error = None
        for attempt in range(len(self.abuseipdb_keys)):
            current_key = self._get_current_abuseipdb_key()
            if not current_key:
                break
            
            try:
                headers = {
                    "Key": current_key,
                    "Accept": "application/json"
                }
                params = {
                    "ipAddress": ip,
                    "maxAgeInDays": 90,
                    "verbose": ""
                }
                
                response = requests.get(ABUSEIPDB_URL, headers=headers, params=params, timeout=10)
                
                # Check for rate limiting or authentication errors
                if response.status_code == 429:
                    # Rate limit - try next key
                    self._rotate_abuseipdb_key()
                    last_error = "Rate limit exceeded, trying next key..."
                    if attempt < len(self.abuseipdb_keys) - 1:
                        continue
                    else:
                        return {
                            "status": "error",
                            "error": "All AbuseIPDB API keys rate limited. Please wait and try again."
                        }
                
                if response.status_code == 401 or response.status_code == 403:
                    # Invalid API key - try next key
                    self._rotate_abuseipdb_key()
                    last_error = f"API key authentication failed (HTTP {response.status_code}), trying next key..."
                    if attempt < len(self.abuseipdb_keys) - 1:
                        continue
                    else:
                        return {
                            "status": "error",
                            "error": "All AbuseIPDB API keys are invalid. Please check your API keys in .env file."
                        }
                
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
                    # Unexpected response format - try next key
                    self._rotate_abuseipdb_key()
                    last_error = "Unexpected response format from AbuseIPDB"
                    if attempt < len(self.abuseipdb_keys) - 1:
                        continue
                    else:
                        return {
                            "status": "error",
                            "error": last_error
                        }
                
            except requests.exceptions.RequestException as e:
                last_error = f"AbuseIPDB API error: {str(e)}"
                # Try next key if available
                if attempt < len(self.abuseipdb_keys) - 1:
                    self._rotate_abuseipdb_key()
                    continue
                else:
                    return {
                        "status": "error",
                        "error": f"All AbuseIPDB API keys failed. Last error: {last_error}"
                    }
            except Exception as e:
                last_error = f"Unexpected error: {str(e)}"
                if attempt < len(self.abuseipdb_keys) - 1:
                    self._rotate_abuseipdb_key()
                    continue
                else:
                    return {
                        "status": "error",
                        "error": f"All AbuseIPDB API keys failed. Last error: {last_error}"
                    }
        
        # If we get here, all keys failed
        return {
            "status": "error",
            "error": f"All AbuseIPDB API keys failed. Last error: {last_error or 'Unknown error'}"
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
        if not self.virustotal_keys:
            return {
                "status": "error",
                "error": "VirusTotal API key not configured. Set VIRUSTOTAL_API_KEY in .env file."
            }
        
        # Try all keys in sequence if one fails
        last_error = None
        for attempt in range(len(self.virustotal_keys)):
            current_key = self._get_current_virustotal_key()
            if not current_key:
                break
            
            try:
                # Rate limiting for free tier (4 requests per minute = 15 seconds between requests)
                # Track per key to allow better distribution
                key_index = self.current_virustotal_key_index
                current_time = time.time()
                time_since_last_request = current_time - self.last_vt_request_times.get(key_index, 0)
                if time_since_last_request < self.rate_limit_delay:
                    sleep_time = self.rate_limit_delay - time_since_last_request
                    time.sleep(sleep_time)
                self.last_vt_request_times[key_index] = time.time()
                
                if resource_type == "url":
                    # VirusTotal v2 API requires URL to be base64 encoded
                    url_endpoint = f"{VIRUSTOTAL_URL}/url/report"
                    # Base64 encode the URL (without padding, as VT expects)
                    encoded_resource = base64.urlsafe_b64encode(resource.encode()).decode().rstrip('=')
                    params = {
                        "apikey": current_key,
                        "resource": encoded_resource
                    }
                elif resource_type == "domain":
                    # VirusTotal v2 API doesn't have a direct domain endpoint
                    # Use URL report with http:// prefix as workaround
                    url_endpoint = f"{VIRUSTOTAL_URL}/url/report"
                    # Convert domain to URL format for checking
                    domain_url = f"http://{resource}" if not resource.startswith(("http://", "https://")) else resource
                    # Base64 encode the domain URL (without padding)
                    encoded_resource = base64.urlsafe_b64encode(domain_url.encode()).decode().rstrip('=')
                    params = {
                        "apikey": current_key,
                        "resource": encoded_resource
                    }
                elif resource_type == "hash":
                    url_endpoint = f"{VIRUSTOTAL_URL}/file/report"
                    params = {
                        "apikey": current_key,
                        "resource": resource
                    }
                else:
                    return {
                        "status": "error",
                        "error": f"Unsupported resource type: {resource_type}"
                    }
                
                response = requests.get(url_endpoint, params=params, timeout=15)
                
                # Check for rate limiting (HTTP 429 or 204) - try next key
                if response.status_code == 429:
                    self._rotate_virustotal_key()
                    last_error = "Rate limit exceeded, trying next key..."
                    if attempt < len(self.virustotal_keys) - 1:
                        continue
                    else:
                        return {
                            "status": "error",
                            "error": "All VirusTotal API keys rate limited. Free tier allows 4 requests per minute per key."
                        }
                if response.status_code == 204:
                    self._rotate_virustotal_key()
                    last_error = "Rate limit exceeded (HTTP 204), trying next key..."
                    if attempt < len(self.virustotal_keys) - 1:
                        continue
                    else:
                        return {
                            "status": "error",
                            "error": "All VirusTotal API keys rate limited (HTTP 204). Free tier allows 4 requests per minute per key."
                        }
            
                # Check if response has content
                if not response.text or not response.text.strip():
                    # Empty response might mean the resource hasn't been scanned yet
                    # For domains/URLs, return "clean" with a note instead of error
                    if resource_type in ["url", "domain"]:
                        return {
                            "status": "clean",
                            "positives": 0,
                            "total": 0,
                            "scan_date": None,
                            "permalink": None,
                            "message": "Resource not yet scanned by VirusTotal. Empty response may indicate the domain/URL hasn't been analyzed yet."
                        }
                    else:
                        # For hashes, try next key if available
                        self._rotate_virustotal_key()
                        last_error = "Empty response, trying next key..."
                        if attempt < len(self.virustotal_keys) - 1:
                            continue
                        else:
                            return {
                                "status": "error",
                                "error": "VirusTotal API returned empty response for all keys. Possible causes: rate limiting (4 req/min), invalid API keys, or API issues."
                            }
                
                # Check if response is HTML (error page) instead of JSON
                if response.text.strip().startswith('<') or '<html' in response.text.lower()[:100]:
                    self._rotate_virustotal_key()
                    last_error = "HTML response (invalid endpoint/key), trying next key..."
                    if attempt < len(self.virustotal_keys) - 1:
                        continue
                    else:
                        return {
                            "status": "error",
                            "error": "VirusTotal API returned HTML instead of JSON for all keys. This may indicate invalid endpoints or API key issues."
                        }
                
                # Check HTTP status code for authentication errors
                if response.status_code == 401 or response.status_code == 403:
                    self._rotate_virustotal_key()
                    last_error = f"Authentication failed (HTTP {response.status_code}), trying next key..."
                    if attempt < len(self.virustotal_keys) - 1:
                        continue
                    else:
                        return {
                            "status": "error",
                            "error": f"All VirusTotal API keys authentication failed (HTTP {response.status_code}). Please check your API keys in .env file."
                        }
                
                # Try to parse JSON
                try:
                    data = response.json()
                except ValueError as e:
                    # JSON decode error - response is not valid JSON
                    error_preview = response.text[:200] if len(response.text) > 200 else response.text
                    # Check for common error messages
                    if "API key" in error_preview.lower() or "authentication" in error_preview.lower():
                        self._rotate_virustotal_key()
                        last_error = "Invalid API key detected, trying next key..."
                        if attempt < len(self.virustotal_keys) - 1:
                            continue
                        else:
                            return {
                                "status": "error",
                                "error": "All VirusTotal API keys appear to be invalid. Please check your API keys in .env file."
                            }
                    self._rotate_virustotal_key()
                    last_error = f"Invalid JSON response, trying next key..."
                    if attempt < len(self.virustotal_keys) - 1:
                        continue
                    else:
                        return {
                            "status": "error",
                            "error": f"VirusTotal API returned invalid JSON for all keys. Response preview: {error_preview}"
                        }
                
                # Check HTTP status code
                if response.status_code != 200:
                    error_msg = response.text[:200] if response.text else "No error message"
                    self._rotate_virustotal_key()
                    last_error = f"HTTP {response.status_code}: {error_msg}"
                    if attempt < len(self.virustotal_keys) - 1:
                        continue
                    else:
                        return {
                            "status": "error",
                            "error": f"VirusTotal API returned status {response.status_code} for all keys: {error_msg}"
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
                    # Found - success!
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
                    # Unexpected response code - try next key
                    self._rotate_virustotal_key()
                    last_error = f"Unexpected response code: {response_code}"
                    if attempt < len(self.virustotal_keys) - 1:
                        continue
                    else:
                        return {
                            "status": "error",
                            "error": f"VirusTotal API returned unexpected code {response_code} for all keys"
                        }
                
            except requests.exceptions.Timeout:
                last_error = "Request timed out"
                if attempt < len(self.virustotal_keys) - 1:
                    self._rotate_virustotal_key()
                    continue
                else:
                    return {
                        "status": "error",
                        "error": "VirusTotal API request timed out for all keys. Please try again later."
                    }
            except requests.exceptions.RequestException as e:
                last_error = f"Request error: {str(e)}"
                if attempt < len(self.virustotal_keys) - 1:
                    self._rotate_virustotal_key()
                    continue
                else:
                    return {
                        "status": "error",
                        "error": f"All VirusTotal API keys failed. Last error: {last_error}"
                    }
            except Exception as e:
                last_error = f"Unexpected error: {str(e)}"
                if attempt < len(self.virustotal_keys) - 1:
                    self._rotate_virustotal_key()
                    continue
                else:
                    return {
                        "status": "error",
                        "error": f"All VirusTotal API keys failed. Last error: {last_error}"
                    }
        
        # If we get here, all keys failed
        return {
            "status": "error",
            "error": f"All VirusTotal API keys failed. Last error: {last_error or 'Unknown error'}"
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
        # Note: With free tier (4 req/min), checking many domains will take time
        total_vt_checks = len(iocs.get("urls", [])) + len(domains_to_check) + len([h for h in iocs.get("hashes", []) if len(h) in [32, 40, 64]])
        if total_vt_checks > 4:
            # Warn user that this will take a while due to rate limits
            print(f"Warning: {total_vt_checks} VirusTotal checks requested. Free tier allows 4 requests/minute, so this will take approximately {((total_vt_checks - 1) * 15) / 60:.1f} minutes.")
        
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

