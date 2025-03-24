import ipaddress
import re
import json
import time
import os
from datetime import datetime, timedelta
import threading
import hashlib
from collections import deque
import logging
from logging.handlers import RotatingFileHandler
import socket
import random
import string

# Setup logging
log_dir = "security_logs"
os.makedirs(log_dir, exist_ok=True)

logging.basicConfig(level=logging.INFO)
security_logger = logging.getLogger("security")
security_logger.setLevel(logging.INFO)

# Create rotating file handler
handler = RotatingFileHandler(
    os.path.join(log_dir, "security.log"),
    maxBytes=10*1024*1024,  # 10MB
    backupCount=5
)
formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
handler.setFormatter(formatter)
security_logger.addHandler(handler)

# Create separate logger for blocked attempts
attack_logger = logging.getLogger("attacks")
attack_logger.setLevel(logging.WARNING)
attack_handler = RotatingFileHandler(
    os.path.join(log_dir, "attacks.log"),
    maxBytes=10*1024*1024,
    backupCount=5
)
attack_handler.setFormatter(formatter)
attack_logger.addHandler(attack_handler)

# Enhanced class with more protection features
class SecurityGateway:
    def __init__(self, db=None):
        self.db = db
        
        # IP blacklist and recent activities
        self.blacklisted_ips = set()
        self.suspicious_ips = {}  # IP -> count of suspicious activities
        self.ip_request_count = {}  # IP -> [timestamp, count]
        self.failed_attempts = {}  # IP -> count of failed attempts
        self.recent_requests = {}  # IP -> deque of timestamps
        
        # Distributed attack detection
        self.path_access_counts = {}  # path -> count in last minute
        self.user_agent_counts = {}  # user agent -> count in last hour
        
        # Token bucket for rate limiting (more sophisticated than simple counting)
        self.token_buckets = {}  # IP -> [tokens, last_update, max_tokens, refill_rate]
        
        # Attack patterns
        self.sql_injection_patterns = [
            r"(\b(?:select|update|delete|insert|drop|alter)\b.*\bfrom\b)",
            r"(?:--|\*\/|\/\*|;|'|\"|\bor\b|\band\b|\bunion\b|\bwhere\b|\bhaving\b)",
            r"(?:exec\s+xp_cmdshell|exec\s+sp_executesql)",
            r"(?:version\(\)|database\(\)|user\(\)|system_user\(\)|@@version)",
            r"(?:0x[0-9a-fA-F]+)",
            r"(?:\bor\s+1=1\b|\band\s+1=1\b|\bor\s+'1'='1'\b)",
            r"(?:waitfor\s+delay\s+'|sleep\(\s*\d+\s*\))",  # Time-based SQLi
        ]
        
        # Path traversal patterns
        self.path_traversal_patterns = [
            r"(?:\.\./|\..\\|%2e%2e%2f|\x2e\x2e\x2f)",
            r"(?:/etc/(?:passwd|shadow|hosts|config)|c:\\windows\\system32)",
            r"(?:boot\.ini|win\.ini|\.htaccess|\.git)",
            r"(?:%00|%0a|%0d|\x00|\n|\r)",
            r"(?:\.\./\./\./)",  # Multiple traversal attempts
        ]
        
        # XSS patterns
        self.xss_patterns = [
            r"(?:<script.*?>.*?</script.*?>)",
            r"(?:javascript:.*?|eval\(.*?\)|setTimeout\(.*?\)|setInterval\(.*?\))",
            r"(?:alert\(.*?\)|confirm\(.*?\)|prompt\(.*?\))",
            r"(?:onerror|onload|onmouseover|onclick|onmouseout|onkeypress|ondblclick)",
            r"(?:<img.*?src=.*?>|<iframe.*?>|<svg.*?>)",
            r"(?:document\.cookie|document\.domain|window\.location)",
            r"(?:<[a-z]+\s+[^>]*\bon[a-z]+\s*=)",  # Generic event handler detection
        ]
        
        # Command injection patterns
        self.cmd_injection_patterns = [
            r"(?:;|\||\|\||&&|\$\(|\`)",
            r"(?:/bin/(?:sh|bash|dash|ksh|tcsh|zsh|csh)|cmd\.exe|powershell\.exe)",
            r"(?:wget|curl|ping|nc|netcat|telnet|nslookup|dig|host)",
            r"(?:cat\s+/etc|type\s+c:\\)",
            r"(?:chmod|chown|sudo|su\s+root)",
        ]
        
        # Known bad user-agents (bots, scanners, etc.)
        self.bad_user_agents = [
            "zgrab", "dirbuster", "nikto", "appscan", "nessus", "netsparker", 
            "webinspect", "acunetix", "burpsuite", "sqlmap", "nmap", "masscan",
            "python-requests", "go-http-client", "curl", "wget", "scanner", 
            "wpscan", "jorgee", "masscan", "ltx71"
        ]
        
        # Country blocking (optional - example with high-risk countries)
        self.blocked_country_codes = []  # Empty by default, add codes like 'RU', 'CN' if needed
        
        # Rate limiting
        self.rate_limit_threshold = 30  # requests
        self.rate_limit_window = 10  # seconds
        
        # Permanent blocks last 24 hours by default
        self.block_duration = 24 * 60 * 60  # 24 hours in seconds
        
        # Honeypot paths to detect scanners (these paths don't exist but scanners try them)
        self.honeypot_paths = [
            "/wp-login.php", "/phpmyadmin/", "/admin/", "/wp-admin/", 
            "/.env", "/config.php", "/.git/HEAD", "/api/v1/exploitable"
        ]
        
        # Periodically reset pathway access counts (every minute)
        self.pathway_reset_thread = threading.Thread(target=self._reset_pathway_counts, daemon=True)
        self.pathway_reset_thread.start()
        
        # Load blacklist if exists
        self.load_blacklist()
        
        # Start cleanup thread
        self.cleanup_thread = threading.Thread(target=self._cleanup_old_data, daemon=True)
        self.cleanup_thread.start()
        
        # Create security challenge tokens (for challenging suspicious clients)
        self.challenge_tokens = {}
        
        security_logger.info("Enhanced SecurityGateway initialized with extra protections")
    
    def _reset_pathway_counts(self):
        """Reset pathway access counts every minute to detect DDoS targeting specific paths"""
        while True:
            time.sleep(60)
            self.path_access_counts = {}
    
    def load_blacklist(self):
        """Load blacklisted IPs from file"""
        blacklist_file = os.path.join(log_dir, "blacklist.txt")
        if os.path.exists(blacklist_file):
            try:
                with open(blacklist_file, 'r') as f:
                    lines = f.readlines()
                    for line in lines:
                        parts = line.strip().split(',')
                        if len(parts) >= 1:
                            ip = parts[0].strip()
                            try:
                                # Validate IP
                                ipaddress.ip_address(ip)
                                self.blacklisted_ips.add(ip)
                            except ValueError:
                                security_logger.warning(f"Invalid IP in blacklist: {ip}")
                security_logger.info(f"Loaded {len(self.blacklisted_ips)} IPs to blacklist")
            except Exception as e:
                security_logger.error(f"Error loading blacklist: {e}")
    
    def save_blacklist(self):
        """Save blacklisted IPs to file"""
        blacklist_file = os.path.join(log_dir, "blacklist.txt")
        try:
            with open(blacklist_file, 'w') as f:
                for ip in self.blacklisted_ips:
                    f.write(f"{ip}\n")
            security_logger.info(f"Saved {len(self.blacklisted_ips)} IPs to blacklist")
        except Exception as e:
            security_logger.error(f"Error saving blacklist: {e}")
    
    def _cleanup_old_data(self):
        """Clean up old data periodically"""
        while True:
            try:
                # Clean up old request counts
                current_time = time.time()
                for ip in list(self.ip_request_count.keys()):
                    timestamp, _ = self.ip_request_count[ip]
                    if current_time - timestamp > self.rate_limit_window:
                        del self.ip_request_count[ip]
                
                # Clean up old request timestamps
                for ip in list(self.recent_requests.keys()):
                    if ip in self.recent_requests:
                        while (self.recent_requests[ip] and 
                              current_time - self.recent_requests[ip][0] > 3600):  # 1 hour
                            self.recent_requests[ip].popleft()
                        if not self.recent_requests[ip]:
                            del self.recent_requests[ip]
            except Exception as e:
                security_logger.error(f"Error in cleanup: {e}")
            
            # Sleep for 5 minutes
            time.sleep(300)
    
    def check_request(self, request, db=None):
        """
        Check if a request is potentially malicious
        Returns: dict with results and actions
        """
        if db:
            self.db = db
        
        result = {
            "allowed": True,
            "suspicious": False,
            "blocked": False,
            "reason": None,
            "severity": "info",
            "action_taken": None
        }
        
        try:
            # Get request details
            ip = self._get_client_ip(request)
            path = request.path
            query_params = request.query_string.decode('utf-8', errors='ignore') if request.query_string else ""
            user_agent = request.headers.get('User-Agent', '')
            method = request.method
            host = request.host
            
            # Honeypot check - these paths don't exist but scanners look for them
            if any(hp in path.lower() for hp in self.honeypot_paths):
                result["allowed"] = False
                result["blocked"] = True
                result["reason"] = "Scanner detected accessing honeypot path"
                result["severity"] = "critical"
                result["action_taken"] = "blacklisted_scanner"
                self._block_ip(ip)
                self._log_blocked_request(ip, path, method, user_agent, "Honeypot triggered")
                return result
            
            # Check if IP is already blacklisted
            if ip in self.blacklisted_ips:
                result["allowed"] = False
                result["blocked"] = True
                result["reason"] = "IP is blacklisted"
                result["severity"] = "critical"
                result["action_taken"] = "blocked_request"
                self._log_blocked_request(ip, path, method, user_agent, "Blacklisted IP")
                return result
            
            # Track path access for DDoS detection
            if path in self.path_access_counts:
                self.path_access_counts[path] += 1
            else:
                self.path_access_counts[path] = 1
                
            # Check for distributed attacks on specific paths
            if self.path_access_counts.get(path, 0) > 120:  # More than 120 requests/minute to same path
                result["suspicious"] = True
                result["reason"] = f"Possible DDoS targeting path: {path}"
                result["severity"] = "warning"
                self._log_suspicious_activity(ip, path, method, user_agent, "High volume path access")
            
            # Check bad user agents
            for bad_agent in self.bad_user_agents:
                if user_agent and bad_agent.lower() in user_agent.lower():
                    result["allowed"] = False
                    result["blocked"] = True
                    result["reason"] = f"Malicious user agent: {bad_agent}"
                    result["severity"] = "critical"
                    result["action_taken"] = "blocked_bad_agent" 
                    self._block_ip(ip)
                    self._log_blocked_request(ip, path, method, user_agent, f"Bad user agent: {bad_agent}")
                    return result
            
            # Rate limiting check with token bucket (more sophisticated)
            if self._is_rate_limited(ip):
                result["allowed"] = False
                result["blocked"] = True
                result["reason"] = "Rate limit exceeded"
                result["severity"] = "warning"
                result["action_taken"] = "rate_limited"
                self._log_blocked_request(ip, path, method, user_agent, "Rate limit exceeded")
                # Add to suspicious IPs
                self._increment_suspicious(ip)
                return result
            
            # Check for attack patterns
            attack_check = self._check_attack_patterns(path, query_params, user_agent, request)
            if attack_check["detected"]:
                result["suspicious"] = True
                result["reason"] = attack_check["reason"]
                result["severity"] = attack_check["severity"]
                
                # Log the suspicious activity
                self._log_suspicious_activity(ip, path, method, user_agent, attack_check["reason"])
                
                # For high severity, block immediately
                if attack_check["severity"] == "critical":
                    result["allowed"] = False
                    result["blocked"] = True
                    result["action_taken"] = "blocked_attack"
                    self._block_ip(ip)
                    self._log_blocked_request(ip, path, method, user_agent, attack_check["reason"])
                else:
                    # Increment suspicious count
                    self._increment_suspicious(ip)
                    
                return result
            
            # Update request count for rate limiting
            self._update_request_count(ip)
            
            # For normal requests, maybe do some action
            chance_of_logging = 0.05  # Log about 5% of normal requests to reduce volume
            if random.random() < chance_of_logging:
                security_logger.info(f"Normal request: {ip} - {method} {path}")
                
            return result
            
        except Exception as e:
            security_logger.error(f"Error in security check: {e}")
            # Default to allowing in case of error
            return result
            
    def _get_client_ip(self, request):
        """Extract real client IP, considering proxies"""
        if 'X-Forwarded-For' in request.headers:
            # Get the first IP in X-Forwarded-For (client IP)
            ip = request.headers.getlist("X-Forwarded-For")[0].rpartition(' ')[-1]
        else:
            ip = request.remote_addr or '0.0.0.0'
        
        # Validate and sanitize IP
        try:
            ipaddress.ip_address(ip)  # This will validate the IP format
            return ip
        except ValueError:
            # Return a sanitized version or a default
            return "invalid-ip"
    
    def _is_rate_limited(self, ip):
        """Check if an IP has exceeded rate limits using token bucket algorithm"""
        current_time = time.time()
        
        # Initialize token bucket if new IP
        if ip not in self.token_buckets:
            max_tokens = 30
            self.token_buckets[ip] = [max_tokens, current_time, max_tokens, 2.0]  # [tokens, last_update, max_tokens, refill_rate]
            return False
            
        # Get current token bucket state
        tokens, last_update, max_tokens, refill_rate = self.token_buckets[ip]
        
        # Calculate token refill based on time passed
        time_passed = current_time - last_update
        new_tokens = tokens + time_passed * refill_rate
        
        # Cap tokens at max_tokens
        if new_tokens > max_tokens:
            new_tokens = max_tokens
            
        # Use a token for this request
        if new_tokens >= 1:
            self.token_buckets[ip] = [new_tokens - 1, current_time, max_tokens, refill_rate]
            return False
        else:
            # Update last update time even if we're out of tokens
            self.token_buckets[ip] = [0, current_time, max_tokens, refill_rate]
            return True  # Rate limited
    
    def _update_request_count(self, ip):
        """Update request count for an IP"""
        current_time = time.time()
        
        if ip not in self.ip_request_count:
            self.ip_request_count[ip] = [current_time, 1]
        else:
            timestamp, count = self.ip_request_count[ip]
            
            # If still within window, increment
            if current_time - timestamp <= self.rate_limit_window:
                self.ip_request_count[ip] = [timestamp, count + 1]
            else:
                # New window
                self.ip_request_count[ip] = [current_time, 1]
        
        # Also track in recent_requests for pattern analysis
        if ip not in self.recent_requests:
            self.recent_requests[ip] = deque(maxlen=100)  # Track last 100 requests
            
        self.recent_requests[ip].append(current_time)
    
    def _check_attack_patterns(self, path, query_params, user_agent, request):
        """Check request for attack patterns"""
        result = {"detected": False, "reason": None, "severity": "info"}
        
        # Combine path and query for checking
        full_url = path
        if query_params:
            full_url += "?" + query_params
        
        # Check headers for suspicious content
        headers_str = str(request.headers)
        
        # Check SQL Injection
        for pattern in self.sql_injection_patterns:
            if (re.search(pattern, full_url, re.IGNORECASE) or 
                re.search(pattern, headers_str, re.IGNORECASE)):
                result["detected"] = True
                result["reason"] = "SQL Injection attempt detected"
                result["severity"] = "critical"
                return result
        
        # Check Path Traversal
        for pattern in self.path_traversal_patterns:
            if (re.search(pattern, full_url, re.IGNORECASE) or 
                re.search(pattern, headers_str, re.IGNORECASE)):
                result["detected"] = True
                result["reason"] = "Path traversal attempt detected"
                result["severity"] = "critical"
                return result
        
        # Check XSS
        for pattern in self.xss_patterns:
            if (re.search(pattern, full_url, re.IGNORECASE) or 
                re.search(pattern, headers_str, re.IGNORECASE)):
                result["detected"] = True
                result["reason"] = "Cross-site scripting attempt detected"
                result["severity"] = "critical"
                return result
        
        # Check Command Injection
        for pattern in self.cmd_injection_patterns:
            if (re.search(pattern, full_url, re.IGNORECASE) or 
                re.search(pattern, headers_str, re.IGNORECASE)):
                result["detected"] = True
                result["reason"] = "Command injection attempt detected"
                result["severity"] = "critical"
                return result
        
        # Check User Agent for known attack tools
        if user_agent:
            attack_tools = [
                "sqlmap", "nikto", "nmap", "gobuster", "dirb", "burpsuite", 
                "metasploit", "hydra", "medusa", "zap", "wfuzz"
            ]
            for tool in attack_tools:
                if tool.lower() in user_agent.lower():
                    result["detected"] = True
                    result["reason"] = f"Attack tool detected in User-Agent: {tool}"
                    result["severity"] = "warning"
                    return result
        
        # Check for unusually long parameters (potential buffer overflow or DoS)
        if len(full_url) > 2000:  # Unusually long URL
            result["detected"] = True
            result["reason"] = "Unusually long URL detected"
            result["severity"] = "warning"
            return result
        
        # Check for many parameters (potential DoS)
        if query_params and query_params.count('&') > 30:  # Too many parameters
            result["detected"] = True
            result["reason"] = "Excessive query parameters detected"
            result["severity"] = "warning"
            return result
            
        return result
    
    def _increment_suspicious(self, ip):
        """Increment suspicious activity count for an IP"""
        if ip not in self.suspicious_ips:
            self.suspicious_ips[ip] = 1
        else:
            self.suspicious_ips[ip] += 1
            
        # If IP has many suspicious activities, block it
        if self.suspicious_ips[ip] >= 5:  # Block after 5 suspicious activities
            self._block_ip(ip)
            security_logger.warning(f"IP {ip} blocked after {self.suspicious_ips[ip]} suspicious activities")
    
    def _block_ip(self, ip):
        """Add IP to blacklist"""
        self.blacklisted_ips.add(ip)
        self.save_blacklist()
        
        # If we have DB access, log there too
        if self.db:
            try:
                self.db.log_security_event(ip, "SYSTEM", "BLOCK", "CRITICAL", blocked=True)
            except Exception as e:
                security_logger.error(f"Error logging to database: {e}")
    
    def _log_suspicious_activity(self, ip, path, method, user_agent, reason):
        """Log suspicious activity"""
        security_logger.warning(
            f"SUSPICIOUS: {ip} - {method} {path} - {reason} - UA: {user_agent[:50]}"
        )
        
        # If we have DB access, log there too
        if self.db:
            try:
                self.db.log_security_event(ip, path, method, "WARNING", blocked=False)
            except Exception as e:
                security_logger.error(f"Error logging to database: {e}")
    
    def _log_blocked_request(self, ip, path, method, user_agent, reason):
        """Log blocked request"""
        attack_logger.error(
            f"BLOCKED: {ip} - {method} {path} - {reason} - UA: {user_agent[:50]}"
        )
        
        # If we have DB access, log there too
        if self.db:
            try:
                self.db.log_security_event(ip, path, method, "CRITICAL", blocked=True)
            except Exception as e:
                security_logger.error(f"Error logging to database: {e}")
                
    def get_security_stats(self):
        """Get security statistics"""
        return {
            "blacklisted_ips": len(self.blacklisted_ips),
            "suspicious_ips": len(self.suspicious_ips),
            "currently_tracked_ips": len(self.ip_request_count),
            "hostname": socket.gethostname()
        }
    
    def _generate_challenge(self, ip):
        """Generate a challenge for suspicious IPs to solve (e.g. JavaScript test or CAPTCHA)"""
        # Create a token that's valid for 5 minutes
        token = ''.join(random.choices(string.ascii_letters + string.digits, k=32))
        self.challenge_tokens[ip] = {
            "token": token,
            "expires": time.time() + 300,
            "solved": False
        }
        return token

# Singleton instance
security_gateway = SecurityGateway()