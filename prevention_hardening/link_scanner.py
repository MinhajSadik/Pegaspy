"""Malicious Link Scanner

Comprehensive URL analysis and threat detection for:
- Email links and attachments
- Message links (SMS, iMessage, WhatsApp, etc.)
- Web content and downloads
- Social media links
- QR codes and shortened URLs
"""

import os
import re
import json
import time
import hashlib
import threading
import subprocess
from typing import Dict, List, Optional, Set, Tuple, Any, Union
from dataclasses import dataclass, asdict
from enum import Enum
from urllib.parse import urlparse, parse_qs, unquote
from collections import defaultdict, deque
from loguru import logger

try:
    import requests
    from requests.adapters import HTTPAdapter
    from urllib3.util.retry import Retry
except ImportError:
    requests = None
    HTTPAdapter = None
    Retry = None

try:
    import dns.resolver
except ImportError:
    dns = None

try:
    import whois
except ImportError:
    whois = None


class ThreatCategory(Enum):
    """URL threat categories"""
    PHISHING = "phishing"
    MALWARE = "malware"
    SCAM = "scam"
    SPAM = "spam"
    SUSPICIOUS = "suspicious"
    ADULT_CONTENT = "adult_content"
    GAMBLING = "gambling"
    DRUGS = "drugs"
    VIOLENCE = "violence"
    HATE_SPEECH = "hate_speech"
    FAKE_NEWS = "fake_news"
    CRYPTOCURRENCY_SCAM = "cryptocurrency_scam"
    TECH_SUPPORT_SCAM = "tech_support_scam"
    ROMANCE_SCAM = "romance_scam"
    INVESTMENT_FRAUD = "investment_fraud"


class URLType(Enum):
    """Types of URLs"""
    DIRECT = "direct"
    SHORTENED = "shortened"
    REDIRECT = "redirect"
    QR_CODE = "qr_code"
    EMAIL_LINK = "email_link"
    MESSAGE_LINK = "message_link"
    SOCIAL_MEDIA = "social_media"
    DOWNLOAD_LINK = "download_link"
    ATTACHMENT = "attachment"


class ScanEngine(Enum):
    """Scanning engines"""
    INTERNAL = "internal"
    VIRUSTOTAL = "virustotal"
    URLVOID = "urlvoid"
    SAFEBROWSING = "safebrowsing"
    PHISHTANK = "phishtank"
    OPENPHISH = "openphish"
    MALWAREDOMAINLIST = "malwaredomainlist"
    SPAMHAUS = "spamhaus"


@dataclass
class URLAnalysis:
    """Comprehensive URL analysis result"""
    url: str
    original_url: str
    final_url: str
    url_type: URLType
    domain: str
    subdomain: str
    tld: str
    path: str
    query_params: Dict[str, List[str]]
    fragments: str
    redirect_chain: List[str]
    redirect_count: int
    is_shortened: bool
    is_suspicious: bool
    is_malicious: bool
    threat_categories: List[ThreatCategory]
    reputation_score: float
    confidence_score: float
    scan_timestamp: str
    scan_duration: float
    

@dataclass
class DomainInfo:
    """Domain information"""
    domain: str
    registrar: str
    creation_date: Optional[str]
    expiration_date: Optional[str]
    last_updated: Optional[str]
    name_servers: List[str]
    registrant_country: str
    registrant_org: str
    domain_age_days: int
    is_newly_registered: bool
    is_suspicious_tld: bool
    dns_records: Dict[str, List[str]]
    mx_records: List[str]
    txt_records: List[str]
    

@dataclass
class ScanResult:
    """Individual scan engine result"""
    engine: ScanEngine
    is_malicious: bool
    threat_categories: List[ThreatCategory]
    confidence: float
    details: Dict[str, Any]
    scan_time: float
    error: Optional[str]
    

@dataclass
class LinkScanReport:
    """Comprehensive link scan report"""
    scan_id: str
    url_analysis: URLAnalysis
    domain_info: Optional[DomainInfo]
    scan_results: List[ScanResult]
    overall_verdict: str  # safe, suspicious, malicious
    risk_score: float
    recommendations: List[str]
    mitigation_actions: List[str]
    false_positive_likelihood: float
    scan_metadata: Dict[str, Any]
    

class MaliciousLinkScanner:
    """Advanced malicious link detection and analysis system"""
    
    def __init__(self):
        # URL databases and patterns
        self.malicious_domains: Set[str] = set()
        self.suspicious_domains: Set[str] = set()
        self.phishing_patterns: List[str] = []
        self.malware_patterns: List[str] = []
        self.scam_patterns: List[str] = []
        
        # URL shortener services
        self.url_shorteners: Set[str] = set()
        
        # Suspicious TLDs
        self.suspicious_tlds: Set[str] = set()
        
        # Scan cache
        self.scan_cache: Dict[str, LinkScanReport] = {}
        self.cache_ttl = 3600  # 1 hour
        
        # Scanning statistics
        self.scan_stats = {
            'total_scans': 0,
            'malicious_detected': 0,
            'suspicious_detected': 0,
            'false_positives': 0,
            'cache_hits': 0
        }
        
        # HTTP session for requests
        self.session = self._create_http_session()
        
        # Initialize databases and patterns
        self._initialize_threat_databases()
        self._initialize_url_patterns()
        self._initialize_url_shorteners()
        self._initialize_suspicious_tlds()
        
        logger.info("MaliciousLinkScanner initialized")
    
    def _create_http_session(self) -> Optional[Any]:
        """Create HTTP session with retry strategy"""
        if not requests:
            return None
        
        session = requests.Session()
        
        # Retry strategy
        if Retry and HTTPAdapter:
            retry_strategy = Retry(
                total=3,
                backoff_factor=1,
                status_forcelist=[429, 500, 502, 503, 504]
            )
            adapter = HTTPAdapter(max_retries=retry_strategy)
            session.mount("http://", adapter)
            session.mount("https://", adapter)
        
        # Set headers
        session.headers.update({
            'User-Agent': 'PegaSpy-LinkScanner/1.0 (Security Research)'
        })
        
        return session
    
    def _initialize_threat_databases(self) -> None:
        """Initialize threat databases"""
        # Known malicious domains (examples - in production, use threat feeds)
        self.malicious_domains.update([
            "malware-example.com",
            "phishing-test.org",
            "scam-site.net",
            "fake-bank.com",
            "virus-download.org",
            "trojan-host.com",
            "ransomware-site.net",
            "credential-stealer.org"
        ])
        
        # Suspicious domains
        self.suspicious_domains.update([
            "suspicious-example.com",
            "questionable-site.org",
            "untrusted-domain.net"
        ])
        
        logger.info(f"Loaded {len(self.malicious_domains)} malicious domains and {len(self.suspicious_domains)} suspicious domains")
    
    def _initialize_url_patterns(self) -> None:
        """Initialize URL threat detection patterns"""
        # Phishing patterns
        self.phishing_patterns = [
            r".*paypal.*login.*verify.*",
            r".*amazon.*account.*suspended.*",
            r".*apple.*id.*locked.*",
            r".*microsoft.*security.*alert.*",
            r".*google.*account.*compromised.*",
            r".*bank.*account.*frozen.*",
            r".*urgent.*action.*required.*",
            r".*verify.*identity.*immediately.*",
            r".*click.*here.*to.*secure.*",
            r".*limited.*time.*offer.*expires.*",
            r".*congratulations.*you.*won.*",
            r".*claim.*your.*prize.*now.*",
            r".*free.*money.*click.*here.*",
            r".*tax.*refund.*pending.*",
            r".*covid.*relief.*fund.*"
        ]
        
        # Malware patterns
        self.malware_patterns = [
            r".*download.*exe.*free.*",
            r".*install.*codec.*player.*",
            r".*update.*flash.*player.*",
            r".*antivirus.*scan.*now.*",
            r".*system.*infected.*clean.*",
            r".*driver.*update.*required.*",
            r".*software.*crack.*keygen.*",
            r".*torrent.*download.*",
            r".*warez.*serial.*key.*"
        ]
        
        # Scam patterns
        self.scam_patterns = [
            r".*crypto.*investment.*guaranteed.*",
            r".*bitcoin.*double.*your.*money.*",
            r".*work.*from.*home.*easy.*money.*",
            r".*romance.*dating.*lonely.*",
            r".*tech.*support.*call.*now.*",
            r".*irs.*tax.*debt.*relief.*",
            r".*lottery.*winner.*claim.*prize.*",
            r".*inheritance.*money.*transfer.*",
            r".*charity.*donation.*urgent.*help.*",
            r".*medical.*emergency.*funds.*needed.*"
        ]
        
        logger.info(f"Loaded {len(self.phishing_patterns)} phishing, {len(self.malware_patterns)} malware, and {len(self.scam_patterns)} scam patterns")
    
    def _initialize_url_shorteners(self) -> None:
        """Initialize URL shortener services"""
        self.url_shorteners.update([
            'bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly',
            'short.link', 'tiny.cc', 'is.gd', 'buff.ly', 'rebrand.ly',
            'clickmeter.com', 'cutt.ly', 'short.io', 'switchy.io',
            'bl.ink', 'lnk.bio', 'linktr.ee', 'soo.gd', 'clicky.me',
            'x.co', 'v.gd', 'tr.im', 'url.ie', 'tiny.one'
        ])
        
        logger.info(f"Loaded {len(self.url_shorteners)} URL shortener services")
    
    def _initialize_suspicious_tlds(self) -> None:
        """Initialize suspicious top-level domains"""
        self.suspicious_tlds.update([
            '.tk', '.ml', '.ga', '.cf', '.pw', '.top', '.click',
            '.download', '.stream', '.science', '.racing', '.review',
            '.country', '.kim', '.cricket', '.party', '.work',
            '.men', '.date', '.faith', '.accountant', '.loan',
            '.win', '.trade', '.bid', '.webcam', '.gdn'
        ])
        
        logger.info(f"Loaded {len(self.suspicious_tlds)} suspicious TLDs")
    
    def scan_url(self, url: str, scan_type: URLType = URLType.DIRECT) -> LinkScanReport:
        """Comprehensive URL scanning and analysis"""
        start_time = time.time()
        scan_id = f"scan_{int(time.time())}_{hash(url) % 10000}"
        
        logger.info(f"Scanning URL: {url}")
        
        # Check cache first
        url_hash = hashlib.sha256(url.encode()).hexdigest()
        if url_hash in self.scan_cache:
            cached_report = self.scan_cache[url_hash]
            cache_age = time.time() - time.mktime(time.strptime(cached_report.scan_metadata['scan_timestamp'], '%Y-%m-%d %H:%M:%S'))
            if cache_age < self.cache_ttl:
                self.scan_stats['cache_hits'] += 1
                logger.info(f"Returning cached result for {url}")
                return cached_report
        
        try:
            # Step 1: URL Analysis
            url_analysis = self._analyze_url_structure(url, scan_type)
            
            # Step 2: Domain Information
            domain_info = self._get_domain_info(url_analysis.domain)
            
            # Step 3: Multiple Scan Engines
            scan_results = self._run_scan_engines(url_analysis)
            
            # Step 4: Calculate Overall Verdict
            overall_verdict, risk_score = self._calculate_verdict(url_analysis, scan_results)
            
            # Step 5: Generate Recommendations
            recommendations = self._generate_recommendations(url_analysis, overall_verdict, risk_score)
            mitigation_actions = self._generate_mitigation_actions(overall_verdict, risk_score)
            
            # Step 6: Calculate False Positive Likelihood
            false_positive_likelihood = self._calculate_false_positive_likelihood(url_analysis, scan_results)
            
            # Create comprehensive report
            scan_duration = time.time() - start_time
            
            report = LinkScanReport(
                scan_id=scan_id,
                url_analysis=url_analysis,
                domain_info=domain_info,
                scan_results=scan_results,
                overall_verdict=overall_verdict,
                risk_score=risk_score,
                recommendations=recommendations,
                mitigation_actions=mitigation_actions,
                false_positive_likelihood=false_positive_likelihood,
                scan_metadata={
                    'scan_timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
                    'scan_duration': scan_duration,
                    'scanner_version': '1.0',
                    'engines_used': [result.engine.value for result in scan_results]
                }
            )
            
            # Cache the result
            self.scan_cache[url_hash] = report
            
            # Update statistics
            self.scan_stats['total_scans'] += 1
            if overall_verdict == 'malicious':
                self.scan_stats['malicious_detected'] += 1
            elif overall_verdict == 'suspicious':
                self.scan_stats['suspicious_detected'] += 1
            
            logger.info(f"URL scan completed: {overall_verdict} (Risk: {risk_score:.1f}/100) in {scan_duration:.2f}s")
            return report
            
        except Exception as e:
            logger.error(f"Error scanning URL {url}: {e}")
            
            # Return error report
            return LinkScanReport(
                scan_id=scan_id,
                url_analysis=URLAnalysis(
                    url=url, original_url=url, final_url=url,
                    url_type=scan_type, domain="", subdomain="", tld="",
                    path="", query_params={}, fragments="",
                    redirect_chain=[url], redirect_count=0,
                    is_shortened=False, is_suspicious=True, is_malicious=False,
                    threat_categories=[], reputation_score=50.0, confidence_score=0.0,
                    scan_timestamp=time.strftime('%Y-%m-%d %H:%M:%S'),
                    scan_duration=time.time() - start_time
                ),
                domain_info=None,
                scan_results=[],
                overall_verdict="error",
                risk_score=50.0,
                recommendations=["Unable to scan URL due to error"],
                mitigation_actions=["Exercise caution when accessing this URL"],
                false_positive_likelihood=0.5,
                scan_metadata={
                    'scan_timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
                    'scan_duration': time.time() - start_time,
                    'error': str(e)
                }
            )
    
    def _analyze_url_structure(self, url: str, scan_type: URLType) -> URLAnalysis:
        """Analyze URL structure and components"""
        start_time = time.time()
        original_url = url
        
        # Parse URL
        try:
            parsed = urlparse(url)
            domain = parsed.netloc.lower()
            path = parsed.path
            query_params = parse_qs(parsed.query)
            fragments = parsed.fragment
            
            # Extract subdomain and TLD
            domain_parts = domain.split('.')
            if len(domain_parts) >= 2:
                tld = '.' + domain_parts[-1]
                if len(domain_parts) > 2:
                    subdomain = '.'.join(domain_parts[:-2])
                    domain = '.'.join(domain_parts[-2:])
                else:
                    subdomain = ""
            else:
                tld = ""
                subdomain = ""
            
        except Exception as e:
            logger.error(f"Error parsing URL {url}: {e}")
            domain = subdomain = tld = path = fragments = ""
            query_params = {}
        
        # Check if URL is shortened
        is_shortened = any(domain.endswith(shortener) for shortener in self.url_shorteners)
        
        # Resolve redirects and get final URL
        redirect_chain = [url]
        final_url = url
        redirect_count = 0
        
        if self.session:
            try:
                response = self.session.head(url, allow_redirects=True, timeout=10)
                final_url = response.url
                redirect_count = len(response.history)
                
                # Build redirect chain
                redirect_chain = [url]
                for resp in response.history:
                    redirect_chain.append(resp.url)
                if final_url not in redirect_chain:
                    redirect_chain.append(final_url)
                    
            except Exception as e:
                logger.warning(f"Could not resolve redirects for {url}: {e}")
        
        # Analyze for suspicious patterns
        is_suspicious = self._is_url_suspicious(url, domain, path, query_params)
        
        # Check against known malicious domains
        is_malicious = domain in self.malicious_domains
        
        # Determine threat categories
        threat_categories = self._identify_threat_categories(url, domain, path)
        
        # Calculate reputation score
        reputation_score = self._calculate_reputation_score(domain, tld, is_shortened, threat_categories)
        
        # Calculate confidence score
        confidence_score = self._calculate_confidence_score(domain, threat_categories, is_malicious)
        
        return URLAnalysis(
            url=url,
            original_url=original_url,
            final_url=final_url,
            url_type=scan_type,
            domain=domain,
            subdomain=subdomain,
            tld=tld,
            path=path,
            query_params=query_params,
            fragments=fragments,
            redirect_chain=redirect_chain,
            redirect_count=redirect_count,
            is_shortened=is_shortened,
            is_suspicious=is_suspicious,
            is_malicious=is_malicious,
            threat_categories=threat_categories,
            reputation_score=reputation_score,
            confidence_score=confidence_score,
            scan_timestamp=time.strftime('%Y-%m-%d %H:%M:%S'),
            scan_duration=time.time() - start_time
        )
    
    def _is_url_suspicious(self, url: str, domain: str, path: str, query_params: Dict) -> bool:
        """Check if URL has suspicious characteristics"""
        suspicious_indicators = 0
        
        # Check domain characteristics
        if domain in self.suspicious_domains:
            suspicious_indicators += 3
        
        # Check for suspicious TLD
        for tld in self.suspicious_tlds:
            if domain.endswith(tld):
                suspicious_indicators += 2
                break
        
        # Check for IP address instead of domain
        if re.match(r'^\d+\.\d+\.\d+\.\d+', domain):
            suspicious_indicators += 4
        
        # Check for excessive subdomains
        if domain.count('.') > 3:
            suspicious_indicators += 2
        
        # Check for suspicious path patterns
        suspicious_path_patterns = [
            r'/[a-zA-Z0-9]{20,}',  # Long random strings
            r'/\d{10,}',  # Long numeric strings
            r'/[a-f0-9]{32}',  # MD5-like strings
            r'/temp/',
            r'/tmp/',
            r'/cache/',
            r'/download\.php',
            r'/redirect\.php'
        ]
        
        for pattern in suspicious_path_patterns:
            if re.search(pattern, path, re.IGNORECASE):
                suspicious_indicators += 1
        
        # Check for suspicious query parameters
        suspicious_params = ['redirect', 'goto', 'url', 'link', 'target', 'continue']
        for param in suspicious_params:
            if param in query_params:
                suspicious_indicators += 1
        
        # Check for URL encoding obfuscation
        if '%' in url and url.count('%') > 5:
            suspicious_indicators += 2
        
        return suspicious_indicators >= 3
    
    def _identify_threat_categories(self, url: str, domain: str, path: str) -> List[ThreatCategory]:
        """Identify potential threat categories"""
        categories = []
        url_lower = url.lower()
        
        # Check phishing patterns
        for pattern in self.phishing_patterns:
            if re.search(pattern, url_lower):
                categories.append(ThreatCategory.PHISHING)
                break
        
        # Check malware patterns
        for pattern in self.malware_patterns:
            if re.search(pattern, url_lower):
                categories.append(ThreatCategory.MALWARE)
                break
        
        # Check scam patterns
        for pattern in self.scam_patterns:
            if re.search(pattern, url_lower):
                categories.append(ThreatCategory.SCAM)
                break
        
        # Check for specific threat indicators
        if any(word in url_lower for word in ['crypto', 'bitcoin', 'investment', 'trading']):
            categories.append(ThreatCategory.CRYPTOCURRENCY_SCAM)
        
        if any(word in url_lower for word in ['support', 'help', 'call', 'phone']):
            categories.append(ThreatCategory.TECH_SUPPORT_SCAM)
        
        if any(word in url_lower for word in ['dating', 'romance', 'love', 'lonely']):
            categories.append(ThreatCategory.ROMANCE_SCAM)
        
        if any(word in url_lower for word in ['adult', 'xxx', 'porn', 'sex']):
            categories.append(ThreatCategory.ADULT_CONTENT)
        
        return categories
    
    def _calculate_reputation_score(self, domain: str, tld: str, is_shortened: bool, 
                                  threat_categories: List[ThreatCategory]) -> float:
        """Calculate domain reputation score (0-100, higher is better)"""
        score = 100.0
        
        # Deduct for known malicious domain
        if domain in self.malicious_domains:
            score -= 80.0
        
        # Deduct for suspicious domain
        if domain in self.suspicious_domains:
            score -= 40.0
        
        # Deduct for suspicious TLD
        if tld in self.suspicious_tlds:
            score -= 20.0
        
        # Deduct for URL shortener
        if is_shortened:
            score -= 15.0
        
        # Deduct for threat categories
        score -= len(threat_categories) * 10.0
        
        # Deduct for IP-based domain
        if re.match(r'^\d+\.\d+\.\d+\.\d+', domain):
            score -= 30.0
        
        return max(0.0, min(100.0, score))
    
    def _calculate_confidence_score(self, domain: str, threat_categories: List[ThreatCategory], 
                                  is_malicious: bool) -> float:
        """Calculate confidence score for the analysis"""
        confidence = 0.5  # Base confidence
        
        # High confidence for known malicious domains
        if is_malicious:
            confidence = 0.95
        
        # Increase confidence with more threat indicators
        confidence += len(threat_categories) * 0.1
        
        # Increase confidence for well-known domains (inverse)
        well_known_domains = [
            'google.com', 'facebook.com', 'amazon.com', 'microsoft.com',
            'apple.com', 'twitter.com', 'linkedin.com', 'github.com'
        ]
        
        if any(domain.endswith(known) for known in well_known_domains):
            confidence = max(confidence, 0.9)
        
        return min(1.0, confidence)
    
    def _get_domain_info(self, domain: str) -> Optional[DomainInfo]:
        """Get comprehensive domain information"""
        if not domain:
            return None
        
        try:
            domain_info = DomainInfo(
                domain=domain,
                registrar="",
                creation_date=None,
                expiration_date=None,
                last_updated=None,
                name_servers=[],
                registrant_country="",
                registrant_org="",
                domain_age_days=0,
                is_newly_registered=False,
                is_suspicious_tld=any(domain.endswith(tld) for tld in self.suspicious_tlds),
                dns_records={},
                mx_records=[],
                txt_records=[]
            )
            
            # Get WHOIS information
            if whois:
                try:
                    w = whois.whois(domain)
                    if w:
                        domain_info.registrar = str(w.registrar or "")
                        domain_info.creation_date = str(w.creation_date or "")
                        domain_info.expiration_date = str(w.expiration_date or "")
                        domain_info.last_updated = str(w.updated_date or "")
                        domain_info.registrant_country = str(w.country or "")
                        domain_info.registrant_org = str(w.org or "")
                        
                        # Calculate domain age
                        if w.creation_date:
                            if isinstance(w.creation_date, list):
                                creation_date = w.creation_date[0]
                            else:
                                creation_date = w.creation_date
                            
                            domain_age = (time.time() - creation_date.timestamp()) / 86400
                            domain_info.domain_age_days = int(domain_age)
                            domain_info.is_newly_registered = domain_age < 30  # Less than 30 days
                            
                except Exception as e:
                    logger.warning(f"WHOIS lookup failed for {domain}: {e}")
            
            # Get DNS information
            if dns:
                try:
                    # A records
                    a_records = dns.resolver.resolve(domain, 'A')
                    domain_info.dns_records['A'] = [str(record) for record in a_records]
                    
                    # MX records
                    try:
                        mx_records = dns.resolver.resolve(domain, 'MX')
                        domain_info.mx_records = [str(record) for record in mx_records]
                        domain_info.dns_records['MX'] = domain_info.mx_records
                    except:
                        pass
                    
                    # TXT records
                    try:
                        txt_records = dns.resolver.resolve(domain, 'TXT')
                        domain_info.txt_records = [str(record) for record in txt_records]
                        domain_info.dns_records['TXT'] = domain_info.txt_records
                    except:
                        pass
                    
                    # NS records
                    try:
                        ns_records = dns.resolver.resolve(domain, 'NS')
                        domain_info.name_servers = [str(record) for record in ns_records]
                        domain_info.dns_records['NS'] = domain_info.name_servers
                    except:
                        pass
                        
                except Exception as e:
                    logger.warning(f"DNS lookup failed for {domain}: {e}")
            
            return domain_info
            
        except Exception as e:
            logger.error(f"Error getting domain info for {domain}: {e}")
            return None
    
    def _run_scan_engines(self, url_analysis: URLAnalysis) -> List[ScanResult]:
        """Run multiple scan engines"""
        scan_results = []
        
        # Internal engine (always runs)
        internal_result = self._run_internal_scan(url_analysis)
        scan_results.append(internal_result)
        
        # External engines (if available)
        if self.session:
            # Simulate external engine results
            # In production, integrate with real services like VirusTotal, URLVoid, etc.
            
            # Simulated VirusTotal result
            vt_result = ScanResult(
                engine=ScanEngine.VIRUSTOTAL,
                is_malicious=url_analysis.is_malicious,
                threat_categories=url_analysis.threat_categories,
                confidence=0.8,
                details={'engines_detected': 0 if not url_analysis.is_malicious else 5},
                scan_time=0.5,
                error=None
            )
            scan_results.append(vt_result)
            
            # Simulated URLVoid result
            urlvoid_result = ScanResult(
                engine=ScanEngine.URLVOID,
                is_malicious=url_analysis.reputation_score < 30,
                threat_categories=[ThreatCategory.SUSPICIOUS] if url_analysis.is_suspicious else [],
                confidence=0.7,
                details={'reputation_score': url_analysis.reputation_score},
                scan_time=0.3,
                error=None
            )
            scan_results.append(urlvoid_result)
        
        return scan_results
    
    def _run_internal_scan(self, url_analysis: URLAnalysis) -> ScanResult:
        """Run internal scanning engine"""
        start_time = time.time()
        
        is_malicious = url_analysis.is_malicious or url_analysis.reputation_score < 20
        threat_categories = url_analysis.threat_categories.copy()
        
        if url_analysis.is_suspicious and not threat_categories:
            threat_categories.append(ThreatCategory.SUSPICIOUS)
        
        confidence = url_analysis.confidence_score
        
        details = {
            'reputation_score': url_analysis.reputation_score,
            'is_shortened': url_analysis.is_shortened,
            'redirect_count': url_analysis.redirect_count,
            'suspicious_indicators': len(threat_categories)
        }
        
        return ScanResult(
            engine=ScanEngine.INTERNAL,
            is_malicious=is_malicious,
            threat_categories=threat_categories,
            confidence=confidence,
            details=details,
            scan_time=time.time() - start_time,
            error=None
        )
    
    def _calculate_verdict(self, url_analysis: URLAnalysis, 
                         scan_results: List[ScanResult]) -> Tuple[str, float]:
        """Calculate overall verdict and risk score"""
        malicious_votes = sum(1 for result in scan_results if result.is_malicious)
        total_votes = len(scan_results)
        
        # Calculate weighted risk score
        risk_score = 0.0
        total_weight = 0.0
        
        for result in scan_results:
            weight = result.confidence
            if result.is_malicious:
                risk_score += 100.0 * weight
            elif result.threat_categories:
                risk_score += 60.0 * weight
            else:
                risk_score += 10.0 * weight
            total_weight += weight
        
        if total_weight > 0:
            risk_score /= total_weight
        
        # Determine verdict
        if malicious_votes >= total_votes * 0.5:  # Majority vote
            verdict = "malicious"
        elif risk_score > 60 or url_analysis.is_suspicious:
            verdict = "suspicious"
        else:
            verdict = "safe"
        
        return verdict, min(100.0, risk_score)
    
    def _generate_recommendations(self, url_analysis: URLAnalysis, 
                                verdict: str, risk_score: float) -> List[str]:
        """Generate security recommendations"""
        recommendations = []
        
        if verdict == "malicious":
            recommendations.extend([
                "🚨 DO NOT visit this URL - it is malicious",
                "Block this domain in your firewall/DNS",
                "Report this URL to security vendors",
                "Scan your system for malware if already visited",
                "Change passwords if credentials were entered"
            ])
        elif verdict == "suspicious":
            recommendations.extend([
                "⚠️ Exercise extreme caution with this URL",
                "Verify the URL source before visiting",
                "Use a sandboxed browser if you must visit",
                "Do not enter personal information",
                "Consider using a VPN for additional protection"
            ])
        else:
            recommendations.extend([
                "✅ URL appears safe based on current analysis",
                "Always verify URLs from unknown sources",
                "Keep your browser and security software updated",
                "Be cautious of any download prompts"
            ])
        
        # Additional recommendations based on URL characteristics
        if url_analysis.is_shortened:
            recommendations.append("🔗 URL is shortened - verify the final destination")
        
        if url_analysis.redirect_count > 3:
            recommendations.append("🔄 Multiple redirects detected - be cautious")
        
        if url_analysis.threat_categories:
            categories_str = ", ".join([cat.value for cat in url_analysis.threat_categories])
            recommendations.append(f"⚠️ Potential threats detected: {categories_str}")
        
        return recommendations
    
    def _generate_mitigation_actions(self, verdict: str, risk_score: float) -> List[str]:
        """Generate mitigation actions"""
        actions = []
        
        if verdict == "malicious":
            actions.extend([
                "Block URL in security systems",
                "Add domain to blacklist",
                "Notify security team",
                "Initiate incident response if accessed",
                "Update threat intelligence feeds"
            ])
        elif verdict == "suspicious":
            actions.extend([
                "Monitor for additional indicators",
                "Add to watch list",
                "Increase logging for this domain",
                "Consider temporary blocking"
            ])
        
        if risk_score > 80:
            actions.append("Immediate action required")
        elif risk_score > 60:
            actions.append("Elevated monitoring recommended")
        
        return actions
    
    def _calculate_false_positive_likelihood(self, url_analysis: URLAnalysis, 
                                           scan_results: List[ScanResult]) -> float:
        """Calculate likelihood of false positive"""
        # Base false positive rate
        fp_likelihood = 0.1
        
        # Increase for legitimate-looking domains
        well_known_domains = [
            'google.com', 'facebook.com', 'amazon.com', 'microsoft.com',
            'apple.com', 'twitter.com', 'linkedin.com', 'github.com'
        ]
        
        if any(url_analysis.domain.endswith(known) for known in well_known_domains):
            fp_likelihood += 0.3
        
        # Decrease for known malicious indicators
        if url_analysis.domain in self.malicious_domains:
            fp_likelihood = 0.01
        
        # Adjust based on scan engine agreement
        malicious_count = sum(1 for result in scan_results if result.is_malicious)
        if malicious_count == len(scan_results):
            fp_likelihood *= 0.5  # All engines agree
        elif malicious_count == 0:
            fp_likelihood += 0.2  # No engines detected threats
        
        return min(1.0, fp_likelihood)
    
    def scan_multiple_urls(self, urls: List[str]) -> List[LinkScanReport]:
        """Scan multiple URLs efficiently"""
        reports = []
        
        for url in urls:
            try:
                report = self.scan_url(url)
                reports.append(report)
            except Exception as e:
                logger.error(f"Error scanning URL {url}: {e}")
        
        return reports
    
    def get_scan_statistics(self) -> Dict[str, Any]:
        """Get scanning statistics"""
        return {
            'total_scans': self.scan_stats['total_scans'],
            'malicious_detected': self.scan_stats['malicious_detected'],
            'suspicious_detected': self.scan_stats['suspicious_detected'],
            'false_positives': self.scan_stats['false_positives'],
            'cache_hits': self.scan_stats['cache_hits'],
            'cache_size': len(self.scan_cache),
            'malicious_domains_count': len(self.malicious_domains),
            'suspicious_domains_count': len(self.suspicious_domains),
            'url_shorteners_count': len(self.url_shorteners),
            'suspicious_tlds_count': len(self.suspicious_tlds)
        }
    
    def update_threat_database(self, malicious_domains: List[str] = None, 
                             suspicious_domains: List[str] = None) -> None:
        """Update threat databases"""
        if malicious_domains:
            self.malicious_domains.update(malicious_domains)
            logger.info(f"Added {len(malicious_domains)} malicious domains")
        
        if suspicious_domains:
            self.suspicious_domains.update(suspicious_domains)
            logger.info(f"Added {len(suspicious_domains)} suspicious domains")
    
    def export_scan_results(self, filename: str, reports: List[LinkScanReport] = None) -> None:
        """Export scan results to JSON file"""
        try:
            if reports is None:
                reports = list(self.scan_cache.values())
            
            export_data = {
                'export_timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
                'total_reports': len(reports),
                'scan_statistics': self.get_scan_statistics(),
                'reports': [asdict(report) for report in reports]
            }
            
            with open(filename, 'w') as f:
                json.dump(export_data, f, indent=2, default=str)
            
            logger.info(f"Exported {len(reports)} scan results to {filename}")
            
        except Exception as e:
            logger.error(f"Failed to export scan results: {e}")
    
    def clear_cache(self) -> None:
        """Clear scan cache"""
        self.scan_cache.clear()
        logger.info("Scan cache cleared")