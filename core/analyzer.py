# EnvelopeX - Email Forensics Analyzer

from .parser import parse_eml_bytes

import email
import hashlib
import html
import logging
import os
import re
import tempfile
from datetime import datetime, timezone
from email import policy
from email.parser import BytesParser
from email.utils import parseaddr, getaddresses, parsedate_to_datetime
from email.header import decode_header
from typing import Dict, List, Optional
from urllib.parse import urlparse

import dkim
from bs4 import BeautifulSoup

try:
    import extract_msg
    MSG_SUPPORT = True
except ImportError:
    MSG_SUPPORT = False

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class EmailForensicsAnalyzer:
    
    VERSION = "1.0.0"
    
    URL_REGEX = re.compile(r'https?://[^\s<>"\'()]+', re.IGNORECASE)
    IP_REGEX = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
    EMAIL_REGEX = re.compile(r'[\w\.-]+@[\w\.-]+\.\w+')
    HASH_REGEX = re.compile(r'\b[a-fA-F0-9]{32,128}\b')
    DOMAIN_REGEX = re.compile(r'\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,63}\b')
    
    def __init__(self):
        self.email_message = None
        self.raw_email = None
        self.file_path = None
        self.parsing_errors = []
        
    def analyze_email(
        self,
        file_content: bytes,
        filename: str,
        metadata: Optional[Dict] = None
    ) -> Dict:
        temp_path = None
        try:
            temp_path = self._save_temp_file(file_content, filename)
            self.file_path = temp_path
            self.raw_email = file_content
            
            tempdir = tempfile.mkdtemp(prefix='envelopex_')
            try:
                parsed_message = parse_eml_bytes(
                    file_content,
                    tempdir=tempdir,
                    message_index=1
                )
                
                report = self._transform_to_frontend_format(
                    parsed_message,
                    filename,
                    file_content,
                    metadata or {}
                )
                
                return report
            finally:
                import shutil
                try:
                    shutil.rmtree(tempdir, ignore_errors=True)
                except Exception:
                    pass
                # Fallback to legacy extraction
                return self._legacy_analysis(
                    file_content,
                    filename,
                    metadata or {}
                )
            
        except Exception as e:
            logger.error(f"Analysis failed: {str(e)}", exc_info=True)
            return self._error_response(
                f"Analysis exception: {str(e)}",
                filename,
                len(file_content)
            )
        finally:
            # Cleanup
            if temp_path and os.path.exists(temp_path):
                try:
                    os.unlink(temp_path)
                except Exception as e:
                    logger.warning(f"Cleanup failed: {e}")
    
    def _transform_to_frontend_format(
        self,
        parsed_message: Dict,
        filename: str,
        file_content: bytes,
        client_metadata: Dict
    ) -> Dict:
        """
        Transform ext.py output to frontend-compatible format
        """
        # Extract key sections from ext.py output
        essential = parsed_message.get('essential_headers', {})
        headers_raw = parsed_message.get('headers_raw', {})
        body = parsed_message.get('body', {})
        iocs = parsed_message.get('iocs', {})
        auth = parsed_message.get('authentication', {})
        attachments = parsed_message.get('attachments', [])
        phishing = parsed_message.get('phishing', {})
        tracking = parsed_message.get('tracking', {})
        obfuscation = parsed_message.get('obfuscation', {})
        timeline = parsed_message.get('timeline', {})
        
        # Build metadata for frontend (legacy compatibility)
        metadata = {
            'from': headers_raw.get('From'),
            'from_email': essential.get('from'),
            'from_display_name': essential.get('from_display_name'),
            'to': essential.get('to', []),
            'cc': essential.get('cc', []),
            'bcc': essential.get('bcc', []),
            'subject': essential.get('subject'),
            'date': essential.get('date'),
            'message_id': essential.get('message_id'),
            'reply_to': essential.get('reply_to'),
            'return_path': essential.get('return_path'),
            'originating_ip': self._extract_ip_from_received(
                parsed_message.get('received_parsed', [])
            ),
            'reverse_dns': self._extract_rdns_from_received_parsed(
                parsed_message.get('received_parsed', [])
            ),
            'sender_domain': (
                essential.get('from', '').split('@')[-1]
                if essential.get('from') and '@' in essential.get('from', '')
                else None
            )
        }
        
        # Build headers dict for frontend table
        headers_dict = {k: str(v) for k, v in headers_raw.items()}
        
        # Build anomalies list from phishing indicators + auth failures
        anomalies = self._build_anomalies_from_ext(phishing, auth)
        
        # Transform authentication to frontend format
        authentication = {
            'spf': {
                'spf_pass_fail': auth.get('spf', 'unknown'),
                'spf_domain': None,
                'spf_explanation': headers_raw.get('Received-SPF')
            },
            'dkim': {
                'dkim_pass_fail': auth.get('dkim', 'unknown'),
                'dkim_selector': None,
                'dkim_domain': None,
                'dkim_signature_header_present': bool(
                    headers_raw.get('DKIM-Signature')
                )
            },
            'dmarc': {
                'dmarc_policy': None,
                'dmarc_pass_fail': auth.get('dmarc', 'unknown'),
                'dmarc_alignment': None
            },
            'arc': {
                'arc_seal_present': bool(headers_raw.get('ARC-Seal')),
                'arc_message_signature_present': bool(
                    headers_raw.get('ARC-Message-Signature')
                ),
                'arc_authentication_results_present': bool(
                    headers_raw.get('ARC-Authentication-Results')
                )
            }
        }
        
        # Build final report
        report = {
            # Frontend compatibility
            'metadata': metadata,
            'headers': headers_dict,
            'authentication': authentication,
            'body': {
                'body_text': body.get('text'),
                'body_text_length': body.get('text_length', 0),
                'body_html_raw': body.get('html_raw'),
                'body_html_sanitized': body.get('html_sanitized'),
                'has_scripts': bool(
                    re.search(r'<script', body.get('html_raw', ''), re.I)
                ),
                'has_iframes': bool(
                    re.search(r'<iframe', body.get('html_raw', ''), re.I)
                ),
                'has_external_images': bool(tracking.get('remote_image_urls')),
                'has_obfuscated_content': bool(
                    obfuscation.get('base64_blobs')
                ),
                'body_language': body.get('language'),
                'body_charset': body.get('charset')
            },
            'iocs': {
                'urls': iocs.get('urls', []),
                'urls_count': len(iocs.get('urls', [])),
                'urls_suspicious': [
                    u for u in iocs.get('urls', [])
                    if self._is_suspicious_url(u)
                ],
                'domains': iocs.get('domains', []),
                'primary_domain': (
                    iocs.get('domains', [])[0]
                    if iocs.get('domains') else None
                ),
                'domain_variants': [],
                'homograph_suspected': phishing.get(
                    'homograph_suspected', False
                ),
                'ips': iocs.get('ips', []),
                'geoip_data': None,
                'emails_extracted': iocs.get('emails', []),
                'hashes_extracted': iocs.get('hashes', [])
            },
            'attachments': attachments,
            'anomalies': anomalies,
            
            # Complete forensics data (ext.py format)
            'forensics': {
                'file_metadata': {
                    'file_name': filename,
                    'file_type': self._detect_file_type(
                        filename, file_content
                    ),
                    'file_size': len(file_content),
                    'md5': hashlib.md5(file_content).hexdigest(),
                    'sha1': hashlib.sha1(file_content).hexdigest(),
                    'sha256': hashlib.sha256(file_content).hexdigest(),
                    'parsed_at': datetime.utcnow().isoformat() + 'Z',
                    'parser_version': self.VERSION,
                    'is_multipart': parsed_message.get(
                        'analysis_flags', {}
                    ).get('is_multipart', False),
                    'parsing_errors': []
                },
                'complete_extraction': parsed_message,
                'tracking': tracking,
                'obfuscation': obfuscation,
                'timeline': timeline,
                'phishing_indicators': phishing,
                'client_metadata': client_metadata
            }
        }
        
        return report
    
    def _extract_ip_from_received(
        self, received_parsed: List[Dict]
    ) -> Optional[str]:
        """Extract originating IP from parsed received headers"""
        if not received_parsed:
            return None
        
        # Get the first (oldest) hop
        for hop in received_parsed:
            ip = hop.get('from_ip')
            if ip and not self._is_private_ip(ip):
                return ip
        
        return None
    
    def _extract_rdns_from_received_parsed(
        self, received_parsed: List[Dict]
    ) -> Optional[str]:
        """Extract reverse DNS from parsed received headers"""
        if not received_parsed:
            return None
        
        # Get the first (oldest) hop
        for hop in received_parsed:
            server = hop.get('from_server')
            if server and '.' in server:
                return server
        
        return None
    
    def _build_anomalies_from_ext(
        self, phishing: Dict, auth: Dict
    ) -> List[Dict]:
        """Build anomalies list from ext.py phishing data"""
        anomalies = []
        
        if phishing.get('display_name_spoofed'):
            anomalies.append({
                'type': 'DISPLAY_NAME_SPOOFED',
                'severity': 'high',
                'description': 'Sender display name may be spoofed'
            })
        
        if phishing.get('reply_to_mismatch'):
            anomalies.append({
                'type': 'REPLY_TO_MISMATCH',
                'severity': 'medium',
                'description': 'Reply-To differs from sender address'
            })
        
        if phishing.get('homograph_suspected'):
            anomalies.append({
                'type': 'HOMOGRAPH_SUSPECTED',
                'severity': 'high',
                'description': 'Possible homograph/lookalike domain detected'
            })
        
        for brand in phishing.get('brand_impersonation', []):
            anomalies.append({
                'type': 'BRAND_IMPERSONATION',
                'severity': 'high',
                'description': f'Possible impersonation: {brand}'
            })
        
        # Auth failures
        if auth.get('spf') == 'fail':
            anomalies.append({
                'type': 'SPF_FAILURE',
                'severity': 'high',
                'description': 'SPF validation failed'
            })
        
        if auth.get('dkim') == 'fail':
            anomalies.append({
                'type': 'DKIM_FAILURE',
                'severity': 'high',
                'description': 'DKIM signature validation failed'
            })
        
        if auth.get('dmarc') == 'fail':
            anomalies.append({
                'type': 'DMARC_FAILURE',
                'severity': 'high',
                'description': 'DMARC validation failed'
            })
        
        return anomalies
    
    def _is_suspicious_url(self, url: str) -> bool:
        """Check if URL is suspicious"""
        suspicious_patterns = [
            r'bit\.ly',
            r'tinyurl',
            r'awstrack',
            r'@',
            r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}',
            r'-login',
            r'-secure',
            r'verify',
            r'update.*account',
        ]
        
        for pattern in suspicious_patterns:
            if re.search(pattern, url, re.IGNORECASE):
                return True
        
        return False
    
    def _is_private_ip(self, ip: str) -> bool:
        """Check if IP is private/internal"""
        private_ranges = [
            r'^10\.',
            r'^172\.(1[6-9]|2[0-9]|3[01])\.',
            r'^192\.168\.',
            r'^127\.',
            r'^169\.254\.',
            r'^::1$',
            r'^fe80:',
            r'^fc00:',
            r'^fd00:'
        ]
        
        for pattern in private_ranges:
            if re.match(pattern, ip):
                return True
        
        return False
    
    def _legacy_analysis(
        self,
        file_content: bytes,
        filename: str,
        metadata: Dict
    ) -> Dict:
        """Fallback to legacy analysis if ext.py not available"""
        return {
            'error': (
                'Advanced extraction not available. '
                'Install ext.py dependencies.'
            ),
            'metadata': {
                'file_name': filename,
                'file_size': len(file_content)
            }
        }
    
    def _save_temp_file(self, content: bytes, filename: str) -> str:
        """Save file content to temporary location"""
        ext = os.path.splitext(filename)[1] or '.eml'
        fd, path = tempfile.mkstemp(suffix=ext, prefix='envelopex_')
        try:
            os.write(fd, content)
        finally:
            os.close(fd)
        return path
    
    def _detect_file_type(self, filename: str, content: bytes) -> str:
        """Detect file type from extension and content"""
        ext = filename.lower().split('.')[-1]
        
        # Validate against content signatures
        if ext == 'msg':
            # MSG files start with D0CF11E0 (OLE compound file)
            if content[:4] == b'\xD0\xCF\x11\xE0':
                return 'msg'
        elif ext in ['eml', 'txt', 'emlx']:
            # EML files should contain email headers
            try:
                decoded = content.decode('utf-8', errors='ignore')
                if 'From:' in decoded or 'Subject:' in decoded:
                    return 'eml'
            except Exception:
                pass
        elif ext == 'mbox':
            return 'mbox'
        
        # Default to eml for text-like content
        return 'eml'
    
    def _parse_email(self, content: bytes, file_type: str) -> bool:
        """Parse email based on detected type"""
        try:
            if file_type == 'msg' and MSG_SUPPORT:
                return self._parse_msg(content)
            else:
                return self._parse_eml(content)
        except Exception as e:
            self.parsing_errors.append(f"Parse error: {str(e)}")
            logger.error(f"Parsing failed: {e}", exc_info=True)
            return False
    
    def _parse_eml(self, content: bytes) -> bool:
        """Parse EML/MBOX/TXT format"""
        try:
            parser = BytesParser(policy=policy.default)
            self.email_message = parser.parsebytes(content)
            self.raw_email = content
            return True
        except Exception as e:
            self.parsing_errors.append(f"EML parse error: {str(e)}")
            return False
    
    def _parse_msg(self, content: bytes) -> bool:
        """Parse Microsoft MSG format"""
        try:
            if not MSG_SUPPORT:
                self.parsing_errors.append("MSG support not available")
                return False
            
            msg = extract_msg.Message(self.file_path)
            
            # Convert to EmailMessage
            self.email_message = email.message.EmailMessage()
            self.email_message['From'] = msg.sender or ''
            self.email_message['To'] = msg.to or ''
            self.email_message['Cc'] = msg.cc or ''
            self.email_message['Subject'] = msg.subject or ''
            self.email_message['Date'] = msg.date or ''
            
            if msg.body:
                self.email_message.set_content(msg.body)
            
            self.raw_email = content
            return True
            
        except Exception as e:
            self.parsing_errors.append(f"MSG parse error: {str(e)}")
            return False
    
    def _build_forensic_report(
        self,
        filename: str,
        file_content: bytes,
        metadata: Dict
    ) -> Dict:
        """Build comprehensive forensic report with all fields"""
        
        parsed_at = datetime.utcnow()
        
        # Calculate file hashes
        md5_hash = hashlib.md5(file_content).hexdigest()
        sha1_hash = hashlib.sha1(file_content).hexdigest()
        sha256_hash = hashlib.sha256(file_content).hexdigest()
        
        # Extract all forensic components
        headers = self._extract_headers()
        authentication = self._analyze_authentication()
        body = self._extract_body()
        attachments = self._extract_attachments()
        iocs = self._extract_iocs(body)
        timeline = self._build_timeline(headers)
        phishing_indicators = self._detect_phishing_indicators(
            headers, body, iocs
        )
        obfuscation = self._detect_obfuscation(body)
        tracking = self._detect_tracking(body)
        
        # Build comprehensive forensic report with backward compatibility
        report = {
            # Legacy format for frontend compatibility
            'metadata': {
                'from': headers.get('from'),
                'from_email': headers.get('from_email'),
                'from_display_name': headers.get('from_display_name'),
                'to': headers.get('to'),
                'cc': headers.get('cc'),
                'bcc': headers.get('bcc'),
                'subject': headers.get('subject'),
                'date': headers.get('date'),
                'message_id': headers.get('message_id'),
                'reply_to': headers.get('reply_to'),
                'return_path': headers.get('return_path'),
                'originating_ip': headers.get('x_originating_ip'),
                'reverse_dns': headers.get('reverse_dns'),
                'sender_domain': (
                    headers.get('from_email', '').split('@')[-1]
                    if headers.get('from_email') and
                    '@' in headers.get('from_email', '')
                    else None
                )
            },
            
            # Headers as flat object for frontend table
            'headers': {
                item['name']: item['value']
                for item in headers.get('all_headers', [])
            },
            
            # Authentication Results
            'authentication': authentication,
            
            # Body Content
            'body': body,
            
            # IOC Extraction
            'iocs': iocs,
            
            # Attachments
            'attachments': attachments,
            
            # Anomalies (derived from phishing indicators)
            'anomalies': self._build_anomalies_list(
                phishing_indicators, authentication
            ),
            
            # Advanced forensic data (v2.0 format)
            'forensics': {
                'file_metadata': {
                    'file_name': filename,
                    'file_type': self._detect_file_type(
                        filename, file_content
                    ),
                    'file_size': len(file_content),
                    'md5': md5_hash,
                    'sha1': sha1_hash,
                    'sha256': sha256_hash,
                    'parsed_at': parsed_at.isoformat() + 'Z',
                    'parser_version': self.VERSION,
                    'is_multipart': self.email_message.is_multipart(),
                    'parsing_errors': self.parsing_errors
                },
                'header_analysis': headers,
                'phishing_indicators': phishing_indicators,
                'timeline': timeline,
                'tracking': tracking,
                'obfuscation': obfuscation,
                'summary': self._build_summary(
                    iocs, attachments, phishing_indicators
                ),
                'raw_source': {
                    'raw_headers': self._get_raw_headers(),
                    'raw_body': body.get('body_text', '')[:5000],
                    'full_available': True
                },
                'analysis_flags': self._build_analysis_flags(
                    phishing_indicators, attachments, authentication
                ),
                'client_metadata': metadata
            }
        }
        
        return report
    
    def _extract_headers(self) -> Dict:
        """Extract comprehensive RFC 5322 headers"""
        
        # Essential headers
        from_raw = self._get_header('From')
        from_name, from_email = parseaddr(from_raw or '')
        
        to_list = self._parse_address_list('To')
        cc_list = self._parse_address_list('Cc')
        bcc_list = self._parse_address_list('Bcc')
        
        reply_to_raw = self._get_header('Reply-To')
        _, reply_to_email = parseaddr(reply_to_raw or '')
        
        # Routing headers
        received_headers = self.email_message.get_all('Received', [])
        received_parsed = self._parse_received_headers(received_headers)
        
        # Technical headers - extract originating IP and rDNS
        x_originating_ip = self._extract_originating_ip()
        rdns_hostname = self._extract_rdns(x_originating_ip, received_headers)
        
        headers = {
            # Essential
            'from': from_raw,
            'from_display_name': from_name,
            'from_email': from_email,
            'to': to_list,
            'cc': cc_list,
            'bcc': bcc_list,
            'subject': self._get_header('Subject'),
            'date': self._get_header('Date'),
            'message_id': self._get_header('Message-ID'),
            'reply_to': reply_to_email,
            'return_path': self._get_header('Return-Path'),
            
            # Routing
            'received': [str(r) for r in received_headers],
            'received_parsed': received_parsed,
            
            # Additional common headers
            'mime_version': self._get_header('MIME-Version'),
            'content_type': self._get_header('Content-Type'),
            'content_transfer_encoding': self._get_header(
                'Content-Transfer-Encoding'
            ),
            'content_language': self._get_header('Content-Language'),
            'user_agent': self._get_header('User-Agent'),
            'x_mailer': self._get_header('X-Mailer'),
            'x_originating_ip': x_originating_ip,
            'reverse_dns': rdns_hostname,
            'x_sender': self._get_header('X-Sender'),
            'x_received': self._get_header('X-Received'),
            'x_priority': self._get_header('X-Priority'),
            'references': self._get_header('References'),
            'in_reply_to': self._get_header('In-Reply-To'),
            
            # All headers (for completeness)
            'all_headers': [
                {'name': k, 'value': str(v)}
                for k, v in self.email_message.items()
            ]
        }
        
        return headers
    
    def _parse_address_list(self, header_name: str) -> List[Dict]:
        """Parse email address list from header"""
        raw = self._get_header(header_name)
        if not raw:
            return []
        
        addresses = []
        for addr in raw.split(','):
            name, email_addr = parseaddr(addr.strip())
            if email_addr:
                addresses.append({
                    'name': name or None,
                    'email': email_addr
                })
        
        return addresses
    
    def _parse_received_headers(
        self, received_headers: List[str]
    ) -> List[Dict]:
        """Parse Received headers into structured format"""
        parsed = []
        
        for idx, header in enumerate(reversed(received_headers)):
            hop = {
                'hop_number': idx + 1,
                'from_server': None,
                'from_ip': None,
                'by_server': None,
                'by_ip': None,
                'timestamp': None,
                'raw': str(header)
            }
            
            # Extract 'from' server and IP
            from_match = re.search(
                r'from\s+([^\s]+)(?:\s+\(([^\)]+)\))?', header
            )
            if from_match:
                hop['from_server'] = from_match.group(1)
                if from_match.group(2):
                    # Extract IP from parentheses
                    ip_match = re.search(
                        r'\[?(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\]?',
                        from_match.group(2)
                    )
                    if ip_match:
                        hop['from_ip'] = ip_match.group(1)
            
            # Extract 'by' server
            by_match = re.search(r'by\s+([^\s]+)', header)
            if by_match:
                hop['by_server'] = by_match.group(1)
            
            # Extract timestamp
            date_match = re.search(
                r';\s*(.+?)(?:\s+\(|$)', header
            )
            if date_match:
                hop['timestamp'] = date_match.group(1).strip()
            
            parsed.append(hop)
        
        return parsed
    
    def _extract_originating_ip(self) -> Optional[str]:
        """Extract originating IP from various headers"""
        # Priority order
        ip_headers = [
            'X-Originating-IP',
            'X-Sender-IP',
            'X-Real-IP',
            'X-Forwarded-For'
        ]
        
        for header in ip_headers:
            value = self._get_header(header)
            if value:
                ip = self._extract_ip_from_string(value)
                if ip and not self._is_private_ip(ip):
                    return ip
        
        # Extract from Received headers
        received = self.email_message.get_all('Received', [])
        if received:
            # Get first (oldest) Received header
            first = received[-1]
            ips = re.findall(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', first)
            for ip in ips:
                if not self._is_private_ip(ip):
                    return ip
        
        return None
    
    def _extract_rdns(
        self,
        originating_ip: Optional[str],
        received_headers: List[str]
    ) -> Optional[str]:
        """Extract reverse DNS hostname"""
        # Try reverse DNS lookup on the IP
        if originating_ip:
            try:
                import socket
                hostname, _, _ = socket.gethostbyaddr(originating_ip)
                return hostname.rstrip('.')
            except Exception:
                pass
        
        # Extract from Received headers
        if received_headers:
            first_received = received_headers[-1]
            # Look for hostname in "from hostname (IP)" pattern
            from_match = re.search(
                r'from\s+([a-zA-Z0-9][\w\.-]+\.[a-zA-Z]{2,})',
                first_received
            )
            if from_match:
                hostname = from_match.group(1)
                # Exclude localhost-like names
                if not hostname.startswith('localhost'):
                    return hostname.rstrip('.')
        
        return None
    
    def _extract_ip_from_string(self, text: str) -> Optional[str]:
        """Extract IPv4 from string"""
        match = re.search(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', text)
        return match.group(1) if match else None
    
    def _is_private_ip(self, ip: str) -> bool:
        """Check if IP is in private range"""
        try:
            parts = list(map(int, ip.split('.')))
            if parts[0] == 10:
                return True
            if parts[0] == 172 and 16 <= parts[1] <= 31:
                return True
            if parts[0] == 192 and parts[1] == 168:
                return True
            if parts[0] == 127:
                return True
            return False
        except Exception:
            return False
    
    def _analyze_authentication(self) -> Dict:
        """Analyze SPF, DKIM, DMARC, ARC"""
        
        spf = self._check_spf()
        dkim = self._check_dkim()
        dmarc = self._check_dmarc()
        arc = self._check_arc()
        
        return {
            'spf': spf,
            'dkim': dkim,
            'dmarc': dmarc,
            'arc': arc
        }
    
    def _check_spf(self) -> Dict:
        """Extract SPF validation results"""
        spf_header = self._get_header('Received-SPF')
        auth_results = self._get_header('Authentication-Results')
        
        spf_data = {
            'spf_pass_fail': 'unknown',
            'spf_domain': None,
            'spf_explanation': None
        }
        
        # Parse from Received-SPF header
        if spf_header:
            spf_lower = spf_header.lower()
            if 'pass' in spf_lower:
                spf_data['spf_pass_fail'] = 'pass'
            elif 'fail' in spf_lower:
                spf_data['spf_pass_fail'] = 'fail'
            elif 'softfail' in spf_lower:
                spf_data['spf_pass_fail'] = 'softfail'
            elif 'neutral' in spf_lower:
                spf_data['spf_pass_fail'] = 'neutral'
            
            # Extract domain
            domain_match = re.search(r'domain of ([^\s]+)', spf_header)
            if domain_match:
                spf_data['spf_domain'] = domain_match.group(1)
            
            spf_data['spf_explanation'] = spf_header
        
        # Parse from Authentication-Results
        elif auth_results and 'spf=' in auth_results.lower():
            if 'spf=pass' in auth_results.lower():
                spf_data['spf_pass_fail'] = 'pass'
            elif 'spf=fail' in auth_results.lower():
                spf_data['spf_pass_fail'] = 'fail'
            
            spf_data['spf_explanation'] = auth_results
        
        return spf_data
    
    def _check_dkim(self) -> Dict:
        """Check DKIM signature and validation"""
        dkim_header = self._get_header('DKIM-Signature')
        
        dkim_data = {
            'dkim_pass_fail': 'unknown',
            'dkim_selector': None,
            'dkim_domain': None,
            'dkim_signature_header_present': dkim_header is not None
        }
        
        if dkim_header:
            # Parse DKIM parameters
            selector_match = re.search(r's=([^;]+)', dkim_header)
            if selector_match:
                dkim_data['dkim_selector'] = selector_match.group(1).strip()
            
            domain_match = re.search(r'd=([^;]+)', dkim_header)
            if domain_match:
                dkim_data['dkim_domain'] = domain_match.group(1).strip()
            
            # Attempt validation
            if self.raw_email:
                try:
                    is_valid = dkim.verify(self.raw_email)
                    dkim_data['dkim_pass_fail'] = 'pass' if is_valid else 'fail'
                except Exception as e:
                    dkim_data['dkim_pass_fail'] = 'error'
                    dkim_data['validation_error'] = str(e)
        
        return dkim_data
    
    def _check_dmarc(self) -> Dict:
        """Check DMARC policy and alignment"""
        auth_results = self._get_header('Authentication-Results')
        
        dmarc_data = {
            'dmarc_policy': None,
            'dmarc_pass_fail': 'unknown',
            'dmarc_alignment': None
        }
        
        if auth_results:
            auth_lower = auth_results.lower()
            
            if 'dmarc=pass' in auth_lower:
                dmarc_data['dmarc_pass_fail'] = 'pass'
            elif 'dmarc=fail' in auth_lower:
                dmarc_data['dmarc_pass_fail'] = 'fail'
            elif 'dmarc=none' in auth_lower:
                dmarc_data['dmarc_pass_fail'] = 'none'
            
            # Extract policy
            policy_match = re.search(r'policy\.dmarc=([^\s;]+)', auth_results)
            if policy_match:
                dmarc_data['dmarc_policy'] = policy_match.group(1)
        
        return dmarc_data
    
    def _check_arc(self) -> Dict:
        """Check ARC (Authenticated Received Chain)"""
        return {
            'arc_seal_present': self._get_header('ARC-Seal') is not None,
            'arc_message_signature_present': (
                self._get_header('ARC-Message-Signature') is not None
            ),
            'arc_authentication_results_present': (
                self._get_header('ARC-Authentication-Results') is not None
            )
        }
    
    def _extract_body(self) -> Dict:
        """Extract and analyze email body content"""
        body_text = None
        body_html_raw = None
        body_html_sanitized = None
        
        if self.email_message.is_multipart():
            for part in self.email_message.walk():
                content_type = part.get_content_type()
                
                try:
                    payload = part.get_payload(decode=True)
                    if not payload:
                        continue
                    
                    decoded = payload.decode('utf-8', errors='ignore')
                    
                    if content_type == 'text/plain' and not body_text:
                        body_text = decoded
                    elif content_type == 'text/html' and not body_html_raw:
                        body_html_raw = decoded
                except Exception:
                    pass
        else:
            try:
                payload = self.email_message.get_payload(decode=True)
                if payload:
                    decoded = payload.decode('utf-8', errors='ignore')
                    content_type = self.email_message.get_content_type()
                    
                    if content_type == 'text/plain':
                        body_text = decoded
                    elif content_type == 'text/html':
                        body_html_raw = decoded
            except Exception:
                pass
        
        # Extract text from HTML if no plain text
        if not body_text and body_html_raw:
            body_text = self._html_to_text(body_html_raw)
        
        # Sanitize HTML
        if body_html_raw:
            body_html_sanitized = self._sanitize_html(body_html_raw)
        
        # Analyze HTML content
        has_scripts = False
        has_iframes = False
        has_external_images = False
        has_obfuscated_content = False
        
        if body_html_raw:
            soup = BeautifulSoup(body_html_raw, 'html.parser')
            has_scripts = soup.find('script') is not None
            has_iframes = soup.find('iframe') is not None
            
            # Check for external images
            for img in soup.find_all('img'):
                src = img.get('src', '')
                if src.startswith('http'):
                    has_external_images = True
                    break
            
            # Check for obfuscation
            if body_html_raw.count('&#') > 20 or 'base64' in body_html_raw:
                has_obfuscated_content = True
        
        # Detect language and charset
        charset = self.email_message.get_content_charset() or 'utf-8'
        language = self._get_header('Content-Language')
        
        return {
            'body_text': body_text,
            'body_text_length': len(body_text) if body_text else 0,
            'body_html_raw': body_html_raw,
            'body_html_sanitized': body_html_sanitized,
            'has_scripts': has_scripts,
            'has_iframes': has_iframes,
            'has_external_images': has_external_images,
            'has_obfuscated_content': has_obfuscated_content,
            'body_language': language,
            'body_charset': charset
        }
    
    def _html_to_text(self, html_content: str) -> str:
        """Convert HTML to plain text"""
        try:
            soup = BeautifulSoup(html_content, 'html.parser')
            return soup.get_text(separator='\n', strip=True)
        except Exception:
            return html_content
    
    def _sanitize_html(self, html_content: str) -> str:
        """Sanitize HTML by removing scripts and dangerous content"""
        try:
            soup = BeautifulSoup(html_content, 'html.parser')
            
            # Remove dangerous tags
            for tag in soup.find_all(['script', 'iframe', 'object', 'embed']):
                tag.decompose()
            
            # Remove event handlers
            for tag in soup.find_all(True):
                for attr in list(tag.attrs.keys()):
                    if attr.startswith('on'):
                        del tag[attr]
            
            return str(soup)
        except Exception:
            return html.escape(html_content)
    
    def _extract_attachments(self) -> List[Dict]:
        """Extract and analyze attachments"""
        attachments = []
        
        if not self.email_message.is_multipart():
            return attachments
        
        for part in self.email_message.iter_attachments():
            filename = part.get_filename() or 'unnamed_attachment'
            content_type = part.get_content_type()
            
            attachment_info = {
                'filename': filename,
                'content_type': content_type,
                'size': 0,
                'md5': None,
                'sha1': None,
                'sha256': None,
                'mime_type_detected': content_type,
                'extension': os.path.splitext(filename)[1].lower(),
                'is_archive': False,
                'is_password_protected': False,
                'has_macros': False,
                'is_executable': False,
                'extraction_notes': [],
                'safe_preview_available': False
            }
            
            try:
                payload = part.get_payload(decode=True)
                if payload:
                    attachment_info['size'] = len(payload)
                    attachment_info['md5'] = hashlib.md5(payload).hexdigest()
                    attachment_info['sha1'] = hashlib.sha1(payload).hexdigest()
                    attachment_info['sha256'] = (
                        hashlib.sha256(payload).hexdigest()
                    )
                    
                    # Detect file types
                    ext = attachment_info['extension']
                    
                    # Archive detection
                    if ext in ['.zip', '.rar', '.7z', '.tar', '.gz']:
                        attachment_info['is_archive'] = True
                    
                    # Executable detection
                    if ext in ['.exe', '.dll', '.bat', '.cmd', '.ps1', '.sh']:
                        attachment_info['is_executable'] = True
                    
                    # Office doc with potential macros
                    if ext in ['.doc', '.docm', '.xls', '.xlsm', '.ppt', '.pptm']:
                        attachment_info['has_macros'] = True
                    
                    # Safe preview for text/images
                    if content_type.startswith('text/') or \
                       content_type.startswith('image/'):
                        attachment_info['safe_preview_available'] = True
                        
            except Exception as e:
                attachment_info['extraction_notes'].append(
                    f"Extraction error: {str(e)}"
                )
            
            attachments.append(attachment_info)
        
        return attachments
    
    def _extract_iocs(self, body: Dict) -> Dict:
        """Extract Indicators of Compromise (IOCs)"""
        text = body.get('body_text', '') or ''
        html = body.get('body_html_raw', '') or ''
        combined = text + '\n' + html
        
        # Extract URLs
        url_pattern = r'https?://[^\s<>"\'{}|\\^`\[\]]+|www\.[^\s<>"\'{}|\\^`\[\]]+'
        urls = list(set(re.findall(url_pattern, combined, re.IGNORECASE)))
        
        # Extract domains
        domains = []
        primary_domain = None
        for url in urls:
            parsed = urlparse(url if url.startswith('http') else f'http://{url}')
            if parsed.netloc:
                domains.append(parsed.netloc)
        
        domains = list(set(domains))
        if domains:
            primary_domain = domains[0]
        
        # Extract IPs
        ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
        ips = list(set(re.findall(ip_pattern, combined)))
        
        # Extract email addresses
        email_pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
        emails = list(set(re.findall(email_pattern, combined)))
        
        # Extract hashes (MD5, SHA1, SHA256)
        hash_pattern = r'\b[a-fA-F0-9]{32}\b|\b[a-fA-F0-9]{40}\b|\b[a-fA-F0-9]{64}\b'
        hashes = list(set(re.findall(hash_pattern, combined)))
        
        # Analyze URL suspiciousness
        suspicious_urls = []
        for url in urls:
            if self._is_suspicious_url(url):
                suspicious_urls.append(url)
        
        # Detect homograph/lookalike domains
        homograph_suspected = False
        for domain in domains:
            if self._has_unicode_tricks(domain):
                homograph_suspected = True
                break
        
        return {
            'urls': urls,
            'urls_count': len(urls),
            'urls_suspicious': suspicious_urls,
            'domains': domains,
            'primary_domain': primary_domain,
            'domain_variants': [],  # Advanced feature
            'homograph_suspected': homograph_suspected,
            'ips': ips,
            'geoip_data': None,  # Requires external service
            'emails_extracted': emails,
            'hashes_extracted': hashes
        }
    
    def _is_suspicious_url(self, url: str) -> bool:
        """Check if URL has suspicious characteristics"""
        suspicious_patterns = [
            r'bit\.ly',
            r'tinyurl',
            r'@',  # URL with @ symbol
            r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}',  # IP address
            r'-login',
            r'-secure',
            r'verify',
            r'update.*account',
        ]
        
        for pattern in suspicious_patterns:
            if re.search(pattern, url, re.IGNORECASE):
                return True
        
        return False
    
    def _has_unicode_tricks(self, domain: str) -> bool:
        """Detect Unicode homograph attacks"""
        # Check for mixed scripts or lookalike characters
        suspicious_chars = ['а', 'е', 'о', 'р', 'с', 'х', 'у']  # Cyrillic
        for char in suspicious_chars:
            if char in domain:
                return True
        return False
    
    def _detect_phishing_indicators(
        self, headers: Dict, body: Dict, iocs: Dict
    ) -> Dict:
        """Detect phishing indicators"""
        
        indicators = {
            'display_name_spoofed': False,
            'reply_to_mismatch': False,
            'domain_lookalike': False,
            'brand_impersonation_detected': [],
            'suspicious_keywords': [],
            'header_anomalies': [],
            'sender_domain_age': None,  # Requires external service
            'identity_risk_score': 0.0
        }
        
        # Check display name spoofing
        from_name = headers.get('from_display_name', '')
        from_email = headers.get('from_email', '')
        
        if from_name and from_email:
            # Check if display name contains different email
            email_in_name = re.search(
                r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}',
                from_name
            )
            if email_in_name and email_in_name.group(0) != from_email:
                indicators['display_name_spoofed'] = True
                indicators['identity_risk_score'] += 0.3
        
        # Check Reply-To mismatch
        reply_to = headers.get('reply_to')
        if reply_to and from_email and reply_to != from_email:
            indicators['reply_to_mismatch'] = True
            indicators['identity_risk_score'] += 0.2
        
        # Check brand impersonation
        brands = ['paypal', 'amazon', 'microsoft', 'apple', 'google', 'bank']
        subject = (headers.get('subject') or '').lower()
        body_text = (body.get('body_text') or '').lower()
        
        for brand in brands:
            if brand in subject or brand in body_text:
                if from_email and brand not in from_email.lower():
                    indicators['brand_impersonation_detected'].append(brand)
                    indicators['identity_risk_score'] += 0.25
        
        # Check suspicious keywords
        suspicious_keywords = [
            'urgent', 'verify', 'suspended', 'unusual activity',
            'confirm identity', 'click here', 'update payment',
            'account locked', 'security alert', 'immediate action'
        ]
        
        for keyword in suspicious_keywords:
            if keyword in subject or keyword in body_text:
                indicators['suspicious_keywords'].append(keyword)
                indicators['identity_risk_score'] += 0.1
        
        # Header anomalies
        if not headers.get('message_id'):
            indicators['header_anomalies'].append('Missing Message-ID')
            indicators['identity_risk_score'] += 0.1
        
        if not headers.get('date'):
            indicators['header_anomalies'].append('Missing Date header')
        
        # Cap risk score at 1.0
        indicators['identity_risk_score'] = min(
            indicators['identity_risk_score'], 1.0
        )
        
        return indicators
    
    def _detect_tracking(self, body: Dict) -> Dict:
        """Detect tracking pixels and remote images"""
        html = body.get('body_html_raw', '')
        
        tracking_pixel_detected = False
        remote_image_urls = []
        embedded_base64_count = 0
        
        if html:
            soup = BeautifulSoup(html, 'html.parser')
            
            for img in soup.find_all('img'):
                src = img.get('src', '')
                
                # Check for tracking pixels (1x1 images)
                width = img.get('width', '')
                height = img.get('height', '')
                if (width == '1' or height == '1') and src.startswith('http'):
                    tracking_pixel_detected = True
                
                # Collect remote images
                if src.startswith('http'):
                    remote_image_urls.append(src)
                elif src.startswith('data:'):
                    embedded_base64_count += 1
        
        return {
            'tracking_pixel_detected': tracking_pixel_detected,
            'remote_image_urls': remote_image_urls,
            'embedded_base64_images_count': embedded_base64_count
        }
    
    def _detect_obfuscation(self, body: Dict) -> Dict:
        """Detect obfuscation techniques"""
        text = body.get('body_text', '') or ''
        html = body.get('body_html_raw', '') or ''
        combined = text + '\n' + html
        
        # Detect Base64 blobs
        base64_pattern = r'[A-Za-z0-9+/]{50,}={0,2}'
        base64_blobs = re.findall(base64_pattern, combined)
        
        # Detect ROT13
        rot13_present = 'rot13' in combined.lower()
        
        # Detect hex-encoded strings
        hex_pattern = r'(?:\\x[0-9a-fA-F]{2}){10,}'
        hex_strings = re.findall(hex_pattern, combined)
        
        # Detect suspicious JavaScript
        js_functions = []
        if html:
            js_patterns = [
                'eval\\(',
                'unescape\\(',
                'fromCharCode\\(',
                'atob\\(',
                'btoa\\('
            ]
            for pattern in js_patterns:
                if re.search(pattern, html):
                    js_functions.append(pattern.replace('\\', ''))
        
        # Detect redirect chains
        redirect_chains = []
        if html:
            meta_refresh = re.findall(
                r'<meta[^>]+http-equiv=["\']refresh["\'][^>]*>',
                html,
                re.IGNORECASE
            )
            redirect_chains = meta_refresh
        
        # Extract JavaScript code snippets
        js_snippets = []
        if html:
            soup = BeautifulSoup(html, 'html.parser')
            for script in soup.find_all('script'):
                if script.string:
                    js_snippets.append(script.string[:200])  # Limit length
        
        return {
            'base64_blobs': base64_blobs[:10],  # Limit count
            'rot13_present': rot13_present,
            'hex_encoded_strings': hex_strings[:10],
            'suspicious_js_functions_found': js_functions,
            'javascript_code_snippets': js_snippets,
            'redirect_chains_detected': redirect_chains
        }
    
    def _build_timeline(self, headers: Dict) -> Dict:
        """Build email timeline from headers"""
        date_str = headers.get('date')
        original_date = None
        
        if date_str:
            try:
                # Parse date
                from email.utils import parsedate_to_datetime
                original_date = parsedate_to_datetime(date_str).isoformat()
            except Exception:
                original_date = date_str
        
        # Extract timestamps from Received headers
        received_parsed = headers.get('received_parsed', [])
        
        first_received = None
        last_received = None
        hop_count = len(received_parsed)
        
        if received_parsed:
            if received_parsed[0].get('timestamp'):
                first_received = received_parsed[0]['timestamp']
            if received_parsed[-1].get('timestamp'):
                last_received = received_parsed[-1]['timestamp']
        
        return {
            'original_date': original_date,
            'first_received_timestamp': first_received,
            'last_received_timestamp': last_received,
            'timezone_normalized': None,  # Could normalize to UTC
            'hop_count': hop_count,
            'routing_delay_seconds': None,  # Calculate if timestamps parseable
            'timestamp_inconsistencies': []
        }
    
    def _build_summary(
        self, iocs: Dict, attachments: List, phishing: Dict
    ) -> Dict:
        """Build case summary metrics"""
        
        risk_level = 'low'
        risk_score = phishing.get('identity_risk_score', 0.0)
        
        if risk_score >= 0.7:
            risk_level = 'high'
        elif risk_score >= 0.4:
            risk_level = 'medium'
        
        # Determine recommended actions
        recommended_actions = []
        
        if phishing.get('display_name_spoofed'):
            recommended_actions.append('Verify sender identity')
        
        if phishing.get('brand_impersonation_detected'):
            recommended_actions.append('Report phishing attempt')
        
        if iocs.get('urls_suspicious'):
            recommended_actions.append('Do not click suspicious links')
        
        if any(a.get('is_executable') for a in attachments):
            recommended_actions.append('Quarantine executable attachments')
        
        if not recommended_actions:
            recommended_actions.append('Email appears legitimate')
        
        return {
            'total_urls': iocs.get('urls_count', 0),
            'total_domains': len(iocs.get('domains', [])),
            'total_ips': len(iocs.get('ips', [])),
            'total_attachments': len(attachments),
            'total_iocs': (
                iocs.get('urls_count', 0) +
                len(iocs.get('domains', [])) +
                len(iocs.get('ips', []))
            ),
            'risk_summary': {
                'risk_level': risk_level,
                'risk_score': risk_score,
                'confidence': 'medium'
            },
            'recommended_actions': recommended_actions
        }
    
    def _build_anomalies_list(
        self, phishing: Dict, authentication: Dict
    ) -> List[Dict]:
        """Build anomalies list for frontend (legacy format)"""
        anomalies = []
        
        # Display name spoofing
        if phishing.get('display_name_spoofed'):
            anomalies.append({
                'type': 'DISPLAY_NAME_SPOOFED',
                'severity': 'high',
                'description': 'Sender display name contains different email'
            })
        
        # Reply-To mismatch
        if phishing.get('reply_to_mismatch'):
            anomalies.append({
                'type': 'REPLY_TO_MISMATCH',
                'severity': 'medium',
                'description': 'Reply-To address differs from sender'
            })
        
        # Brand impersonation
        brands = phishing.get('brand_impersonation_detected', [])
        if brands:
            anomalies.append({
                'type': 'BRAND_IMPERSONATION',
                'severity': 'high',
                'description': f'Possible impersonation: {", ".join(brands)}'
            })
        
        # Suspicious keywords
        keywords = phishing.get('suspicious_keywords', [])
        if keywords:
            anomalies.append({
                'type': 'SUSPICIOUS_KEYWORDS',
                'severity': 'medium',
                'description': f'Suspicious keywords found: {len(keywords)}'
            })
        
        # Header anomalies
        header_anomalies = phishing.get('header_anomalies', [])
        for anomaly in header_anomalies:
            anomalies.append({
                'type': 'HEADER_ANOMALY',
                'severity': 'low',
                'description': anomaly
            })
        
        # Authentication failures
        spf = authentication.get('spf', {})
        if isinstance(spf, dict) and spf.get('spf_pass_fail') == 'fail':
            anomalies.append({
                'type': 'SPF_FAILURE',
                'severity': 'high',
                'description': 'SPF validation failed'
            })
        
        dkim = authentication.get('dkim', {})
        if isinstance(dkim, dict) and dkim.get('dkim_pass_fail') == 'fail':
            anomalies.append({
                'type': 'DKIM_FAILURE',
                'severity': 'high',
                'description': 'DKIM signature validation failed'
            })
        
        return anomalies
    
    def _build_analysis_flags(
        self, phishing: Dict, attachments: List, auth: Dict
    ) -> Dict:
        """Build analysis flags"""
        
        is_phishing = phishing.get('identity_risk_score', 0) >= 0.6
        is_spoofed = phishing.get('display_name_spoofed', False)
        
        contains_suspicious = any(
            a.get('is_executable') or a.get('has_macros')
            for a in attachments
        )
        
        return {
            'is_spam': False,  # Requires ML model
            'is_phishing': is_phishing,
            'is_spoofed': is_spoofed,
            'is_multipart': self.email_message.is_multipart(),
            'contains_malware_signatures': False,  # Requires AV scan
            'contains_suspicious_attachments': contains_suspicious,
            'analysis_partial': len(self.parsing_errors) > 0,
            'authentication_passed': (
                auth.get('spf', {}).get('spf_pass_fail') == 'pass' and
                auth.get('dkim', {}).get('dkim_pass_fail') == 'pass'
            )
        }
    
    def _get_raw_headers(self) -> str:
        """Get raw headers as string"""
        headers_str = ""
        for key, value in self.email_message.items():
            headers_str += f"{key}: {value}\n"
        return headers_str
    
    def _get_header(self, name: str) -> Optional[str]:
        """Safely get header value"""
        try:
            value = self.email_message.get(name)
            return str(value) if value else None
        except Exception:
            return None
    
    def _decode_mime_words(self, value: str) -> Optional[str]:
        """Decode MIME encoded-words (from ext.py)"""
        if not value:
            return None
        parts = decode_header(value)
        out = []
        for text, enc in parts:
            try:
                if isinstance(text, bytes):
                    out.append(text.decode(enc or "utf-8", errors="ignore"))
                else:
                    out.append(text)
            except Exception:
                out.append(str(text))
        return "".join(out)
    
    def _safe_parse_date(self, date_str: str) -> Optional[str]:
        """Parse date to ISO format (from ext.py)"""
        if not date_str:
            return None
        try:
            dt = parsedate_to_datetime(date_str)
            if dt:
                return dt.astimezone(timezone.utc).isoformat()
        except Exception:
            pass
        return None
    
    def _get_all_addresses(self, header_value: str) -> List[Dict]:
        """Parse all email addresses from header (from ext.py)"""
        if not header_value:
            return []
        try:
            addrs = getaddresses([header_value])
            return [
                {
                    "display_name": self._decode_mime_words(name),
                    "address": addr
                }
                for name, addr in addrs
            ]
        except Exception:
            return []
    
    def _error_response(
        self, error_msg: str, filename: str, file_size: int
    ) -> Dict:
        """Return error response with minimal metadata"""
        return {
            'success': False,
            'error': error_msg,
            'file_metadata': {
                'file_name': filename,
                'file_size': file_size,
                'parsed_at': datetime.utcnow().isoformat() + 'Z',
                'parser_version': self.VERSION,
                'parsing_errors': self.parsing_errors
            }
        }
