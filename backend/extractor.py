# extractor.py
import os
import re
import json
import tempfile
import shutil
from pathlib import Path
from email import policy
from email.parser import BytesParser
from email.utils import parseaddr, getaddresses, parsedate_to_datetime
from email.header import decode_header
import datetime
import hashlib
import logging

try:
    from bs4 import BeautifulSoup
except Exception:
    BeautifulSoup = None

try:
    import bleach
except Exception:
    bleach = None

logging.basicConfig(level=logging.INFO)

# ---------- small helpers ----------
def now_iso():
    return datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()

def read_bytes(path):
    with open(path, "rb") as f:
        return f.read()

def compute_hashes_bytes(b: bytes):
    import hashlib
    return {
        "md5": hashlib.md5(b).hexdigest(),
        "sha1": hashlib.sha1(b).hexdigest(),
        "sha256": hashlib.sha256(b).hexdigest()
    }

def compute_hashes_file(path):
    import hashlib
    h_md5 = hashlib.md5()
    h_sha1 = hashlib.sha1()
    h_sha256 = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h_md5.update(chunk)
            h_sha1.update(chunk)
            h_sha256.update(chunk)
    return {"md5": h_md5.hexdigest(), "sha1": h_sha1.hexdigest(), "sha256": h_sha256.hexdigest()}

def decode_mime_words(value):
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

def safe_parse_date(date_str):
    if not date_str:
        return None
    try:
        dt = parsedate_to_datetime(date_str)
        if dt:
            return dt.astimezone(datetime.timezone.utc).isoformat()
    except Exception:
        return None
    return None

# ---------- IOCs ----------
URL_REGEX = re.compile(r'https?://[^\s<>"\'()]+', re.IGNORECASE)
IP_REGEX = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
EMAIL_REGEX = re.compile(r'[\w\.-]+@[\w\.-]+\.\w+')
HASH_REGEX = re.compile(r'\b[a-fA-F0-9]{32,128}\b')
DOMAIN_REGEX = re.compile(r'\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,63}\b')

def extract_iocs(text):
    if not text:
        return {"urls": [], "ips": [], "emails": [], "hashes": [], "domains": []}
    urls = list(dict.fromkeys(URL_REGEX.findall(text)))
    ips = list(dict.fromkeys(IP_REGEX.findall(text)))
    emails = list(dict.fromkeys(EMAIL_REGEX.findall(text)))
    hashes = list({m.group(0).lower() for m in HASH_REGEX.finditer(text)})
    domains = list(dict.fromkeys(DOMAIN_REGEX.findall(text)))
    return {"urls": urls, "ips": ips, "emails": emails, "hashes": hashes, "domains": domains}

# ---------- tracking pixel detection ----------
def parse_style_for_dimensions(style_str):
    if not style_str:
        return {}
    styles = {}
    for part in style_str.split(';'):
        if ':' in part:
            k, v = part.split(':', 1)
            styles[k.strip().lower()] = v.strip().lower()
    return styles

def is_tracking_image_tag(tag):
    if not tag:
        return False
    src = (tag.get("src") or "").strip()
    is_data = src.startswith("data:")
    try:
        w_attr = tag.get("width")
        h_attr = tag.get("height")
        if w_attr:
            w = int(re.sub(r'[^0-9]', '', str(w_attr))) if re.search(r'\d', str(w_attr)) else None
            if w is not None and w <= 1:
                return True
        if h_attr:
            h = int(re.sub(r'[^0-9]', '', str(h_attr))) if re.search(r'\d', str(h_attr)) else None
            if h is not None and h <= 1:
                return True
    except Exception:
        pass
    style = tag.get("style") or ""
    styles = parse_style_for_dimensions(style)
    for k in ("width", "height"):
        val = styles.get(k)
        if val and re.search(r'\b1(px)?\b', val):
            return True
    if styles.get("display") == "none" or styles.get("opacity") in ("0", "0.0"):
        return True
    if src and not is_data:
        if re.search(r'awstrack|track|pixel|tracker|beacon', src, re.I):
            return True
    return False

def detect_tracking_images(html):
    if not html:
        return {"tracking_pixel_detected": False, "remote_image_urls": [], "embedded_base64_images_count": 0}
    remote_urls = []
    embedded_count = 0
    tracking_found = False
    if BeautifulSoup:
        soup = BeautifulSoup(html, "lxml")
        imgs = soup.find_all("img")
        for img in imgs:
            src = (img.get("src") or "").strip()
            if src.startswith("data:image"):
                embedded_count += 1
            else:
                remote_urls.append(src)
            try:
                if is_tracking_image_tag(img):
                    tracking_found = True
            except Exception:
                pass
    else:
        img_tags = re.findall(r'<img[^>]+>', html, re.I)
        for tag in img_tags:
            m_src = re.search(r'src\s*=\s*["\']([^"\']+)["\']', tag, re.I)
            src = m_src.group(1) if m_src else ""
            if src.startswith("data:image"):
                embedded_count += 1
            else:
                remote_urls.append(src)
            m_style = re.search(r'style\s*=\s*["\']([^"\']+)["\']', tag, re.I)
            style = m_style.group(1) if m_style else ""
            styles = parse_style_for_dimensions(style)
            if styles.get("display") == "none" or re.search(r'1px', style) or re.search(r'pixel|track|tracker', src, re.I):
                tracking_found = True
    remote_urls = list(dict.fromkeys([u for u in remote_urls if u]))
    return {"tracking_pixel_detected": tracking_found, "remote_image_urls": remote_urls, "embedded_base64_images_count": embedded_count}

# ---------- header helpers ----------
def get_all_addresses(header_value):
    if not header_value:
        return []
    try:
        addrs = getaddresses([header_value])
        return [{"display_name": decode_mime_words(name), "address": addr} for name, addr in addrs]
    except Exception:
        return []

def parse_received_headers(raw_received_list):
    parsed = []
    for i, raw in enumerate(raw_received_list or []):
        hop = {"hop_number": i+1, "raw": raw, "from_server": None, "from_ip": None, "by_server": None, "by_ip": None, "timestamp": None}
        m_from = re.search(r'from\s+([^\s\(;]+)', raw, re.I)
        if m_from:
            hop["from_server"] = m_from.group(1)
        m_by = re.search(r'by\s+([^\s\(;]+)', raw, re.I)
        if m_by:
            hop["by_server"] = m_by.group(1)
        m_ip = re.search(r'\[?((?:\d{1,3}\.){3}\d{1,3})\]?', raw)
        if m_ip:
            hop["from_ip"] = m_ip.group(1)
        m_time = re.search(r';\s*(.+)$', raw)
        if m_time:
            hop["timestamp"] = safe_parse_date(m_time.group(1).strip())
        parsed.append(hop)
    return parsed

def parse_authentication_results(headers):
    ar = headers.get("Authentication-Results") or headers.get("Authentication-Results:")
    result = {"spf": None, "dkim": None, "dmarc": None, "raw": ar}
    if not ar:
        return result
    if "spf=" in ar:
        m = re.search(r'spf=(\w+)', ar, re.I)
        if m:
            result["spf"] = m.group(1)
    if "dkim=" in ar:
        m = re.search(r'dkim=(\w+)', ar, re.I)
        if m:
            result["dkim"] = m.group(1)
    if "dmarc=" in ar:
        m = re.search(r'dmarc=(\w+)', ar, re.I)
        if m:
            result["dmarc"] = m.group(1)
    return result

# ---------- attachment analyzer ----------
def analyze_attachment(part, save_dir=None):
    payload = None
    try:
        payload = part.get_payload(decode=True)
    except Exception:
        payload = None
    filename = part.get_filename()
    content_type = part.get_content_type()
    cte = part.get("Content-Transfer-Encoding")
    size = len(payload) if payload else 0
    hashes = None
    file_path = None
    if payload and save_dir:
        file_path = Path(save_dir) / (filename or f"attachment_{hashlib.md5(payload).hexdigest()}")
        try:
            file_path.write_bytes(payload)
            hashes = compute_hashes_file(str(file_path))
        except Exception:
            hashes = compute_hashes_bytes(payload)
    elif payload:
        hashes = compute_hashes_bytes(payload)

    is_executable = bool(filename and re.search(r'\.exe$|\.dll$|\.scr$|\.bat$|\.com$|\.msi$', filename, re.I))
    is_archive = bool(filename and re.search(r'\.zip$|\.rar$|\.7z$|\.tar$|\.gz$', filename, re.I))

    return {
        "filename": filename,
        "content_type": content_type,
        "content_transfer_encoding": cte,
        "size": size,
        "md5": (hashes or {}).get("md5") if hashes else None,
        "sha1": (hashes or {}).get("sha1") if hashes else None,
        "sha256": (hashes or {}).get("sha256") if hashes else None,
        "mime_type_detected": None,
        "extension": Path(filename).suffix if filename else None,
        "is_archive": is_archive,
        "is_password_protected": None,
        "has_macros": False,
        "yara_matches": [],
        "is_executable": is_executable,
        "extraction_notes": None,
        "safe_preview_available": not is_executable
    }

# ---------- parse a single message ----------
def parse_eml_bytes(raw_bytes, tempdir=None, message_index=None):
    msg = BytesParser(policy=policy.default).parsebytes(raw_bytes)
    headers = {}
    for k, v in msg.items():
        headers[k] = decode_mime_words(v)
    from_field = msg.get("From")
    to_field = msg.get("To")
    cc_field = msg.get("Cc")
    bcc_field = msg.get("Bcc")
    essential = {
        "from": parseaddr(from_field)[1] if from_field else None,
        "from_display_name": decode_mime_words(parseaddr(from_field)[0]) if from_field else None,
        "to": [a["address"] for a in get_all_addresses(to_field)] if to_field else [],
        "cc": [a["address"] for a in get_all_addresses(cc_field)] if cc_field else [],
        "bcc": [a["address"] for a in get_all_addresses(bcc_field)] if bcc_field else [],
        "subject": decode_mime_words(msg.get("Subject")),
        "date": msg.get("Date"),
        "message_id": msg.get("Message-ID"),
        "reply_to": msg.get("Reply-To"),
        "return_path": msg.get("Return-Path")
    }
    raw_received = msg.get_all("Received", [])
    received_parsed = parse_received_headers(raw_received)

    body_text = None
    body_html = None
    body_charset = None
    body_cte = None
    try:
        if msg.is_multipart():
            for part in msg.walk():
                ctype = part.get_content_type()
                cdisp = part.get_content_disposition()
                if cdisp == "attachment":
                    continue
                try:
                    payload = part.get_payload(decode=True)
                except Exception:
                    payload = None
                if not payload:
                    continue
                charset = part.get_content_charset()
                cte_part = part.get("Content-Transfer-Encoding")
                try:
                    decoded = payload.decode(charset or "utf-8", errors="ignore")
                except Exception:
                    decoded = payload.decode("utf-8", errors="ignore")
                if ctype == "text/plain" and body_text is None:
                    body_text = decoded
                    if charset and not body_charset:
                        body_charset = charset
                    if cte_part and not body_cte:
                        body_cte = cte_part
                if ctype == "text/html" and body_html is None:
                    body_html = decoded
                    if charset and not body_charset:
                        body_charset = charset
                    if cte_part and not body_cte:
                        body_cte = cte_part
        else:
            ctype = msg.get_content_type()
            payload = msg.get_payload(decode=True)
            cte_part = msg.get("Content-Transfer-Encoding")
            if payload:
                charset = msg.get_content_charset()
                try:
                    decoded = payload.decode(charset or "utf-8", errors="ignore")
                except Exception:
                    decoded = payload.decode("utf-8", errors="ignore")
                if ctype == "text/plain":
                    body_text = decoded
                elif ctype == "text/html":
                    body_html = decoded
                body_charset = charset
                body_cte = cte_part
    except Exception as e:
        logging.warning(f"body extraction error: {e}")

    sanitized_html = None
    if body_html:
        if bleach:
            try:
                allowed_tags = bleach.sanitizer.ALLOWED_TAGS + ["img", "span", "div", "font"]
                allowed_attrs = dict(bleach.sanitizer.ALLOWED_ATTRIBUTES)
                allowed_attrs.update({"*": ["style", "class", "id", "src", "href", "alt", "title", "width", "height"]})
                sanitized_html = bleach.clean(body_html, tags=allowed_tags, attributes=allowed_attrs, strip=True)
            except Exception:
                sanitized_html = re.sub(r'<script[\s\S]*?</script>', '', body_html, flags=re.I)
        else:
            sanitized_html = re.sub(r'<script[\s\S]*?</script>', '', body_html, flags=re.I)

    combined_text = (body_text or "") + "\n" + (body_html or "")
    iocs = extract_iocs(combined_text)
    tracking = detect_tracking_images(body_html)
    obf = {
        "base64_blobs": re.findall(r'([A-Za-z0-9+/]{40,}={0,2})', combined_text),
        "rot13_present": bool(re.search(r'rot13|ROT13', combined_text)),
        "hex_encoded_strings": re.findall(r'(?:0x)?[A-Fa-f0-9]{8,}', combined_text),
        "suspicious_js_functions_found": re.findall(r'(eval\(|unescape\(|fromCharCode\()', combined_text),
        "javascript_code_snippets": re.findall(r'<script[^>]*>([\s\S]{0,5000}?)</script>', body_html or "", re.I),
        "redirect_chains_detected": []
    }

    attachments = []
    save_dir = None
    if tempdir:
        att_dir = Path(tempdir) / "attachments"
        att_dir.mkdir(parents=True, exist_ok=True)
        save_dir = str(att_dir)
    for part in msg.walk():
        if part.get_content_disposition() == "attachment" or part.get_filename():
            att = analyze_attachment(part, save_dir=save_dir)
            attachments.append(att)

    auth = parse_authentication_results(headers)

    phishing = {"display_name_spoofed": False, "reply_to_mismatch": False, "homograph_suspected": False, "brand_impersonation": []}
    try:
        from_raw = headers.get("From")
        if from_raw:
            disp, addr = parseaddr(from_raw)
            if disp and addr and "abhibus" in (disp.lower()) and "@abhibus.com" not in addr.lower():
                phishing["display_name_spoofed"] = True
    except Exception:
        pass
    try:
        reply = headers.get("Reply-To")
        frm = headers.get("From")
        if reply and frm:
            if parseaddr(reply)[1].lower() != parseaddr(frm)[1].lower():
                phishing["reply_to_mismatch"] = True
    except Exception:
        pass

    original_date = safe_parse_date(msg.get("Date"))
    first_received = None
    last_received = None
    hop_count = len(received_parsed)
    if received_parsed:
        times = [r.get("timestamp") for r in received_parsed if r.get("timestamp")]
        if times:
            first_received = times[0]
            last_received = times[-1]

    analysis_flags = {
        "is_spam": None,
        "is_phishing": None,
        "is_spoofed": phishing["display_name_spoofed"] or phishing["reply_to_mismatch"],
        "is_multipart": msg.is_multipart(),
        "contains_malware_signatures": False,
        "contains_suspicious_attachments": any(a.get("has_macros") or a.get("is_executable") for a in attachments),
        "analysis_partial": False
    }
    summary_metrics = {
        "total_urls": len(iocs.get("urls", [])),
        "total_domains": len(iocs.get("domains", [])),
        "total_ips": len(iocs.get("ips", [])),
        "total_attachments": len(attachments),
        "total_iocs": sum(len(iocs.get(k, [])) for k in ["urls", "ips", "domains", "emails", "hashes"]),
        "risk_summary": None,
        "recommended_actions": []
    }

    parsed_message = {
        "headers_raw": headers,
        "essential_headers": essential,
        "received": raw_received,
        "received_parsed": received_parsed,
        "authentication": {**auth},
        "body": {
            "text": body_text,
            "text_length": len(body_text) if body_text else 0,
            "html_raw": body_html,
            "html_sanitized": sanitized_html,
            "charset": body_charset,
            "content_transfer_encoding": body_cte,
            "language": None
        },
        "iocs": iocs,
        "tracking": tracking,
        "obfuscation": obf,
        "attachments": attachments,
        "phishing": phishing,
        "timeline": {
            "original_date": original_date,
            "first_received_timestamp": first_received,
            "last_received_timestamp": last_received,
            "timezone_normalized": None,
            "hop_count": hop_count,
            "routing_delay_seconds": None,
            "timestamp_inconsistencies": []
        },
        "case_summary_metrics": summary_metrics,
        "analysis_flags": analysis_flags,
        "raw_full_email": raw_bytes.decode(errors="ignore")
    }

    return parsed_message

# ---------- top-level file parse ----------
def analyze_file(path: str):
    """
    Analyze the given file path (eml/msg/mbox/txt) and return a dict:
    { meta: {...}, messages: [parsed_message, ...] }
    """
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"{path} not found")

    suffix = p.suffix.lower()
    results = []
    metadata = {
        "fileName": p.name,
        "fileType": suffix.replace(".", ""),
        "fileSize": p.stat().st_size,
        "md5": None, "sha1": None, "sha256": None,
        "parsedAt": now_iso(),
        "parserVersion": "2.1-patch",
        "isMultipart": None,
        "parsingErrors": []
    }
    try:
        raw = read_bytes(str(p))
        hs = compute_hashes_bytes(raw)
        metadata.update({"md5": hs["md5"], "sha1": hs["sha1"], "sha256": hs["sha256"]})
    except Exception as e:
        metadata["parsingErrors"].append(str(e))

    if suffix in [".mbox", ".mbx"]:
        import mailbox
        try:
            mbox = mailbox.mbox(str(p))
            idx = 0
            for msg in mbox:
                idx += 1
                raw_bytes = msg.as_bytes()
                parsed = parse_eml_bytes(raw_bytes, tempdir=tempfile.mkdtemp(prefix="ex_"))
                parsed["meta"] = {"message_index": idx}
                results.append(parsed)
            metadata["mbox_count"] = idx
        except Exception as e:
            metadata["parsingErrors"].append(str(e))
    elif suffix == ".msg":
        try:
            import extract_msg
        except Exception:
            extract_msg = None
        if extract_msg:
            try:
                m = extract_msg.Message(str(p))
                body = m.body or ""
                subj = m.subject
                from_addr = m.sender
                pseudo_eml = f"From: {from_addr}\nSubject: {subj}\n\n{body}".encode("utf-8")
                parsed = parse_eml_bytes(pseudo_eml, tempdir=tempfile.mkdtemp(prefix="ex_"))
                results.append(parsed)
            except Exception as e:
                metadata["parsingErrors"].append(str(e))
        else:
            metadata["parsingErrors"].append("extract_msg not installed - .msg parsing limited")
    else:
        try:
            raw_bytes = read_bytes(str(p))
            parsed = parse_eml_bytes(raw_bytes, tempdir=tempfile.mkdtemp(prefix="ex_"))
            results.append(parsed)
            metadata["isMultipart"] = parsed.get("analysis_flags", {}).get("is_multipart")
        except Exception as e:
            metadata["parsingErrors"].append(str(e))

    out = {"meta": metadata, "messages": results, "extractedAt": now_iso(), "tool": {"name": "EnvelopeX-Extractor", "version": "2.1-patch"}}
    return out
