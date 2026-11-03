#!/usr/bin/env python3
"""
Collector v3.0 - Proxy collector with GeoIP, TCP checks and Base64 support
"""

import base64
import hashlib
import json
import os
import re
import signal
import socket
import sys
import time
import urllib.parse
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import requests

# Configure stdout for unbuffered output
sys.stdout.reconfigure(line_buffering=True)

TRUE = {'1', 'true', 'yes', 'on'}
BASE_DIR = Path(__file__).resolve().parent
OUT_DIR = BASE_DIR / os.environ.get('OUT_DIR', 'out')
OUT_DIR.mkdir(parents=True, exist_ok=True)


def env_bool(name: str, default: bool = False) -> bool:
    return os.environ.get(name, str(default)).strip().lower() in TRUE


def env_int(name: str, default: int) -> int:
    try:
        return int(os.environ.get(name, '').strip() or default)
    except Exception:
        return default


def env_set(name: str, default: str) -> set:
    val = os.environ.get(name, default)
    return {x.strip().lower() for x in val.split(',') if x.strip()}


def env_list(name: str, sep: str = ',') -> List[str]:
    val = os.environ.get(name, '').strip()
    if not val:
        return []
    return [x.strip() for x in val.split(sep) if x.strip()]


def read_lines(path: Path) -> List[str]:
    if not path.exists():
        return []
    out = []
    for line in path.read_text(encoding='utf-8', errors='ignore').splitlines():
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        out.append(line)
    return out


# =========================
# Limits
# =========================
MAX_SERVERS_TOTAL = env_int('MAX_SERVERS_TOTAL', 600)
MAX_SERVERS_PER_PROTOCOL = env_int('MAX_SERVERS_PER_PROTOCOL', 250)
MAX_WHITELIST = env_int('MAX_WHITELIST', 300)
MAX_RUSSIAN = env_int('MAX_RUSSIAN', 250)
MAX_DUPLICATE_IP = env_int('MAX_DUPLICATE_IP', 2)
MAX_DUPLICATE_IP_WHITELIST = env_int('MAX_DUPLICATE_IP_WHITELIST', 3)

US_CA_QUOTA_PERCENT = env_int('US_CA_QUOTA_PERCENT', 30)

# =========================
# Parameters
# =========================
MAX_LATENCY_MS = env_int('MAX_LATENCY_MS', 1500)
TCP_TIMEOUT = float(os.environ.get('TCP_TIMEOUT', '2.5'))
TCP_WORKERS = env_int('TCP_WORKERS', 25)
GEO_WORKERS = env_int('GEO_WORKERS', 15)
TCP_MAX_CANDIDATES = env_int('TCP_MAX_CANDIDATES', 1500)

CHECK_TCP = env_bool('CHECK_TCP', True)
CHECK_CORES = env_bool('CHECK_CORES', False)
ENABLE_GEO = env_bool('ENABLE_GEO', True)
ENABLE_GITHUB_SEARCH = env_bool('ENABLE_GITHUB_SEARCH', False)

# =========================
# Filters
# =========================
ALLOWED_PROTOCOLS = env_set('ALLOWED_PROTOCOLS', 'vless,vmess,trojan,hysteria2,shadowsocks')
COMMON_FILE_PROTOCOLS = env_set('COMMON_FILE_PROTOCOLS', 'vless,vmess,trojan,hysteria2')
BLOCKED_PROTOCOLS = env_set('BLOCKED_PROTOCOLS', 'tuic,wireguard,socks,socks5,http,https')
BLOCKED_NETWORKS = env_set('BLOCKED_NETWORKS', 'quic')
REQUIRE_ENCRYPTED = env_bool('REQUIRE_ENCRYPTED', True)
ALLOW_PLAIN_VMESS = env_bool('ALLOW_PLAIN_VMESS', False)
ALLOW_UNKNOWN_COUNTRY = env_bool('ALLOW_UNKNOWN_COUNTRY', True)

# =========================
# Sources
# =========================
SEARCH_QUERIES = read_lines(BASE_DIR / 'sources' / 'search_queries.txt') or [
    '"vless://"', '"vmess://"', '"trojan://"', '"ss://"', '"hysteria2://"'
]

GITHUB_REPOS = read_lines(BASE_DIR / 'sources' / 'github_repos.txt') + env_list('GITHUB_REPOS')
RAW_URLS = read_lines(BASE_DIR / 'sources' / 'raw_urls.txt') + env_list('RAW_URLS')

DEFAULT_RU_SNI = ['vk.com', 'yandex.ru', 'ya.ru', 'ozon.ru', 'wildberries.ru', 'mail.ru', 'gosuslugi.ru', 'avito.ru']
RU_SNI = read_lines(BASE_DIR / 'allowlists' / 'ru_sni.txt') or DEFAULT_RU_SNI

GITHUB_TOKEN = os.environ.get('GITHUB_TOKEN', '').strip()
SESSION = requests.Session()
SESSION.headers.update({'User-Agent': 'proxy-collector/3.0', 'Accept': 'application/vnd.github+json'})
if GITHUB_TOKEN:
    SESSION.headers['Authorization'] = f'Bearer {GITHUB_TOKEN}'


# =========================
# Parsing helpers
# =========================
def parse_qs(query: str) -> Dict[str, List[str]]:
    return urllib.parse.parse_qs(query, keep_blank_values=True)


def q_get(qs: Dict[str, List[str]], key: str, default: Optional[str] = None) -> Optional[str]:
    vals = qs.get(key)
    return vals[0] if vals else default


def split_host_port(value: str, default_port: int) -> Tuple[str, int]:
    value = value.strip()
    if not value:
        return '', default_port

    if value.startswith('['):
        host, _, rest = value.partition(']')
        host = host[1:]
        port = default_port
        if rest.startswith(':') and rest[1:].isdigit():
            port = int(rest[1:])
        return host, port

    if value.count(':') > 1:
        return value, default_port

    host, _, port_s = value.partition(':')
    if port_s.isdigit():
        return host, int(port_s)

    return host, default_port


def b64decode_any(value: str) -> str:
    value = value.strip()
    if not value:
        return ''
    value = value.replace('-', '+').replace('_', '/')
    value += '=' * (-len(value) % 4)
    try:
        return base64.b64decode(value).decode('utf-8', errors='ignore')
    except Exception:
        return ''


# =========================
# Parsers
# =========================
def parse_vless(url: str) -> Optional[Dict[str, Any]]:
    parts = urllib.parse.urlsplit(url)
    if parts.scheme.lower() != 'vless' or '@' not in parts.netloc:
        return None

    uuid, hostport = parts.netloc.rsplit('@', 1)
    host, port = split_host_port(hostport, 443)
    if not host:
        return None

    qs = parse_qs(parts.query)
    security = q_get(qs, 'security', 'none') or 'none'
    sni = q_get(qs, 'sni') or q_get(qs, 'serverName')
    network = q_get(qs, 'type', 'tcp') or 'tcp'

    return {
        'protocol': 'vless',
        'address': host,
        'port': port,
        'uuid': uuid,
        'security': security.lower(),
        'network': network.lower(),
        'sni': sni,
        'host': q_get(qs, 'host'),
        'path': q_get(qs, 'path'),
        'flow': q_get(qs, 'flow'),
        'pbk': q_get(qs, 'pbk') or q_get(qs, 'publicKey'),
        'sid': q_get(qs, 'sid') or q_get(qs, 'shortId'),
        'fp': q_get(qs, 'fp'),
        'name_original': urllib.parse.unquote(parts.fragment),
        'raw': url,
    }


def parse_vmess(url: str) -> Optional[Dict[str, Any]]:
    if not url.lower().startswith('vmess://'):
        return None

    b64 = url[len('vmess://'):].strip()
    try:
        decoded = b64decode_any(b64)
        data = json.loads(decoded)
    except Exception:
        return None

    host = data.get('add')
    if not host:
        return None

    try:
        port = int(data.get('port', 443))
    except Exception:
        port = 443

    security = 'tls' if str(data.get('tls', '')).lower() == 'tls' else 'none'
    network = str(data.get('net', 'tcp')).lower()

    return {
        'protocol': 'vmess',
        'address': host,
        'port': port,
        'uuid': data.get('id'),
        'aid': str(data.get('aid', '0')),
        'method': data.get('scy') or data.get('security') or 'auto',
        'security': security,
        'network': network,
        'sni': data.get('sni') or data.get('host'),
        'host': data.get('host'),
        'path': data.get('path'),
        'name_original': data.get('ps'),
        'raw': url,
        'vmess': data,
    }


def parse_trojan(url: str) -> Optional[Dict[str, Any]]:
    parts = urllib.parse.urlsplit(url)
    if parts.scheme.lower() != 'trojan' or '@' not in parts.netloc:
        return None

    password, hostport = parts.netloc.rsplit('@', 1)
    host, port = split_host_port(hostport, 443)
    if not host:
        return None

    qs = parse_qs(parts.query)
    security = q_get(qs, 'security', 'tls') or 'tls'
    sni = q_get(qs, 'sni')
    network = q_get(qs, 'type', 'tcp') or 'tcp'

    return {
        'protocol': 'trojan',
        'address': host,
        'port': port,
        'password': password,
        'security': security.lower(),
        'network': network.lower(),
        'sni': sni,
        'host': q_get(qs, 'host'),
        'path': q_get(qs, 'path'),
        'name_original': urllib.parse.unquote(parts.fragment),
        'raw': url,
    }


def parse_ss(url: str) -> Optional[Dict[str, Any]]:
    if not url.lower().startswith('ss://'):
        return None

    full = url[len('ss://'):]
    frag_raw = ''
    query_raw = ''

    if '#' in full:
        full, frag_raw = full.split('#', 1)

    if '?' in full:
        full, query_raw = full.split('?', 1)

    frag = urllib.parse.unquote(frag_raw)
    qs = parse_qs(query_raw)

    userinfo = ''
    hostport = ''

    if '@' in full:
        userinfo, hostport = full.rsplit('@', 1)
        if '%' in userinfo:
            userinfo = urllib.parse.unquote(userinfo)
        if ':' not in userinfo:
            try:
                userinfo = b64decode_any(userinfo)
            except Exception:
                return None
    else:
        try:
            decoded = b64decode_any(full)
        except Exception:
            return None
        if '@' not in decoded:
            return None
        userinfo, hostport = decoded.rsplit('@', 1)

    if ':' not in userinfo:
        return None

    method, password = userinfo.split(':', 1)
    host, port = split_host_port(hostport, 8388)
    if not host:
        return None

    return {
        'protocol': 'shadowsocks',
        'address': host,
        'port': port,
        'method': method,
        'password': password,
        'security': 'ss',
        'network': 'tcp',
        'sni': None,
        'host': None,
        'path': None,
        'plugin': q_get(qs, 'plugin'),
        'name_original': frag,
        'raw': url,
    }


def parse_hysteria2(url: str) -> Optional[Dict[str, Any]]:
    parts = urllib.parse.urlsplit(url)
    if parts.scheme.lower() not in ('hysteria2', 'hy2') or '@' not in parts.netloc:
        return None

    password, hostport = parts.netloc.rsplit('@', 1)
    host, port = split_host_port(hostport, 443)
    if not host:
        return None

    qs = parse_qs(parts.query)
    sni = q_get(qs, 'sni')

    return {
        'protocol': 'hysteria2',
        'address': host,
        'port': port,
        'password': password,
        'security': 'tls',
        'network': 'udp',
        'sni': sni,
        'host': q_get(qs, 'host'),
        'path': None,
        'name_original': urllib.parse.unquote(parts.fragment),
        'raw': url,
    }


def parse_proxy_url(url: str) -> Optional[Dict[str, Any]]:
    try:
        scheme = urllib.parse.urlsplit(url).scheme.lower()
    except Exception:
        return None

    if scheme in BLOCKED_PROTOCOLS:
        return None

    try:
        if scheme == 'vless':
            s = parse_vless(url)
        elif scheme == 'vmess':
            s = parse_vmess(url)
        elif scheme == 'trojan':
            s = parse_trojan(url)
        elif scheme == 'ss':
            s = parse_ss(url)
        elif scheme in ('hysteria2', 'hy2'):
            s = parse_hysteria2(url)
        else:
            return None
    except Exception:
        return None

    if not s or not s.get('address') or not s.get('port'):
        return None

    if s['protocol'] not in ALLOWED_PROTOCOLS:
        return None

    return s


# =========================
# Deduplication
# =========================
def make_fingerprint(s: Dict[str, Any]) -> str:
    identity = ''
    if s['protocol'] in ('vless', 'vmess'):
        identity = s.get('uuid') or ''
    elif s['protocol'] in ('trojan', 'hysteria2'):
        identity = s.get('password') or ''
    elif s['protocol'] == 'shadowsocks':
        identity = f"{s.get('method', '')}:{s.get('password', '')}"

    key = '|'.join([
        s['protocol'],
        s['address'].lower(),
        str(s['port']),
        str(identity),
        str(s.get('security', '')),
        str(s.get('network', '')),
        (s.get('sni') or '').lower(),
        str(s.get('path') or ''),
        str(s.get('flow') or ''),
        str(s.get('pbk') or ''),
    ])

    return hashlib.sha1(key.encode('utf-8')).hexdigest()


# =========================
# Filters
# =========================
def is_ru_reality(s: Dict[str, Any]) -> bool:
    if s.get('protocol') != 'vless' or s.get('security') != 'reality':
        return False

    sni = (s.get('sni') or s.get('host') or '').lower()
    if not sni:
        return False

    for domain in RU_SNI:
        d = domain.lower().strip()
        if not d:
            continue
        if sni == d or sni.endswith('.' + d):
            return True

    return False


def passes_filters(s: Dict[str, Any]) -> bool:
    if s['protocol'] not in ALLOWED_PROTOCOLS:
        return False

    if (s.get('network') or '').lower() in BLOCKED_NETWORKS:
        return False

    if REQUIRE_ENCRYPTED:
        if s['protocol'] in ('vless', 'trojan') and s.get('security') not in ('tls', 'reality'):
            return False
        if s['protocol'] == 'vmess' and not ALLOW_PLAIN_VMESS and s.get('security') != 'tls':
            return False

    country = (s.get('country') or 'UN').upper()
    if not ALLOW_UNKNOWN_COUNTRY and country == 'UN':
        return False

    return True


# =========================
# TCP checks
# =========================
def tcp_latency(s: Dict[str, Any]) -> Optional[int]:
    try:
        start = time.perf_counter()
        with socket.create_connection((s['address'], s['port']), timeout=TCP_TIMEOUT):
            pass
        return int((time.perf_counter() - start) * 1000)
    except Exception:
        return None


def run_tcp_checks(servers: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    if not CHECK_TCP:
        return servers

    checked = []
    total = len(servers)
    done = 0

    def timeout_handler(signum, frame):
        raise TimeoutError("TCP check timeout")

    old_handler = signal.signal(signal.SIGALRM, timeout_handler)
    signal.alarm(900)  # 15 minutes max

    try:
        with ThreadPoolExecutor(max_workers=TCP_WORKERS) as ex:
            futures = {ex.submit(tcp_latency, s): s for s in servers}
            for f in as_completed(futures):
                s = futures[f]
                lat = f.result()
                done += 1

                if done % 100 == 0:
                    print(f'[TCP] Progress: {done}/{total} ({done * 100 // total}%)', flush=True)

                if lat is None:
                    continue

                if lat <= MAX_LATENCY_MS:
                    s['latency_ms'] = lat
                    checked.append(s)
    except TimeoutError:
        print(f'[TCP] Timeout reached after {done}/{total} checks', flush=True)
    finally:
        signal.alarm(0)
        signal.signal(signal.SIGALRM, old_handler)

    return checked


# =========================
# Sorting
# =========================
PROTOCOL_PRIORITY = {
    'vless': 0,
    'trojan': 1,
    'vmess': 2,
    'hysteria2': 3,
    'shadowsocks': 4,
}


def pre_sort_key(s: Dict[str, Any]):
    proto = PROTOCOL_PRIORITY.get(s['protocol'], 9)

    sec = s.get('security')
    if sec == 'reality':
        sec_rank = 0
    elif sec == 'tls':
        sec_rank = 1
    elif s['protocol'] == 'shadowsocks':
        sec_rank = 2
    else:
        sec_rank = 3

    ru_rank = 0 if is_ru_reality(s) else 1
    lat = s.get('latency_ms') or 999999

    return (proto, sec_rank, ru_rank, lat, s['address'].lower(), s['port'])


def final_sort_key(s: Dict[str, Any]):
    lat = s.get('latency_ms') or 999999
    speed = s.get('speed_kbps') or 0
    return (lat, -speed, *pre_sort_key(s))


# =========================
# Limits
# =========================
def apply_limits(servers: List[Dict[str, Any]], max_total: int, max_per_protocol: int,
                 us_ca_quota_percent: int, max_duplicate_ip: int) -> List[Dict[str, Any]]:
    """Apply limits: total, per protocol, per IP, US/CA quota"""

    # Filter by duplicate IP count
    ip_count = {}
    filtered = []
    for s in servers:
        ip = s.get('ip') or s['address']
        ip_count[ip] = ip_count.get(ip, 0) + 1
        if ip_count[ip] <= max_duplicate_ip:
            filtered.append(s)

    servers = filtered

    # Sort
    servers.sort(key=final_sort_key)

    # Split US/CA and others
    us_ca_servers = [s for s in servers if (s.get('country') or '').upper() in ('US', 'CA')]
    other_servers = [s for s in servers if (s.get('country') or '').upper() not in ('US', 'CA')]

    us_ca_limit = int(max_total * us_ca_quota_percent / 100)
    other_limit = max_total - us_ca_limit

    us_ca_selected = us_ca_servers[:us_ca_limit]
    other_selected = other_servers[:other_limit]

    selected = us_ca_selected + other_selected

    # Protocol limit
    protocol_count = {}
    final_selected = []

    for s in selected:
        proto = s['protocol']
        if protocol_count.get(proto, 0) < max_per_protocol:
            final_selected.append(s)
            protocol_count[proto] = protocol_count.get(proto, 0) + 1

    return final_selected[:max_total]


# =========================
# Naming
# =========================
def build_name(s: Dict[str, Any]) -> str:
    """Build name: 🇱🇹 Lithuania, Šiauliai"""
    country_code = (s.get('country') or 'UN').upper()
    country_name = s.get('country_name') or country_code
    city = s.get('city') or ''

    flag = get_flag(country_code)

    if country_name and country_name != 'UN':
        name = f"{flag} {country_name}"
    else:
        name = f"{flag} {country_code}"

    if city:
        name += f", {city}"

    return name


def rename_link(s: Dict[str, Any], name: str) -> str:
    url = s.get('raw', '')

    if s['protocol'] == 'vmess':
        data = s.get('vmess')
        if isinstance(data, dict):
            data = data.copy()
            data['ps'] = name
            try:
                payload = json.dumps(data, separators=(',', ':'), ensure_ascii=False).encode('utf-8')
                return 'vmess://' + base64.b64encode(payload).decode()
            except Exception:
                return url
        return url

    try:
        parts = urllib.parse.urlsplit(url)
        return urllib.parse.urlunsplit((
            parts.scheme,
            parts.netloc,
            parts.path,
            parts.query,
            urllib.parse.quote(name, safe=''),
        ))
    except Exception:
        return url


# =========================
# Sing-box conversion
# =========================
def to_singbox_outbound(s: Dict[str, Any], tag: str) -> Optional[Dict[str, Any]]:
    out = {
        'tag': tag,
        'server': s['address'],
        'server_port': s['port'],
    }

    proto = s['protocol']

    if proto == 'vless':
        out['type'] = 'vless'
        out['uuid'] = s.get('uuid')
        if s.get('flow'):
            out['flow'] = s['flow']

        if s.get('security') in ('tls', 'reality'):
            tls = {'enabled': True, 'server_name': s.get('sni') or s.get('host') or s.get('address')}
            if s.get('security') == 'reality':
                tls['reality'] = {'enabled': True}
                if s.get('pbk'):
                    tls['reality']['public_key'] = s['pbk']
                if s.get('sid'):
                    tls['reality']['short_id'] = s['sid']
                if s.get('fp'):
                    tls['utls'] = {'enabled': True, 'fingerprint': s['fp']}
            else:
                tls['insecure'] = True
            out['tls'] = tls

        net = s.get('network')
        if net == 'ws':
            out['transport'] = {'type': 'ws', 'path': s.get('path')}
            if s.get('host'):
                out['transport']['headers'] = {'Host': s['host']}
        elif net == 'grpc':
            out['transport'] = {'type': 'grpc', 'service_name': s.get('path')}
        elif net in ('h2', 'http'):
            out['transport'] = {'type': 'http', 'path': s.get('path')}
            if s.get('host'):
                out['transport']['host'] = [s['host']]

        return out

    elif proto == 'vmess':
        out['type'] = 'vmess'
        out['uuid'] = s.get('uuid')
        out['security'] = s.get('method') or 'auto'
        try:
            out['alter_id'] = int(s.get('aid') or 0)
        except Exception:
            out['alter_id'] = 0

        if s.get('security') == 'tls':
            out['tls'] = {
                'enabled': True,
                'server_name': s.get('sni') or s.get('host') or s.get('address'),
                'insecure': True
            }

        net = s.get('network')
        if net == 'ws':
            out['transport'] = {'type': 'ws', 'path': s.get('path')}
            if s.get('host'):
                out['transport']['headers'] = {'Host': s['host']}
        elif net == 'grpc':
            out['transport'] = {'type': 'grpc', 'service_name': s.get('path')}
        elif net in ('h2', 'http'):
            out['transport'] = {'type': 'http', 'path': s.get('path')}
            if s.get('host'):
                out['transport']['host'] = [s['host']]

        return out

    elif proto == 'trojan':
        out['type'] = 'trojan'
        out['password'] = s.get('password')
        out['tls'] = {
            'enabled': True,
            'server_name': s.get('sni') or s.get('host') or s.get('address'),
            'insecure': True
        }

        net = s.get('network')
        if net == 'ws':
            out['transport'] = {'type': 'ws', 'path': s.get('path')}
            if s.get('host'):
                out['transport']['headers'] = {'Host': s['host']}
        elif net == 'grpc':
            out['transport'] = {'type': 'grpc', 'service_name': s.get('path')}
        elif net in ('h2', 'http'):
            out['transport'] = {'type': 'http', 'path': s.get('path')}
            if s.get('host'):
                out['transport']['host'] = [s['host']]

        return out

    elif proto == 'shadowsocks':
        out['type'] = 'shadowsocks'
        out['method'] = s.get('method')
        out['password'] = s.get('password')
        return out

    elif proto == 'hysteria2':
        out['type'] = 'hysteria2'
        out['password'] = s.get('password')
        out['tls'] = {
            'enabled': True,
            'server_name': s.get('sni') or s.get('host') or s.get('address'),
            'insecure': True
        }
        return out

    return None


# =========================
# Output
# =========================
def write_outputs(servers: List[Dict[str, Any]]) -> None:
    now = datetime.now(timezone.utc).isoformat()

    by_protocol = {}
    common_servers = []
    whitelist_servers = []
    russian_servers = []

    for s in servers:
        proto = s['protocol']

        if proto in COMMON_FILE_PROTOCOLS:
            common_servers.append(s)

        if proto not in by_protocol:
            by_protocol[proto] = []
        by_protocol[proto].append(s)

        if is_ru_reality(s):
            whitelist_servers.append(s)

        if (s.get('country') or '').upper() == 'RU':
            russian_servers.append(s)

    # Apply limits
    common_servers = apply_limits(common_servers, MAX_SERVERS_TOTAL, MAX_SERVERS_PER_PROTOCOL,
                                  US_CA_QUOTA_PERCENT, MAX_DUPLICATE_IP)

    for proto in list(by_protocol.keys()):
        by_protocol[proto] = apply_limits(by_protocol[proto], MAX_SERVERS_TOTAL, MAX_SERVERS_PER_PROTOCOL,
                                          US_CA_QUOTA_PERCENT, MAX_DUPLICATE_IP)

    whitelist_servers = apply_limits(whitelist_servers, MAX_WHITELIST, MAX_WHITELIST,
                                     100, MAX_DUPLICATE_IP_WHITELIST)

    russian_servers = russian_servers[:MAX_RUSSIAN]

    # Create names
    all_named = set()
    for s in common_servers + whitelist_servers + russian_servers:
        name = build_name(s)
        s['name'] = name
        s['named_raw'] = rename_link(s, name)
        all_named.add(id(s))

    for proto_servers in by_protocol.values():
        for s in proto_servers:
            if id(s) not in all_named:
                name = build_name(s)
                s['name'] = name
                s['named_raw'] = rename_link(s, name)
                all_named.add(id(s))

    # Common Xray file
    common_links = [s['named_raw'] for s in common_servers]
    (OUT_DIR / 'xray_links.txt').write_text('\n'.join(common_links) + '\n', encoding='utf-8')

    sub_b64 = base64.b64encode('\n'.join(common_links).encode('utf-8')).decode() if common_links else ''
    (OUT_DIR / 'v2rayng_subscription_b64.txt').write_text(sub_b64, encoding='utf-8')

    # Common sing-box file
    sing_outbounds = []
    for s in common_servers:
        ob = to_singbox_outbound(s, s['name'])
        if ob:
            sing_outbounds.append(ob)
    (OUT_DIR / 'singbox_outbounds.json').write_text(
        json.dumps({'outbounds': sing_outbounds}, indent=2, ensure_ascii=False), encoding='utf-8'
    )

    # Protocol files
    for proto, proto_servers in by_protocol.items():
        proto_links = [s['named_raw'] for s in proto_servers]
        (OUT_DIR / f'{proto}_xray.txt').write_text('\n'.join(proto_links) + '\n', encoding='utf-8')

        proto_outbounds = []
        for s in proto_servers:
            ob = to_singbox_outbound(s, s['name'])
            if ob:
                proto_outbounds.append(ob)
        (OUT_DIR / f'{proto}_singbox.json').write_text(
            json.dumps({'outbounds': proto_outbounds}, indent=2, ensure_ascii=False), encoding='utf-8'
        )

    # Whitelist
    whitelist_links = [s['named_raw'] for s in whitelist_servers]
    (OUT_DIR / 'whitelist_vless_reality_ru.txt').write_text('\n'.join(whitelist_links) + '\n', encoding='utf-8')

    # Russian servers
    russian_links = [s['named_raw'] for s in russian_servers]
    (OUT_DIR / 'russian_servers.txt').write_text('\n'.join(russian_links) + '\n', encoding='utf-8')

    # Metadata
    meta = []
    for s in servers:
        meta.append({
            'name': s.get('name'),
            'protocol': s.get('protocol'),
            'address': s.get('address'),
            'port': s.get('port'),
            'security': s.get('security'),
            'network': s.get('network'),
            'country': s.get('country'),
            'country_name': s.get('country_name'),
            'city': s.get('city'),
            'latency_ms': s.get('latency_ms'),
            'speed_kbps': s.get('speed_kbps'),
            'sni': s.get('sni'),
            'flow': s.get('flow'),
        })
    (OUT_DIR / 'servers_metadata.json').write_text(
        json.dumps(meta, indent=2, ensure_ascii=False), encoding='utf-8'
    )

    # Summary
    by_proto = {}
    by_country = {}

    for s in servers:
        p = s.get('protocol', 'unknown')
        c = s.get('country', 'UN')
        by_proto[p] = by_proto.get(p, 0) + 1
        by_country[c] = by_country.get(c, 0) + 1

    summary = {
        'generated_at': now,
        'total_selected': len(servers),
        'common_servers': len(common_servers),
        'whitelist_count': len(whitelist_servers),
        'russian_count': len(russian_servers),
        'by_protocol': by_proto,
        'by_country': by_country,
        'max_servers_total': MAX_SERVERS_TOTAL,
        'us_ca_quota_percent': US_CA_QUOTA_PERCENT,
    }

    (OUT_DIR / 'summary.json').write_text(
        json.dumps(summary, indent=2, ensure_ascii=False), encoding='utf-8'
    )

    print(f'[OK] Common servers: {len(common_links)}', flush=True)
    print(f'[OK] Whitelist servers: {len(whitelist_links)}', flush=True)
    print(f'[OK] Russian servers: {len(russian_links)}', flush=True)
    for proto, proto_servers in by_protocol.items():
        print(f'[OK] {proto} servers: {len(proto_servers)}', flush=True)


# =========================
# Source collection
# =========================
def http_get_text(url: str, timeout: int = 30) -> str:
    # Handle Telegram channels via jina.ai
    if 't.me/' in url and not url.startswith('https://r.jina.ai/'):
        clean_name = url.split('t.me/')[-1].strip('/')
        if clean_name.startswith('@'):
            clean_name = clean_name[1:]
        url = f"https://r.jina.ai/https://t.me/s/{clean_name}"

    try:
        r = SESSION.get(url, timeout=timeout)
        if r.status_code == 200:
            if len(r.content) > 10_000_000:  # 10 MB limit
                return ''
            return r.text
    except Exception:
        pass
    return ''


def http_get_json(url: str, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    try:
        r = SESSION.get(url, params=params, timeout=25)
        if r.status_code == 200:
            return r.json()
    except Exception:
        pass
    return {}


def github_html_to_raw(html_url: str) -> Optional[str]:
    if not html_url or 'github.com' not in html_url:
        return None
    return html_url.replace('https://github.com/', 'https://raw.githubusercontent.com/').replace('/blob/', '/')


def path_looks_useful(path: str) -> bool:
    p = path.lower()
    allowed_ext = {'.txt', '.md', '.json', '.yaml', '.yml', '.csv', '.conf', '.ini', '.list', '.log'}
    if any(p.endswith(ext) for ext in allowed_ext):
        return True
    keywords = ('proxy', 'sub', 'subscription', 'vless', 'vmess', 'trojan', 'shadowsocks', 'ss',
                'reality', 'node', 'nodes', 'server', 'servers', 'v2ray', 'xray', 'singbox', 'karing', 'hysteria')
    return any(k in p for k in keywords)


def github_code_search_texts() -> List[str]:
    texts = []
    if not SEARCH_QUERIES:
        return texts

    per_page = env_int('SEARCH_PER_PAGE', 30)
    pages = env_int('SEARCH_PAGES', 2)
    items_per_query = env_int('SEARCH_ITEMS_PER_QUERY', 60)

    if not GITHUB_TOKEN:
        print('[WARN] GITHUB_TOKEN is not set', flush=True)

    for q in SEARCH_QUERIES:
        q_final = q if 'in:' in q else f'{q} in:file'
        fetched = 0

        for page in range(1, pages + 1):
            data = http_get_json('https://api.github.com/search/code', {'q': q_final, 'per_page': per_page, 'page': page})
            items = data.get('items', [])
            if not items:
                break

            for item in items:
                if fetched >= items_per_query:
                    break

                raw_url = github_html_to_raw(item.get('html_url'))
                if raw_url:
                    txt = http_get_text(raw_url)
                    if txt:
                        texts.append(txt)
                    fetched += 1
                    time.sleep(1.0)

            if fetched >= items_per_query:
                break

    return texts


def github_repo_texts() -> List[str]:
    texts = []
    max_files_per_repo = env_int('MAX_FILES_PER_REPO', 200)

    for item in GITHUB_REPOS:
        try:
            repo = item.strip().strip('/')
            branch = None
            if '@' in repo:
                repo, branch = repo.split('@', 1)

            info = http_get_json(f'https://api.github.com/repos/{repo}')
            if not info or 'default_branch' not in info:
                continue

            branch = branch or info.get('default_branch', 'main')
            tree = http_get_json(f'https://api.github.com/repos/{repo}/git/trees/{branch}?recursive=1')
            if not tree:
                continue

            count = 0
            for obj in tree.get('tree', []):
                if obj.get('type') != 'blob':
                    continue

                path = obj.get('path', '')
                size = obj.get('size', 0)
                if size > 1_500_000:
                    continue

                if not path_looks_useful(path):
                    continue

                raw_url = f'https://raw.githubusercontent.com/{repo}/{branch}/{urllib.parse.quote(path)}'
                txt = http_get_text(raw_url)
                if txt:
                    texts.append(txt)

                count += 1
                if count >= max_files_per_repo:
                    break
                time.sleep(0.2)
        except Exception:
            continue

    return texts


def raw_url_texts() -> List[str]:
    texts = []
    for url in RAW_URLS:
        txt = http_get_text(url)
        if txt:
            texts.append(txt)
    return texts


def local_text_files() -> List[str]:
    texts = []
    d = BASE_DIR / 'sources' / 'texts'
    if not d.exists():
        return texts

    for f in sorted(d.iterdir()):
        if f.suffix.lower() in {'.txt', '.md', '.json', '.yaml', '.yml', '.csv', '.log'}:
            try:
                texts.append(f.read_text(encoding='utf-8', errors='ignore'))
            except Exception:
                pass

    return texts


LINK_RE = re.compile(r'\b(?:vless|vmess|trojan|ss|hy2|hysteria2?|tuic|wireguard)://[^\s"\'<>`]+', re.IGNORECASE)


def extract_links(text: str) -> List[str]:
    if not text:
        return []

    links = []

    # 1. Direct search for regular links
    for m in LINK_RE.finditer(text):
        url = m.group(0).strip()
        url = re.sub(r'[\)\]\}>"\'`,;]+$', '', url)
        if url:
            links.append(url)

    # 2. Search and decode Base64 blocks
    potential_b64 = re.findall(r'(?:[A-Za-z0-9+/]{4}){20,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?', text)

    for b64_str in potential_b64:
        try:
            decoded_bytes = base64.b64decode(b64_str)
            decoded_text = decoded_bytes.decode('utf-8', errors='ignore')

            for m in LINK_RE.finditer(decoded_text):
                url = m.group(0).strip()
                url = re.sub(r'[\)\]\}>"\'`,;]+$', '', url)
                if url:
                    links.append(url)
        except Exception:
            continue

    # Remove duplicates while preserving order
    return list(dict.fromkeys(links))


def collect_texts() -> List[str]:
    texts = []

    texts.extend(local_text_files())

    if ENABLE_GITHUB_SEARCH:
        texts.extend(github_code_search_texts())

    if GITHUB_TOKEN and GITHUB_REPOS:
        texts.extend(github_repo_texts())

    texts.extend(raw_url_texts())

    return texts


# =========================
# GeoIP (import from geo_utils)
# =========================
try:
    from geo_utils import get_geo_batch, get_flag, resolve_ip, is_public_ip
except ImportError:
    # Fallback if geo_utils not available
    def get_geo_batch(ips): return {}
    def get_flag(cc): return '️'
    def resolve_ip(h): return None
    def is_public_ip(ip): return True


# =========================
# Main
# =========================
def main():
    print('[INFO] === Starting collector ===', flush=True)
    print(f'[INFO] MAX_SERVERS_TOTAL={MAX_SERVERS_TOTAL}', flush=True)
    print(f'[INFO] TCP_MAX_CANDIDATES={TCP_MAX_CANDIDATES}', flush=True)
    print(f'[INFO] CHECK_TCP={CHECK_TCP}', flush=True)
    print(f'[INFO] CHECK_CORES={CHECK_CORES}', flush=True)
    print(f'[INFO] ENABLE_GITHUB_SEARCH={ENABLE_GITHUB_SEARCH}', flush=True)

    # 1. Collect texts
    print('[INFO] Step 1: Collecting source texts...', flush=True)
    texts = collect_texts()
    print(f'[INFO] Source texts collected: {len(texts)}', flush=True)

    if not texts:
        print('[WARN] No source texts found. Check sources/raw_urls.txt', flush=True)
        write_outputs([])
        return

    # 2. Extract links
    print('[INFO] Step 2: Extracting links...', flush=True)
    links = []
    for t in texts:
        links.extend(extract_links(t))

    unique_links = list(dict.fromkeys(links))
    print(f'[INFO] Links found: {len(links)}, unique: {len(unique_links)}', flush=True)

    if not unique_links:
        print('[WARN] No links found in sources', flush=True)
        write_outputs([])
        return

    # 3. Parse
    print('[INFO] Step 3: Parsing proxy URLs...', flush=True)
    servers = []
    seen = set()
    parse_errors = 0

    for url in unique_links:
        s = parse_proxy_url(url)
        if not s:
            parse_errors += 1
            continue

        fp = make_fingerprint(s)
        if fp in seen:
            continue

        seen.add(fp)
        s['fp'] = fp
        servers.append(s)

    print(f'[INFO] Parsed servers: {len(servers)} (errors: {parse_errors})', flush=True)

    if not servers:
        print('[WARN] No valid servers parsed', flush=True)
        write_outputs([])
        return

    # 4. Geolocation
    if ENABLE_GEO:
        print('[INFO] Step 4: Resolving geolocation...', flush=True)
        ips_to_check = []
        for s in servers:
            ip = resolve_ip(s['address'])
            if ip and is_public_ip(ip):
                s['ip'] = ip
                ips_to_check.append(ip)
            else:
                s['country'] = 'UN'
                s['city'] = ''
                s['country_name'] = ''

        if ips_to_check:
            print(f'[INFO] Checking {len(ips_to_check)} unique IPs...', flush=True)
            geo_results = get_geo_batch(ips_to_check)
            for s in servers:
                ip = s.get('ip')
                if ip and ip in geo_results:
                    country, city, country_name = geo_results[ip]
                    s['country'] = country
                    s['city'] = city
                    s['country_name'] = country_name
            print(f'[INFO] Geolocation done', flush=True)
    else:
        for s in servers:
            s['country'] = 'UN'
            s['city'] = ''
            s['country_name'] = ''

    # 5. Filters
    print('[INFO] Step 5: Applying filters...', flush=True)
    servers = [s for s in servers if passes_filters(s)]
    print(f'[INFO] Servers after filters: {len(servers)}', flush=True)

    if not servers:
        print('[WARN] No servers after filters', flush=True)
        write_outputs([])
        return

    # 6. Sort
    servers.sort(key=pre_sort_key)

    # 7. TCP checks
    if CHECK_TCP:
        print(f'[INFO] Step 6: TCP checks for {min(len(servers), TCP_MAX_CANDIDATES)} servers...', flush=True)
        if len(servers) > TCP_MAX_CANDIDATES:
            servers = servers[:TCP_MAX_CANDIDATES]
            print(f'[INFO] Limited to {TCP_MAX_CANDIDATES} candidates', flush=True)

        servers = run_tcp_checks(servers)
        print(f'[INFO] Servers after TCP checks: {len(servers)}', flush=True)
    else:
        print('[INFO] Step 6: TCP checks skipped', flush=True)

    if not servers:
        print('[WARN] No servers after TCP checks', flush=True)
        write_outputs([])
        return

    # 8. Core checks (skipped)
    if CHECK_CORES:
        print('[INFO] Step 7: Core checks...', flush=True)
        try:
            from core_check import filter_by_core_checks
            servers = filter_by_core_checks(servers)
            print(f'[INFO] Servers after core checks: {len(servers)}', flush=True)
        except Exception as e:
            print(f'[WARN] Core check failed: {e}', flush=True)
    else:
        print('[INFO] Step 7: Core checks skipped', flush=True)

    # 9. Final sort and limits
    print('[INFO] Step 8: Applying limits...', flush=True)
    servers.sort(key=final_sort_key)
    servers = apply_limits(servers, MAX_SERVERS_TOTAL, MAX_SERVERS_PER_PROTOCOL,
                           US_CA_QUOTA_PERCENT, MAX_DUPLICATE_IP)

    print(f'[INFO] Final selected servers: {len(servers)}', flush=True)

    # 10. Write outputs
    print('[INFO] Step 9: Writing output files...', flush=True)
    write_outputs(servers)
    print(f'[OK] === Collector finished ===', flush=True)
    print(f'[OK] Output directory: {OUT_DIR}', flush=True)


if __name__ == '__main__':
    main()
