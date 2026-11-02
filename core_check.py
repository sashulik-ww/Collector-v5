import json
import os
import shutil
import socket
import subprocess
import tempfile
import time
from typing import Any, Dict, List

try:
    import collector
except Exception:
    collector = None

TRUE = {'1', 'true', 'yes', 'on'}


def env_bool(name: str, default: bool = False) -> bool:
    return os.environ.get(name, str(default)).strip().lower() in TRUE


def env_int(name: str, default: int) -> int:
    try:
        return int(os.environ.get(name, '').strip() or default)
    except Exception:
        return default


TEST_URL = os.environ.get('CORE_TEST_URL', 'https://www.gstatic.com/generate_204')
TIMEOUT = env_int('CORE_CHECK_TIMEOUT', 8)
SAMPLE = env_int('CORE_CHECK_SAMPLE', 20)
REQUIRED = env_bool('CORE_CHECK_REQUIRED', False)
CORES = {x.strip().lower() for x in os.environ.get('CORE_CHECK_CORES', 'xray,singbox').split(',') if x.strip()}


def xray_binary() -> str:
    return os.environ.get('XRAY_BIN') or shutil.which('xray') or ''


def singbox_binary() -> str:
    return os.environ.get('SINGBOX_BIN') or shutil.which('sing-box') or ''


def get_free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(('127.0.0.1', 0))
        return s.getsockname()[1]


def wait_port(port: int, timeout: float = 5.0) -> bool:
    start = time.time()
    while time.time() - start < timeout:
        try:
            with socket.create_connection(('127.0.0.1', port), timeout=0.5):
                return True
        except Exception:
            time.sleep(0.1)
    return False


def curl_ok(port: int) -> bool:
    curl = shutil.which('curl')
    if not curl:
        return False

    cmd = [
        curl,
        '-s',
        '-o', '/dev/null',
        '-w', '%{http_code}',
        '--max-time', str(TIMEOUT),
        '--socks5-hostname', f'127.0.0.1:{port}',
        TEST_URL,
    ]

    try:
        out = subprocess.check_output(
            cmd,
            stderr=subprocess.DEVNULL,
            timeout=TIMEOUT + 5
        ).decode().strip()

        return out in {'200', '204', '301', '302', '303', '307', '308'}
    except Exception:
        return False


def run_binary_with_config(cmd: List[str], cfg: Dict[str, Any], port: int) -> bool:
    tmp = None
    proc = None

    try:
        with tempfile.NamedTemporaryFile('w', suffix='.json', delete=False, encoding='utf-8') as f:
            json.dump(cfg, f, ensure_ascii=False)
            tmp = f.name

        proc = subprocess.Popen(
            cmd + [tmp],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )

        if not wait_port(port, 5.0):
            return False

        return curl_ok(port)

    except Exception:
        return False

    finally:
        if proc:
            proc.terminate()
            try:
                proc.wait(timeout=2)
            except Exception:
                proc.kill()

        if tmp and os.path.exists(tmp):
            os.unlink(tmp)


def xray_stream_settings(s: Dict[str, Any]) -> Dict[str, Any]:
    stream = {'network': s.get('network', 'tcp')}
    net = s.get('network')

    if net == 'ws':
        ws = {'path': s.get('path') or '/'}
        if s.get('host'):
            ws['headers'] = {'Host': s['host']}
        stream['wsSettings'] = ws

    elif net == 'grpc':
        stream['grpcSettings'] = {
            'serviceName': s.get('path') or ''
        }

    elif net in ('h2', 'http'):
        stream['httpSettings'] = {
            'path': s.get('path') or '/',
            'host': [s.get('host')] if s.get('host') else []
        }

    sec = s.get('security')

    if sec in ('tls', 'reality'):
        stream['security'] = sec

        if sec == 'tls':
            stream['tlsSettings'] = {
                'serverName': s.get('sni') or s.get('host') or s.get('address'),
                'allowInsecure': True,
            }
        else:
            stream['realitySettings'] = {
                'serverName': s.get('sni') or s.get('address'),
                'fingerprint': s.get('fp') or 'chrome',
                'publicKey': s.get('pbk') or '',
                'shortId': s.get('sid') or '',
            }

    return stream


def xray_outbound(s: Dict[str, Any]) -> Dict[str, Any]:
    proto = s.get('protocol')

    if proto == 'vless':
        user = {
            'id': s.get('uuid'),
            'encryption': 'none',
        }
        if s.get('flow'):
            user['flow'] = s['flow']

        return {
            'protocol': 'vless',
            'settings': {
                'vnext': [{
                    'address': s['address'],
                    'port': s['port'],
                    'users': [user],
                }]
            },
            'streamSettings': xray_stream_settings(s),
        }

    if proto == 'vmess':
        user = {
            'id': s.get('uuid'),
            'alterId': int(s.get('aid') or 0),
            'security': s.get('method') or 'auto',
        }

        return {
            'protocol': 'vmess',
            'settings': {
                'vnext': [{
                    'address': s['address'],
                    'port': s['port'],
                    'users': [user],
                }]
            },
            'streamSettings': xray_stream_settings(s),
        }

    if proto == 'trojan':
        stream = xray_stream_settings(s)
        stream.setdefault('security', 'tls')

        return {
            'protocol': 'trojan',
            'settings': {
                'servers': [{
                    'address': s['address'],
                    'port': s['port'],
                    'password': s.get('password'),
                }]
            },
            'streamSettings': stream,
        }

    if proto == 'shadowsocks':
        return {
            'protocol': 'shadowsocks',
            'settings': {
                'servers': [{
                    'address': s['address'],
                    'port': s['port'],
                    'method': s.get('method'),
                    'password': s.get('password'),
                }],
                'udp': True,
            }
        }

    return {}


def xray_config(s: Dict[str, Any], port: int) -> Dict[str, Any]:
    outbound = xray_outbound(s)
    if not outbound:
        return {}

    outbound['tag'] = 'proxy'

    return {
        'log': {'loglevel': 'none'},
        'inbounds': [{
            'listen': '127.0.0.1',
            'port': port,
            'protocol': 'socks',
            'settings': {
                'auth': 'noauth',
                'udp': True,
            }
        }],
        'outbounds': [
            outbound,
            {'protocol': 'freedom', 'tag': 'direct'},
        ],
        'routing': {
            'domainStrategy': 'AsIs',
            'rules': []
        }
    }


def singbox_outbound(s: Dict[str, Any]) -> Dict[str, Any]:
    if collector:
        try:
            return collector.to_singbox_outbound(s, 'proxy')
        except Exception:
            pass

    return {}


def singbox_config(s: Dict[str, Any], port: int) -> Dict[str, Any]:
    outbound = singbox_outbound(s)
    if not outbound:
        return {}

    return {
        'log': {'level': 'panic'},
        'inbounds': [{
            'type': 'mixed',
            'tag': 'in',
            'listen': '127.0.0.1',
            'listen_port': port,
        }],
        'outbounds': [
            outbound,
            {'type': 'direct', 'tag': 'direct'},
        ],
        'route': {
            'rules': [{
                'inbound': 'in',
                'outbound': 'proxy',
            }]
        }
    }


def check_xray(s: Dict[str, Any]) -> bool:
    binary = xray_binary()
    if not binary:
        return False

    cfg = xray_config(s, get_free_port())
    if not cfg:
        return False

    port = cfg['inbounds'][0]['port']
    return run_binary_with_config([binary, 'run', '-c'], cfg, port)


def check_singbox(s: Dict[str, Any]) -> bool:
    binary = singbox_binary()
    if not binary:
        return False

    cfg = singbox_config(s, get_free_port())
    if not cfg:
        return False

    port = cfg['inbounds'][0]['listen_port']
    return run_binary_with_config([binary, 'run', '-c'], cfg, port)


def filter_by_core_checks(servers: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    if not servers:
        return servers

    available = set()
    if xray_binary():
        available.add('xray')
    if singbox_binary():
        available.add('singbox')

    active = CORES & available
    if not active:
        print('[WARN] Core check requested, but xray/sing-box binaries are not found. Skipping.')
        return servers

    sample = servers[:SAMPLE] if SAMPLE > 0 else servers
    passed = []

    for s in sample:
        ok = True

        if 'xray' in active:
            ok = ok and check_xray(s)

        if ok and 'singbox' in active:
            ok = ok and check_singbox(s)

        s['core_check_passed'] = ok

        if ok:
            passed.append(s)

    if REQUIRED:
        return passed

    return servers
