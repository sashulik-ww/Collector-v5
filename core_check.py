#!/usr/bin/env python3
"""Реальная проверка через Xray и sing-box"""

import json
import os
import shutil
import socket
import subprocess
import tempfile
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Dict, List, Optional

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


TEST_URL = os.environ.get('CORE_TEST_URL', 'https://www.google.com/generate_204')
TIMEOUT = env_int('CORE_CHECK_TIMEOUT', 10)
WORKERS = env_int('CORE_CHECK_WORKERS', 20)
SAMPLE = env_int('CORE_CHECK_SAMPLE', 0)
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


def wait_port(port: int, timeout: float = 8.0) -> bool:
    start = time.time()
    while time.time() - start < timeout:
        try:
            with socket.create_connection(('127.0.0.1', port), timeout=0.5):
                return True
        except Exception:
            time.sleep(0.1)
    return False


def curl_test(port: int) -> Dict[str, Any]:
    """Тестируем соединение через прокси"""
    curl = shutil.which('curl')
    if not curl:
        return {'success': False, 'error': 'curl not found'}

    cmd = [
        curl,
        '-s',
        '-o', '/dev/null',
        '-w', '%{http_code} %{time_total} %{speed_download}',
        '--max-time', str(TIMEOUT),
        '--socks5-hostname', f'127.0.0.1:{port}',
        TEST_URL,
    ]

    try:
        start = time.time()
        out = subprocess.check_output(
            cmd,
            stderr=subprocess.DEVNULL,
            timeout=TIMEOUT + 5
        ).decode().strip()

        elapsed = time.time() - start
        parts = out.split()

        if len(parts) >= 3:
            http_code = parts[0]
            time_total = float(parts[1])
            speed = float(parts[2]) / 1024  # KB/s

            success = http_code in {'200', '204', '301', '302', '303', '307', '308'}

            return {
                'success': success,
                'http_code': http_code,
                'time_total': time_total,
                'speed_kbps': speed,
                'elapsed': elapsed
            }
    except subprocess.TimeoutExpired:
        return {'success': False, 'error': 'timeout'}
    except Exception as e:
        return {'success': False, 'error': str(e)}

    return {'success': False, 'error': 'unknown'}


def run_binary_with_config(cmd: List[str], cfg: Dict[str, Any], port: int) -> Dict[str, Any]:
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

        if not wait_port(port, 8.0):
            return {'success': False, 'error': 'port not ready'}

        result = curl_test(port)
        return result

    except Exception as e:
        return {'success': False, 'error': str(e)}

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

    if proto == 'hysteria2':
        return {
            'protocol': 'hysteria2',
            'settings': {
                'servers': [{
                    'address': s['address'],
                    'port': s['port'],
                    'password': s.get('password'),
                }]
            },
            'streamSettings': {
                'security': 'tls',
                'tlsSettings': {
                    'serverName': s.get('sni') or s.get('host') or s.get('address'),
                    'allowInsecure': True,
                }
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


def check_xray(s: Dict[str, Any]) -> Dict[str, Any]:
    binary = xray_binary()
    if not binary:
        return {'success': False, 'error': 'xray not found'}

    cfg = xray_config(s, get_free_port())
    if not cfg:
        return {'success': False, 'error': 'config failed'}

    port = cfg['inbounds'][0]['port']
    return run_binary_with_config([binary, 'run', '-c'], cfg, port)


def check_singbox(s: Dict[str, Any]) -> Dict[str, Any]:
    binary = singbox_binary()
    if not binary:
        return {'success': False, 'error': 'singbox not found'}

    cfg = singbox_config(s, get_free_port())
    if not cfg:
        return {'success': False, 'error': 'config failed'}

    port = cfg['inbounds'][0]['listen_port']
    return run_binary_with_config([binary, 'run', '-c'], cfg, port)


def check_server(s: Dict[str, Any]) -> Dict[str, Any]:
    """Проверяет сервер через Xray и sing-box"""
    results = {
        'xray': None,
        'singbox': None,
        'passed': False
    }

    if 'xray' in CORES:
        results['xray'] = check_xray(s)

    if 'singbox' in CORES:
        results['singbox'] = check_singbox(s)

    if 'xray' in CORES and results['xray'] and results['xray'].get('success'):
        results['passed'] = True
        results['speed_kbps'] = results['xray'].get('speed_kbps', 0)
        results['time_total'] = results['xray'].get('time_total', 0)
    elif 'singbox' in CORES and results['singbox'] and results['singbox'].get('success'):
        results['passed'] = True
        results['speed_kbps'] = results['singbox'].get('speed_kbps', 0)
        results['time_total'] = results['singbox'].get('time_total', 0)

    return results


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
    total = len(sample)

    print(f'[CORE] Starting core check for {total} servers using {", ".join(active)}')
    print(f'[CORE] Using {WORKERS} workers')

    with ThreadPoolExecutor(max_workers=WORKERS) as ex:
        futures = {ex.submit(check_server, s): s for s in sample}

        done_count = 0
        for f in as_completed(futures):
            s = futures[f]
            result = f.result()
            done_count += 1

            if done_count % 50 == 0:
                print(f'[CORE] Progress: {done_count}/{total} ({done_count * 100 // total}%)')

            if result['passed']:
                s['core_check_passed'] = True
                s['speed_kbps'] = result.get('speed_kbps', 0)
                s['time_total'] = result.get('time_total', 0)
                passed.append(s)

    print(f'[CORE] Core check passed: {len(passed)}/{total} servers')

    if REQUIRED:
        return passed

    return servers
