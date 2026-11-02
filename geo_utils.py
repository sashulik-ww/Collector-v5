#!/usr/bin/env python3
"""Утилиты для определения страны и города через несколько сервисов"""

import socket
import threading
import time
from typing import Any, Dict, Optional, Tuple
import requests

SESSION = requests.Session()
SESSION.headers.update({'User-Agent': 'proxy-collector/2.0'})

# Кэш для IP-геолокации
_GEO_CACHE: Dict[str, Dict[str, Any]] = {}
_GEO_LOCK = threading.Lock()


def resolve_ip(host: str) -> Optional[str]:
    """Резолвим хост в IP"""
    try:
        socket.inet_aton(host)
        return host
    except socket.error:
        pass

    try:
        infos = socket.getaddrinfo(host, None, family=socket.AF_INET)
        if infos:
            return infos[0][4][0]
    except Exception:
        pass

    try:
        infos = socket.getaddrinfo(host, None, family=socket.AF_INET6)
        if infos:
            return infos[0][4][0]
    except Exception:
        pass

    return None


def is_public_ip(ip: str) -> bool:
    """Проверяем, что IP публичный"""
    import ipaddress
    try:
        obj = ipaddress.ip_address(ip)
        return not (
            obj.is_private or obj.is_loopback or obj.is_link_local or
            obj.is_reserved or obj.is_multicast or obj.is_unspecified
        )
    except ValueError:
        return False


def get_geo_ipwho(ip: str) -> Tuple[str, str, str]:
    """ipwho.is"""
    try:
        r = SESSION.get(f'https://ipwho.is/{ip}', timeout=8)
        if r.ok:
            data = r.json()
            if data.get('success'):
                country = data.get('country_code', 'UN')
                city = data.get('city', '')
                country_name = data.get('country', '')
                return country, city, country_name
    except Exception:
        pass
    return 'UN', '', ''


def get_geo_ipapi(ip: str) -> Tuple[str, str, str]:
    """ip-api.com"""
    try:
        r = SESSION.get(f'http://ip-api.com/json/{ip}?fields=status,message,country,countryCode,city', timeout=8)
        if r.ok:
            data = r.json()
            if data.get('status') == 'success':
                country = data.get('countryCode', 'UN')
                city = data.get('city', '')
                country_name = data.get('country', '')
                return country, city, country_name
    except Exception:
        pass
    return 'UN', '', ''


def get_geo_ipinfo(ip: str) -> Tuple[str, str, str]:
    """ipinfo.io"""
    try:
        r = SESSION.get(f'https://ipinfo.io/{ip}/json', timeout=8)
        if r.ok:
            data = r.json()
            country = data.get('country', 'UN')
            city = data.get('city', '')
            country_name = data.get('country', '')
            return country, city, country_name
    except Exception:
        pass
    return 'UN', '', ''


def get_geo(ip: str) -> Tuple[str, str, str]:
    """
    Получаем геолокацию через несколько сервисов, возвращаем наиболее точные данные.
    Возвращает: (country_code, city, country_name)
    """
    global _GEO_CACHE
    
    with _GEO_LOCK:
        if ip in _GEO_CACHE:
            cached = _GEO_CACHE[ip]
            if time.time() - cached.get('ts', 0) < 3600 * 24:  # кэш на 24 часа
                return cached.get('country', 'UN'), cached.get('city', ''), cached.get('country_name', '')
    
    # Пробуем несколько сервисов
    country, city, country_name = get_geo_ipwho(ip)
    if country != 'UN':
        result = (country, city, country_name)
    else:
        country, city, country_name = get_geo_ipapi(ip)
        if country != 'UN':
            result = (country, city, country_name)
        else:
            country, city, country_name = get_geo_ipinfo(ip)
            result = (country, city, country_name)
    
    # Кэшируем результат
    with _GEO_LOCK:
        _GEO_CACHE[ip] = {
            'country': result[0],
            'city': result[1],
            'country_name': result[2],
            'ts': time.time()
        }
    
    return result


COUNTRY_FLAGS = {
    'AF': '🇦🇫', 'AX': '🇦🇽', 'AL': '🇦🇱', 'DZ': '🇩🇿', 'AS': '🇦🇸', 'AD': '🇦🇩', 'AO': '🇦🇴',
    'AI': '🇦🇮', 'AQ': '🇦🇶', 'AG': '🇦🇬', 'AR': '🇦🇷', 'AM': '🇦🇲', 'AW': '🇦🇼', 'AU': '🇦🇺',
    'AT': '🇦🇹', 'AZ': '🇦🇿', 'BS': '🇧🇸', 'BH': '🇧🇭', 'BD': '🇧🇩', 'BB': '🇧🇧', 'BY': '🇧🇾',
    'BE': '🇧🇪', 'BZ': '🇧🇿', 'BJ': '🇧🇯', 'BM': '🇧🇲', 'BT': '🇧🇹', 'BO': '🇧🇴', 'BQ': '🇧🇶',
    'BA': '🇧🇦', 'BW': '🇧🇼', 'BV': '🇧🇻', 'BR': '🇧🇷', 'IO': '🇮🇴', 'BN': '🇧🇳', 'BG': '🇧🇬',
    'BF': '🇧🇫', 'BI': '🇧🇮', 'KH': '🇰🇭', 'CM': '🇨🇲', 'CA': '🇨🇦', 'CV': '🇨🇻', 'KY': '🇰🇾',
    'CF': '🇨🇫', 'TD': '🇹🇩', 'CL': '🇨🇱', 'CN': '🇨🇳', 'CX': '🇨🇽', 'CC': '🇨🇨', 'CO': '🇨🇴',
    'KM': '🇰🇲', 'CG': '🇨🇬', 'CD': '🇨🇩', 'CK': '🇨🇰', 'CR': '🇨🇷', 'CI': '🇨🇮', 'HR': '🇭🇷',
    'CU': '🇨🇺', 'CW': '🇨🇼', 'CY': '🇨🇾', 'CZ': '🇨🇿', 'DK': '🇩🇰', 'DJ': '🇩🇯', 'DM': '🇩🇲',
    'DO': '🇩🇴', 'EC': '🇪🇨', 'EG': '🇪🇬', 'SV': '🇸🇻', 'GQ': '🇬🇶', 'ER': '🇪🇷', 'EE': '🇪🇪',
    'ET': '🇪🇹', 'FK': '🇫🇰', 'FO': '🇫🇴', 'FJ': '🇫🇯', 'FI': '🇫🇮', 'FR': '🇫🇷', 'GF': '🇬🇫',
    'PF': '🇵🇫', 'TF': '🇹🇫', 'GA': '🇬🇦', 'GM': '🇬🇲', 'GE': '🇬🇪', 'DE': '🇩🇪', 'GH': '🇬🇭',
    'GI': '🇬🇮', 'GR': '🇬🇷', 'GL': '🇬🇱', 'GD': '🇬🇩', 'GP': '🇬🇵', 'GU': '🇬🇺', 'GT': '🇬🇹',
    'GG': '🇬🇬', 'GN': '🇬🇳', 'GW': '🇬🇼', 'GY': '🇬🇾', 'HT': '🇭🇹', 'HM': '🇭🇲', 'VA': '🇻🇦',
    'HN': '🇭🇳', 'HK': '🇭🇰', 'HU': '🇭🇺', 'IS': '🇮🇸', 'IN': '🇮🇳', 'ID': '🇮🇩', 'IR': '🇮🇷',
    'IQ': '🇮🇶', 'IE': '🇮🇪', 'IM': '🇮🇲', 'IL': '🇮🇱', 'IT': '🇮🇹', 'JM': '🇯🇲', 'JP': '🇯🇵',
    'JE': '🇯🇪', 'JO': '🇯🇴', 'KZ': '🇰🇿', 'KE': '🇰🇪', 'KI': '🇰🇮', 'KP': '🇰🇵', 'KR': '🇰🇷',
    'KW': '🇰🇼', 'KG': '🇰🇬', 'LA': '🇱🇦', 'LV': '🇱🇻', 'LB': '🇱🇧', 'LS': '🇱🇸', 'LR': '🇱🇷',
    'LY': '🇱🇾', 'LI': '🇱🇮', 'LT': '🇱🇹', 'LU': '🇱🇺', 'MO': '🇲🇴', 'MK': '🇲🇰', 'MG': '🇲🇬',
    'MW': '🇲🇼', 'MY': '🇲🇾', 'MV': '🇲🇻', 'ML': '🇲🇱', 'MT': '🇲🇹', 'MH': '🇲🇭', 'MQ': '🇲🇶',
    'MR': '🇲🇷', 'MU': '🇲🇺', 'YT': '🇾🇹', 'MX': '🇲🇽', 'FM': '🇫🇲', 'MD': '🇲🇩', 'MC': '🇲🇨',
    'MN': '🇲🇳', 'ME': '🇲🇪', 'MS': '🇲🇸', 'MA': '🇲🇦', 'MZ': '🇲🇿', 'MM': '🇲🇲', 'NA': '🇳🇦',
    'NR': '🇳🇷', 'NP': '🇳🇵', 'NL': '🇳🇱', 'NC': '🇳🇨', 'NZ': '🇳🇿', 'NI': '🇳🇮', 'NE': '🇳🇪',
    'NG': '🇳🇬', 'NU': '🇳🇺', 'NF': '🇳🇫', 'MP': '🇲🇵', 'NO': '🇳🇴', 'OM': '🇴🇲', 'PK': '🇵🇰',
    'PW': '🇵🇼', 'PS': '🇵🇸', 'PA': '🇵🇦', 'PG': '🇵🇬', 'PY': '🇵🇾', 'PE': '🇵🇪', 'PH': '🇵🇭',
    'PN': '🇵🇳', 'PL': '🇵🇱', 'PT': '🇵🇹', 'PR': '🇵🇷', 'QA': '🇶🇦', 'RE': '🇷🇪', 'RO': '🇷🇴',
    'RU': '🇷🇺', 'RW': '🇷🇼', 'BL': '🇧🇱', 'SH': '🇸🇭', 'KN': '🇰🇳', 'LC': '🇱🇨', 'MF': '🇲🇫',
    'PM': '🇵🇲', 'VC': '🇻🇨', 'WS': '🇼🇸', 'SM': '🇸🇲', 'ST': '🇸🇹', 'SA': '🇸🇦', 'SN': '🇸🇳',
    'RS': '🇷🇸', 'SC': '🇸🇨', 'SL': '🇸🇱', 'SG': '🇸🇬', 'SX': '🇸🇽', 'SK': '🇸🇰', 'SI': '🇸🇮',
    'SB': '🇸🇧', 'SO': '🇸🇴', 'ZA': '🇿🇦', 'GS': '🇬🇸', 'SS': '🇸🇸', 'ES': '🇪🇸', 'LK': '🇱🇰',
    'SD': '🇸🇩', 'SR': '🇸🇷', 'SJ': '🇸🇯', 'SZ': '🇸🇿', 'SE': '🇸🇪', 'CH': '🇨🇭', 'SY': '🇸🇾',
    'TW': '🇹🇼', 'TJ': '🇹🇯', 'TZ': '🇹🇿', 'TH': '🇹🇭', 'TL': '🇹🇱', 'TG': '🇹🇬', 'TK': '🇹🇰',
    'TO': '🇹🇴', 'TT': '🇹🇹', 'TN': '🇹🇳', 'TR': '🇹🇷', 'TM': '🇹🇲', 'TC': '🇹🇨', 'TV': '🇹🇻',
    'UG': '🇺🇬', 'UA': '🇺🇦', 'AE': '🇦🇪', 'GB': '🇬🇧', 'US': '🇺🇸', 'UM': '🇺🇲', 'UY': '🇺🇾',
    'UZ': '🇺🇿', 'VU': '🇻🇺', 'VE': '🇻🇪', 'VN': '🇻🇳', 'VG': '🇻🇬', 'VI': '🇻🇮', 'WF': '🇼🇫',
    'EH': '🇪🇭', 'YE': '🇾🇪', 'ZM': '🇿🇲', 'ZW': '🇿🇼',
}


def get_flag(country_code: str) -> str:
    """Возвращает флаг страны по ISO-коду"""
    return COUNTRY_FLAGS.get(country_code.upper(), '🏳️')
