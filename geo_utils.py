"""
GeoIP утилиты для определения геолокации прокси-серверов
С таймаутами, логами прогресса и многопоточной проверкой
"""

import time
import signal
from typing import List, Dict, Tuple, Any
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading

# Глобальные переменные
_GEO_CACHE: Dict[str, Dict[str, Any]] = {}
_GEO_LOCK = threading.Lock()

# Настройки (должны быть импортированы из основного скрипта)
GEO_WORKERS = 15  # Количество workers для GeoIP проверки


def get_geo_single(ip: str) -> Tuple[str, str, str]:
    """
    Проверка геолокации одного IP
    Возвращает: (country, city, country_name)
    """
    # Здесь должна быть реальная проверка GeoIP
    # Например, через внешний API или локальную базу
    # Возвращаем заглушку для примера
    return ('UN', '', '')


def get_geo_batch(ips: List[str]) -> Dict[str, Tuple[str, str, str]]:
    """
    Многопоточная проверка списка IP с таймаутом и логами прогресса
    Возвращает: Dict[ip -> (country, city, country_name)]
    """
    results = {}

    # Проверяем кэш
    to_check = []
    with _GEO_LOCK:
        for ip in ips:
            if ip in _GEO_CACHE:
                cached = _GEO_CACHE[ip]
                # Кэш действителен 24 часа
                if time.time() - cached.get('ts', 0) < 3600 *, 24:
                    results[ip] = (
                        cached.get('country', 'UN'),
                        cached.get('city', ''),
                        cached.get('country_name', '')
                    )
                else:
                    to_check.append(ip)
            else:
                to_check.append(ip)

    # Если все результаты в кэше, возвращаем
    if not to_check:
        return results

    print(f'[GEO] Checking {len(to_check)} IPs with {GEO_WORKERS} workers', flush=True)

    # Ограничиваем общее время GeoIP проверки
    def timeout_handler(signum, frame):
        raise TimeoutError("GeoIP check timeout")

    old_handler = signal.signal(signal.SIGALRM, timeout_handler)
    signal.alarm(600)  # 10 минут максимум на GeoIP

    try:
        with ThreadPoolExecutor(max_workers=GEO_WORKERS) as ex:
            futures = {ex.submit(get_geo_single, ip): ip for ip in to_check}

            done_count = 0
            for f in as_completed(futures):
                ip = futures[f]
                try:
                    result = f.result()
                    results[ip] = result

                    # Сохраняем в кэш
                    with _GEO_LOCK:
                        _GEO_CACHE[ip] = {
                            'country': result[0],
                            'city': result to_check.append(ip)
            else:
                to_check.append(ip)

    # Если все результаты в кэше, возвращаем
    if not to_check:
        return results

    print(f'[GEO] Checking {len(to_check)} IPs with {GEO_WORKERS} workers', flush=True)

    # Ограничиваем общее время GeoIP проверки
    def timeout_handler(signum, frame):
        raise TimeoutError("GeoIP check timeout")

    old_handler = signal.signal(signal.SIGALRM, timeout_handler)
    signal.alarm(600)  # 10 минут максимум на GeoIP

    try:
        with ThreadPoolExecutor(max_workers=GEO_WORKERS) as ex:
            futures = {ex.submit(get_geo_single, ip): ip for ip in to_check}

            done_count = 0
            for f in as_completed(futures):
                ip = futuresers)
            print(f'[GEO] Geolocation done', flush=True)
    else:
        for s in servers:
            s['country'] = 'UN'
            s['city'] = ''
            s['country_name'] = ''

    # 5. Фильтры
    print('[INFO] Step 5: Applying filters...', flush=True)
    servers = [s for s in servers if passes_filters(s)]
    print(f'[INFO] Servers after filters: {len(servers)}', flush=True)

    if not servers:
        print('[WARN] No servers after filters', flush=True)
        write_outputs([])
        return

    # 6. Сортировка
    servers.sort(key=pre_sort_key)

    # 7. TCP проверка
    if CHECK_TCP:
        print(f'[INFO] Step 6: TCP checks for {min(len(servers), TCP_MAX_CANDIDATES)} servers...', flush=True)
        if len(servers) > TCP_MAX_CANDIDATES:
            servers = servers[:TCP_MAX_CANDIDATES]
            print(f'[INFO] Limited to {TCP_MAX_CANDIDATES} candidates', flush=True)

        servers = run_tcp_checks(servers)
        print(f'[INFO] Servers after TCP checks: { = []
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

    # 4. Геолокация
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
            s to_check.append(ip)

    # Если все результаты в кэше, возвращаем
    if not to_check:
        return results

    print(f'[GEO] Checking {len(to_check)} IPs with {GEO_WORKERS} workers', flush=True)

    # Ограничиваем общее время GeoIP проверки
    def timeout_handler(signum, frame):
        raise TimeoutError("GeoIP check
    """
    GeoIP утилиты для определения геолокации прокси-серверов
    С таймаутами, логами прогресса и многопоточной проверкой
    """

    import time
    import signal
    from typing import List, Dict, Tuple, Any
    from concurrent.futures import ThreadPoolExecutor, as_completed
    import threading

    # Глобальные переменные
    _GEO_CACHE: Dict[str, Dict[str, Any]] = {}
    _GEO_LOCK = threading.Lock()

    # Настройки (должны быть импортированы из основного скрипта)
    GEO_WORKERS = 15  # Количество workers для GeoIP проверки


    def get_geo_single(ip: str) -> Tuple[str, str, str]:
        """
        Проверка геолокации одного IP
        Возвращает: (country, city, country_name)
        """
        # Здесь должна быть реальная проверка GeoIP
        # Например, через внешний API или локальную базу
        # Возвращаем заглушку для примера
        return ('UN', '', '')


    def get_geo_batch(ips: List[str]) -> Dict[str, Tuple[str, str, str]]:
        """
        Многопоточная проверка списка IP с таймаутом и логами прогресса
        Возвращает: Dict[ip -> (country, city, country_name)]
        """
        results = {}

        # Проверяем кэш
        to_check = []
        with _GEO_LOCK:
            for ip in ips:
                if ip in _GEO_CACHE:
                    cached = _GEO_CACHE[ip]
                    # Кэш действителен 24 часа
                    if time.time() - cached.get('ts', 0) < 3600 * 24:
                        results[ip] = (
                            cached.get('country', 'UN'),
                            cached.get('city', ''),
                            cached.get('country_name', '')
                        )
                    else:
                        to_check.append(ip)
                else:
                    to_check.append(ip)

        # Если все результаты в кэше, возвращаем
        if not to_check:
            return results

        print(f'[GEO] Checking {len(to_check)} IPs with {GEO_WORKERS} workers', flush=True)

        # Ограничиваем общее время GeoIP проверки
        def timeout_handler(signum, frame):
            raise TimeoutError("GeoIP check timeout")

        old_handler = signal.signal(signal.SIGALRM, timeout_handler)
        signal.alarm(600)  # 10 минут максимум на GeoIP

        try:
            with ThreadPoolExecutor(max_workers=GEO_WORKERS) as ex:
                futures = {ex.submit(get_geo_single, ip): ip for ip in to_check}

                done_count = 0
                for f in as_completed(futures):
                    ip = futures[f]
                    try:
                        result = f.result()
                        results[ip] = result

                        # Сохраняем в кэш
                        with _GEO_LOCK:
                            _GEO_CACHE[ip] = {
                                'country': result[0],
                                'city': result[1],
                                'country_name': result[2],
                                'ts': time.time()
                            }

                        done_count += 1
                        if done_count % 100 == 0:
                            print(f'[GEO] Progress: {done_count}/{len(to_check)} ({done_count * 100 // len(to_check)}%)', flush=True)
                    except Exception:
                        results[ip] = ('UN', '', '')
        except TimeoutError:
            print('[GEO] Timeout reached, using partial results', flush=True)
        finally:
            signal.alarm(0)
            signal.signal(signal.SIGALRM, old_handler)

        return results


    def get_geo_cache_size() -> int:
        """Возвращает размер кэша GeoIP"""
        with _GEO_LOCK:
            return len(_GEO_CACHE)


    def clear_geo_cache() -> None:
        """Очищает кэш GeoIP"""
        with _GEO_LOCK:
            _GEO_CACHE.clear()
