#!/usr/bin/env python3
"""Try common/dictionary passwords against every active /etc/shadow hash via libcrypt.

Usage: weak_passwords.py HOSTNAME [DICTIONARY_FILE] [SHADOW_FILE]
Output (parsed by checks/10-accounts.sh), one KEY:value per line:
  DICT_LOADED:n  DICT_ERR:msg  CRYPT_AVAILABLE:0|1  TOTAL_PASSWORDS:n
  ALGOS:name:count,...  WEAK:user  PARTIAL:user:tested:total
The matched password itself is never printed.
"""
import ctypes
import ctypes.util
import multiprocessing as mp
import os
import sys
import time

BUDGET_SEC = 240        # per-account time budget
CHUNK = 64              # candidates per worker task

COMMON_PASSWORDS = [
    '123456', 'password', 'qwerty', 'admin', '12345678', 'root',
    'pass123', 'P@ssword', '123456789', 'system', '12345', 'letmein',
    'welcome', 'master', 'administrator', 'changeme', 'ubuntu', 'debian',
    'fedora', 'centos', 'redhat', 'user', 'test', 'demo', 'login', 'pass',
    'password123', 'admin123', 'root123', '1234', '1234567', '1234567890',
]

_lib = None


def load_crypt():
    global _lib
    if _lib is None:
        name = ctypes.util.find_library('crypt')
        if name:
            try:
                lib = ctypes.CDLL(name)
                lib.crypt.argtypes = [ctypes.c_char_p, ctypes.c_char_p]
                lib.crypt.restype = ctypes.c_char_p
                _lib = lib
            except OSError:
                _lib = None
    return _lib


def try_candidates(task):
    """Worker: (hash, candidates) -> (matched password or None, number tested)."""
    hash_val, candidates = task
    lib = load_crypt()
    if not lib:
        return None, 0
    hash_bytes = hash_val.encode()
    tested = 0
    for candidate in candidates:
        tested += 1
        result = lib.crypt(candidate.encode('utf-8', 'ignore'), hash_bytes)
        if result and result.decode('utf-8', 'ignore') == hash_val:
            return candidate, tested
    return None, tested


def algorithm(hash_val):
    prefixes = {'$y$': 'Yescrypt', '$6$': 'SHA-512', '$5$': 'SHA-256', '$1$': 'MD5 (Obsolete)',
                '$2a$': 'Bcrypt', '$2b$': 'Bcrypt'}
    for prefix, name in prefixes.items():
        if hash_val.startswith(prefix):
            return name
    return 'DES (Obsolete)' if len(hash_val) == 13 else 'Unknown'


def main():
    hostname = sys.argv[1] if len(sys.argv) > 1 else ''
    dict_file = sys.argv[2] if len(sys.argv) > 2 else ''
    shadow_file = sys.argv[3] if len(sys.argv) > 3 else '/etc/shadow'

    passwords = list(COMMON_PASSWORDS)
    if hostname:
        passwords.append(hostname.lower())
    if dict_file and os.path.exists(dict_file):
        try:
            with open(dict_file, errors='ignore') as fh:
                loaded = [line.strip() for line in fh if line.strip()]
            passwords.extend(loaded)
            print(f'DICT_LOADED:{len(loaded)}')
        except OSError as err:
            print(f'DICT_ERR:{err}')
    base = list(dict.fromkeys(passwords))

    print('CRYPT_AVAILABLE:' + ('1' if load_crypt() else '0'))
    algos, weak, partial = {}, [], []
    with open(shadow_file) as fh:
        entries = [line.strip().split(':') for line in fh]
    for parts in entries:
        if len(parts) < 2:
            continue
        user, hash_val = parts[0], parts[1]
        if not hash_val or hash_val.startswith(('!', '*', 'x')):
            continue
        algo = algorithm(hash_val)
        algos[algo] = algos.get(algo, 0) + 1
        if not load_crypt():
            continue
        candidates = list(dict.fromkeys(base + [user, f'{user}123', f'{user}2025', f'{user}2026', f'{user}!', f'{user}1']))
        tasks = [(hash_val, candidates[i:i + CHUNK]) for i in range(0, len(candidates), CHUNK)]
        tested, hit, started = 0, None, time.time()
        # One pool per account: leaving the block terminates workers still busy after a hit
        with mp.Pool(max(1, os.cpu_count() or 2)) as pool:
            for match, count in pool.imap_unordered(try_candidates, tasks):
                tested += count
                if match is not None:
                    hit = match
                    break
                if time.time() - started > BUDGET_SEC:
                    break
        if hit is not None:
            weak.append(user)
        elif tested < len(candidates):
            partial.append((user, tested, len(candidates)))

    print(f'TOTAL_PASSWORDS:{len(base)}')
    print('ALGOS:' + ','.join(f'{k}:{v}' for k, v in algos.items()))
    for user in weak:
        print(f'WEAK:{user}')
    for user, tested, total in partial:
        print(f'PARTIAL:{user}:{tested}:{total}')


if __name__ == '__main__':
    main()
