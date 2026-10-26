"""Operasi berkas dan blok DES, 3DES, AES untuk Kriptofull.

DES dan 3DES dapat memakai implementasi Feistel sendiri atau PyCryptodome.
AES-128/192/256 hanya via PyCryptodome. ECB/CBC memakai PKCS#7;
AES GCM memakai nonce dan tag, tanpa PKCS#7.

Wire format:
  ECB: ciphertext
  CBC: IV || ciphertext
  GCM: 12-byte nonce || 16-byte tag || ciphertext
DES/3DES adalah algoritma historis untuk kompatibilitas dan eksperimen; tidak direkomendasikan untuk keamanan produksi.
"""
from __future__ import annotations

import os
import re
import hashlib
import hmac
import base64
import binascii
from pathlib import Path

import des_own
import des3_own

BLOCK = 8  # kompatibilitas dengan versi DES sebelumnya (DES)
MODES = ('ECB', 'CBC', 'GCM')
ENGINES = ('own', 'library')
ALGORITHMS = ('DES', '3DES', 'AES-128', 'AES-192', 'AES-256')
KEY_EXAMPLES = {
    'DES': '133457799BBCDFF1',
    '3DES': '0123456789ABCDEFFEDCBA98765432100011223344556677',
    'AES-128': '000102030405060708090A0B0C0D0E0F',
    'AES-192': '000102030405060708090A0B0C0D0E0F1011121314151617',
    'AES-256': '000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F',
}


def block_size(algorithm):
    if algorithm not in ALGORITHMS:
        raise ValueError('Algoritma tidak dikenal.')
    return 16 if algorithm.startswith('AES') else 8


def key_size(algorithm):
    if algorithm == 'DES': return 8
    if algorithm == '3DES': return 24
    if algorithm == 'AES-128': return 16
    if algorithm == 'AES-192': return 24
    if algorithm == 'AES-256': return 32
    raise ValueError('Algoritma tidak dikenal.')


def _validate_key(key, algorithm):
    if not isinstance(key, bytes) or len(key) != key_size(algorithm):
        n = key_size(algorithm)
        raise ValueError(f'Kunci {algorithm} harus {n} byte ({2*n} karakter HEX).')
    if algorithm == '3DES':
        des3_own._keys(key)  # menolak key K1=K2 atau K2=K3


def parse_key(text, algorithm='DES'):
    """Kunci dengan awalan hex: / text:, atau otomatis HEX bila panjang sesuai."""
    if not isinstance(text, str):
        raise ValueError('Kunci harus berupa teks.')
    n = key_size(algorithm)
    raw = text.strip()
    lowered = raw.lower()
    if lowered.startswith('hex:'):
        raw, force = raw[4:].strip(), 'hex'
    elif lowered.startswith('text:'):
        raw, force = raw[5:], 'text'
    else:
        force = 'hex' if len(raw) == n*2 else 'text'
    if force == 'hex':
        try: key = bytes.fromhex(raw)
        except ValueError as e:
            raise ValueError(f'Kunci HEX tidak valid. Gunakan tepat {n*2} karakter 0-9 / A-F.') from e
    else:
        key = raw.encode('utf-8')
    _validate_key(key, algorithm)
    return key



# Format privat Kriptofull untuk password bebas. Semua hasil tetap dapat
# ditampilkan sebagai HEX dalam TXT, tanpa menyimpan password itu sendiri.
PASSPHRASE_MAGIC = b'SLK1'
PASSPHRASE_ROUNDS = 120_000
SALT_SIZE = 16
TAG_SIZE = 16
ALGORITHM_IDS = {name: i + 1 for i, name in enumerate(ALGORITHMS)}
MODE_IDS = {'ECB': 1, 'CBC': 2, 'GCM': 3}


def _user_key_kind(text, algorithm):
    """HEX persis atau teks dengan panjang tepat -> langsung;
    password teks lainnya -> PBKDF2. Prefix hex: / text: didukung.
    """
    if not isinstance(text, str):
        raise ValueError('Kunci harus berupa teks atau HEX.')
    n = key_size(algorithm)
    text = text.strip()
    if not text:
        raise ValueError('Kunci belum diisi. Masukkan password atau kunci HEX.')
    if text.lower().startswith('hex:'):
        raw = text[4:].strip()
        kind = 'hex'
    elif text.lower().startswith('text:'):
        raw = text[5:]
        kind = 'text'
    else:
        raw = text
        kind = 'hex' if len(raw) == n * 2 and re.fullmatch(r'[0-9a-fA-F]+', raw) else 'text'
    if kind == 'hex':
        try:
            key = bytes.fromhex(raw)
        except ValueError as exc:
            raise ValueError('Kunci HEX harus berisi pasangan digit 0-9 / A-F.') from exc
        _validate_key(key, algorithm)
        return 'direct', key
    password = raw.encode('utf-8')
    if not password:
        raise ValueError('Password tidak boleh kosong.')
    if len(password) == n:
        try:
            _validate_key(password, algorithm)
            return 'direct', password
        except ValueError:
            if algorithm != '3DES':
                raise
            # Password sepanjang 24 byte yang berulang tetap boleh:
            # turunkan menjadi 3 kunci DES independen, bukan menerima kunci degenerate.
    # Bila panjang tidak pas, gunakan derivasi password dengan salt.
    return 'password', password


def _stretch_key(password, salt, algorithm):
    """Hasilkan kunci DES/3DES/AES + kunci MAC dari password yang sama."""
    if len(salt) != SALT_SIZE:
        raise ValueError('Salt password tidak valid.')
    material = hashlib.pbkdf2_hmac('sha256', password, salt, PASSPHRASE_ROUNDS,
                                   dklen=key_size(algorithm) + 32)
    key, auth = material[:key_size(algorithm)], material[key_size(algorithm):]
    _validate_key(key, algorithm)
    return key, auth


def encrypt_user_bytes(data, user_key, mode='CBC', engine='own', iv=None, algorithm='DES'):
    """Kunci HEX/kunci teks tepat ukuran: format lama. Password: amplop SLK1.

    Amplop SLK1 = magic (4) | id algoritma (1) | id mode (1) |
    salt (16) | HMAC-SHA256 potong 16 | ciphertext mode biasa.
    """
    kind, key_or_password = _user_key_kind(user_key, algorithm)
    if kind == 'direct':
        return encrypt_bytes(data, key_or_password, mode, engine, iv, algorithm)
    if algorithm == '3DES' and len(key_or_password.decode('utf-8')) < 13:
        raise ValueError('Password 3DES minimal 13 karakter. Kunci HEX 48 digit atau teks tepat 24 byte tetap diterima.')
    salt = os.urandom(SALT_SIZE)
    key, auth = _stretch_key(key_or_password, salt, algorithm)
    encrypted = encrypt_bytes(data, key, mode, engine, iv, algorithm)
    header = PASSPHRASE_MAGIC + bytes([ALGORITHM_IDS[algorithm], MODE_IDS[mode]]) + salt
    tag = hmac.new(auth, header + encrypted, hashlib.sha256).digest()[:TAG_SIZE]
    return header + tag + encrypted


def decrypt_user_bytes(raw, user_key, mode='CBC', engine='own', algorithm='DES'):
    """Mendukung ciphertext SLK1 baru serta HEX/ENC/ZAR1 lama."""
    if not isinstance(raw, bytes):
        raise TypeError('Ciphertext harus bytes.')
    kind, key_or_password = _user_key_kind(user_key, algorithm)
    if raw.startswith(PASSPHRASE_MAGIC):
        minimum = 4 + 1 + 1 + SALT_SIZE + TAG_SIZE + 1
        if len(raw) < minimum:
            raise ValueError('Ciphertext SLK1 tidak lengkap atau terpotong.')
        alg_id, mode_id = raw[4:6]
        if alg_id != ALGORITHM_IDS[algorithm]:
            raise ValueError('Algoritma tidak cocok dengan ciphertext SLK1. Ubah pilihan algoritma.')
        if mode_id != MODE_IDS[mode]:
            raise ValueError('Mode tidak cocok dengan ciphertext SLK1. Ubah ECB/CBC/GCM.')
        if kind != 'password':
            raise ValueError('Ciphertext ini dibuat memakai password teks. Gunakan password teks yang sama saat enkripsi.')
        salt = raw[6:6 + SALT_SIZE]
        header = raw[:6 + SALT_SIZE]
        signature = raw[6 + SALT_SIZE:6 + SALT_SIZE + TAG_SIZE]
        encrypted = raw[6 + SALT_SIZE + TAG_SIZE:]
        key, auth = _stretch_key(key_or_password, salt, algorithm)
        expected = hmac.new(auth, header + encrypted, hashlib.sha256).digest()[:TAG_SIZE]
        if not hmac.compare_digest(signature, expected):
            raise ValueError('Password salah atau ciphertext berubah. Gunakan password persis seperti saat enkripsi.')
        return decrypt_bytes(encrypted, key, mode, engine, algorithm)
    if kind != 'direct':
        raise ValueError('Ciphertext ini tidak memiliki metadata password SLK1. Untuk file lama, gunakan kunci HEX atau teks dengan panjang kunci asli.')
    return decrypt_bytes(raw, key_or_password, mode, engine, algorithm)



def _legacy_candidate_keys(user_key, algorithm):
    """Exact historical key representations; do not guess/derive missing secrets.

    DES 8-byte and 3DES 24-byte keys are supported as before. An additional
    interoperable 2-key 3DES variant expands 16-byte K1|K2 to K1|K2|K1.
    """
    try:
        kind, value = _user_key_kind(user_key, algorithm)
    except ValueError:
        kind, value = None, None
    if kind == 'direct':
        return [('kunci langsung', value)]

    # Two-key 3DES is E(K1) D(K2) E(K1). Do not silently truncate keys.
    if algorithm != '3DES' or not isinstance(user_key, str):
        return []
    s = user_key.strip()
    prefix = s[:5].lower()
    raw = s[5:] if prefix == 'text:' else s
    if s.lower().startswith('hex:'):
        raw = s[4:].strip()
        if not re.fullmatch(r'[0-9a-fA-F]{32}', raw):
            return []
        raw = bytes.fromhex(raw)
    elif prefix != 'text:' and re.fullmatch(r'[0-9a-fA-F]{32}', raw):
        raw = bytes.fromhex(raw)
    else:
        raw = raw.encode('utf-8')
    if len(raw) == 16:
        key = raw + raw[:8]
        try:
            _validate_key(key, '3DES')
        except ValueError:
            return []
        return [('3DES 2-kunci (16 byte)', key)]
    return []


def _plausible_text(plaintext):
    """Avoid accepting accidental valid padding as a successful auto-decrypt.

    This is only a plausibility check for text files, not cryptographic proof.
    """
    try:
        text = plaintext.decode('utf-8', errors='strict')
    except UnicodeDecodeError:
        return False
    if not text:
        return True
    return sum(ch.isprintable() or ch in '\n\r\t' for ch in text) / len(text) > .97


def decrypt_auto(raw, user_key, mode='CBC', engine='own', algorithm='DES',
                 metadata=None, expected_plaintext=None):
    """Auto-select *known* metadata or try compatible settings for legacy HEX.

    Cannot infer unknown passwords or missing PBKDF2 salts. For legacy text,
    PKCS7 plus strict UTF-8 plausibility is an indicator, never authentication.
    Optionally verify against an original file by exact byte comparison.
    """
    metadata = metadata or ciphertext_metadata(raw)
    if raw.startswith(PASSPHRASE_MAGIC):
        alg = metadata['algorithm']
        detected_mode = metadata['mode']
        out = decrypt_user_bytes(raw, user_key, detected_mode,
                                 ('library' if alg.startswith('AES') else engine), alg)
        return out, {'algorithm': alg, 'mode': detected_mode,
                     'key_type': 'password SLK1', 'confidence': 'terautentikasi'}

    # A format header narrows the algorithm/mode; no need to try other ones.
    tagged_alg = metadata.get('algorithm')
    tagged_mode = metadata.get('mode')
    algs = [tagged_alg] if tagged_alg else list(dict.fromkeys([algorithm, '3DES', 'DES', 'AES-128', 'AES-192', 'AES-256']))
    candidates = []
    for alg in algs:
        if alg not in ALGORITHMS:
            continue
        possible_modes = [tagged_mode] if tagged_mode else list(dict.fromkeys([mode, 'CBC', 'ECB'] + (['GCM'] if alg.startswith('AES') else [])))
        if tagged_mode == 'GCM' and not alg.startswith('AES'):
            continue
        for candidate_mode in possible_modes:
            if candidate_mode not in ('ECB','CBC') and not alg.startswith('AES'):
                continue
            for key_type, key in _legacy_candidate_keys(user_key, alg):
                candidates.append((alg, candidate_mode, key_type, key))

    # First valid candidate in preference order, but reject ambiguous plaintexts.
    successes = []
    for alg, candidate_mode, key_type, key in candidates:
        try:
            used_engine = 'library' if alg.startswith('AES') else engine
            text = decrypt_bytes(raw, key, candidate_mode, used_engine, alg)
        except (ValueError, RuntimeError):
            continue
        if expected_plaintext is not None:
            if text != expected_plaintext:
                continue
        elif not _plausible_text(text):
            continue
        successes.append((text, alg, candidate_mode, key_type))
        # If unambiguous metadata and a valid plaintext were found we are done.
        if tagged_alg and tagged_mode:
            break

    # Wrong CBC vs ECB can both produce valid padding in some cases; prefer
    # readable, unambiguous results, never silently present multiple answers.
    uniq = {}
    for item in successes:
        uniq.setdefault(item[0], item)
    if len(uniq) == 1:
        out, alg, actual_mode, key_type = next(iter(uniq.values()))
        confidence = ('identik dengan file asli' if expected_plaintext is not None
                      else 'perkiraan valid (tanpa autentikasi)')
        return out, {'algorithm':alg, 'mode':actual_mode,
                     'key_type':key_type, 'confidence':confidence}
    if len(uniq) > 1:
        raise ValueError('Beberapa hasil dekripsi terlihat valid. Pilih algoritma/mode yang tepat atau unggah file asli untuk verifikasi.')
    raise ValueError('Dekripsi otomatis belum menemukan plaintext valid. File HEX lama tidak menyimpan algoritma, mode, atau password. Pastikan kunci yang SAMA persis dengan pembuat file; password baru tidak dapat memulihkan ciphertext lama yang dibuat dengan kunci berbeda atau salt yang hilang. Untuk format 3DES lama, program juga mencoba kunci teks 16 byte (2-key 3DES).')

def derive_analysis_key(user_key, algorithm):
    """Kunci uji sementara: sama untuk dua engine/trace, bukan salt file nyata."""
    kind, key_or_password = _user_key_kind(user_key, algorithm)
    if kind == 'direct':
        return key_or_password, False
    salt = b'KriptofullTrace!'  # 16 byte, hanya untuk visualisasi/perbandingan
    key, _ = _stretch_key(key_or_password, salt, algorithm)
    return key, True


def parse_ciphertext_hex(value):
    """Terima teks HEX dengan spasi, newline, dan prefiks opsional 0x/HEX:."""
    value = value.strip()
    if value.lower().startswith('hex:'):
        value = value[4:].strip()
    if value.lower().startswith('0x'):
        value = value[2:]
    value = ''.join(value.split())
    if not value:
        raise ValueError('Ciphertext kosong. Enkripsi teks terlebih dahulu, lalu klik Dekripsi.')
    if not re.fullmatch(r'[0-9a-fA-F]+', value):
        raise ValueError('Input dekripsi harus berupa CIPHERTEXT HEX, bukan plaintext. Klik Enkripsi dahulu, lalu Dekripsi langsung (otomatis mengambil hasil enkripsi), atau tempel HEX ciphertext ke kolom input.')
    if len(value) % 2:
        raise ValueError('Ciphertext HEX memiliki jumlah karakter ganjil. Pastikan hasil enkripsi tidak terpotong.')
    return bytes.fromhex(value)



def _from_url_b64(payload, format_name):
    if not payload or not re.fullmatch(r'[A-Za-z0-9_-]+={0,2}', payload):
        raise ValueError(f'Payload {format_name} harus berupa Base64 URL-safe yang valid.')
    try:
        payload = payload + '=' * ((-len(payload)) % 4)
        return base64.b64decode(payload, altchars=b'-_', validate=True)
    except (binascii.Error, ValueError) as exc:
        raise ValueError(f'Payload {format_name} rusak atau terpotong.') from exc


def ciphertext_metadata(raw, annotated_algorithm=None, text=None):
    """(algorithm, mode, encoding) bila metadata tersedia, bukan hasil menebak kunci."""
    algorithm, mode, encoding = annotated_algorithm, None, 'HEX'
    if isinstance(text, (str, bytes)):
        if isinstance(text, bytes):
            text = text[:100].decode('utf-8', errors='ignore')
        prefix = text.strip().upper()
        if prefix.startswith('ZAR1:'):
            encoding, mode = 'ZAR1', 'CBC'
        elif prefix.startswith('B64:'):
            encoding = 'B64'
            parts = text.strip().split(':', 3)
            if len(parts) == 4:
                algorithm, mode = parts[1].upper(), parts[2].upper()
        elif prefix.startswith('SLK1:'):
            encoding = 'SLK1'
    if raw.startswith(PASSPHRASE_MAGIC):
        if len(raw) < 38:
            raise ValueError('Ciphertext SLK1 tidak lengkap.')
        algorithms = {v:k for k,v in ALGORITHM_IDS.items()}
        modes = {v:k for k,v in MODE_IDS.items()}
        algorithm = algorithms.get(raw[4]);mode = modes.get(raw[5])
        if not algorithm or not mode:
            raise ValueError('Metadata algoritma atau mode SLK1 rusak.')
        if encoding == 'HEX':encoding = 'SLK1 (HEX)'
    return dict(algorithm=algorithm, mode=mode, format=encoding, password_envelope=raw.startswith(PASSPHRASE_MAGIC))


def encode_ciphertext(raw, algorithm, mode, export_format='HEX'):
    """Empat pilihan TXT; tidak mengubah ciphertext biner yang akan didekripsi."""
    fmt = export_format.strip().upper()
    if fmt == 'HEX':return raw.hex().upper().encode('ascii')
    content = base64.urlsafe_b64encode(raw).decode('ascii').rstrip('=')
    if fmt == 'ZAR1':
        if algorithm not in ('DES', '3DES') or mode != 'CBC':
            raise ValueError('Format ZAR1 hanya untuk DES/3DES mode CBC. Pilih HEX atau B64 untuk mode lain.')
        return f'ZAR1:{algorithm}:{content}'.encode('ascii')
    if fmt == 'SLK1':
        if not raw.startswith(PASSPHRASE_MAGIC):
            raise ValueError('Format SLK1 hanya untuk enkripsi memakai password turunan. Kunci langsung gunakan HEX, B64, atau ZAR1.')
        return f'SLK1:{content}'.encode('ascii')
    if fmt == 'B64':return f'B64:{algorithm}:{mode}:{content}'.encode('ascii')
    raise ValueError('Pilih format TXT: HEX, ZAR1, SLK1 atau B64.')


def decode_input(raw_or_text, input_format='AUTO'):
    fmt = input_format.upper()
    if fmt not in ('AUTO','HEX','ZAR1','SLK1','B64','BIN'):
        raise ValueError('Format ciphertext tidak dikenali.')
    raw, annotated_alg = parse_ciphertext_input(raw_or_text)
    metadata = ciphertext_metadata(raw, annotated_alg, raw_or_text)
    if fmt != 'AUTO':
        seen = metadata['format']
        if fmt == 'SLK1' and not metadata['password_envelope']:
            raise ValueError('Berkas ini bukan ciphertext password SLK1.')
        if fmt == 'ZAR1' and seen != 'ZAR1':
            raise ValueError('Berkas ini tidak berawalan ZAR1.')
        if fmt == 'B64' and seen != 'B64':
            raise ValueError('Berkas ini tidak berawalan B64.')
        if fmt == 'HEX' and seen not in ('HEX','SLK1 (HEX)'):
            raise ValueError('Berkas ini bukan ciphertext HEX.')
        if fmt == 'BIN' and isinstance(raw_or_text, str):
            raise ValueError('Format BIN memerlukan file biner .enc.')
    return raw, metadata


def parse_ciphertext_input(value, algorithm=None):
    """Baca ciphertext HEX Kriptofull atau format TXT interoperabilitas ZAR1.

    Format ZAR1:DES:<base64url> mewakili byte (IV 8-byte || CBC ciphertext).
    Format ZAR1 bukan hex dan tidak mengandung kunci. Pengguna tetap perlu
    menyediakan kunci yang sama dan mode operasi yang kompatibel.

    Menerima bytes untuk file .enc (biner mentah) atau teks file .txt.
    """
    if isinstance(value, bytes):
        if value.startswith(PASSPHRASE_MAGIC) and not value.startswith(b'SLK1:'):
            return value, None
        try:
            text = value.decode('utf-8-sig').strip()
        except UnicodeDecodeError:
            return value, None  # file .enc biner Kriptofull
    elif isinstance(value, str):
        text = value.strip().lstrip('\ufeff')
    else:
        raise TypeError('Ciphertext harus berupa teks atau bytes.')

    if text.upper().startswith('SLK1:'):
        decoded = _from_url_b64(text.split(':', 1)[1], 'SLK1')
        if not decoded.startswith(PASSPHRASE_MAGIC):
            raise ValueError('Konten SLK1 tidak memuat header password yang valid.')
        return decoded, None

    if text.upper().startswith('B64:'):
        parts = text.split(':',3)
        if len(parts) != 4 or parts[1].upper() not in ALGORITHMS or parts[2].upper() not in MODES:
            raise ValueError('Format B64 harus B64:ALGORITMA:MODE:BASE64URL.')
        if algorithm is not None and parts[1].upper() != algorithm:
            raise ValueError(f'File menggunakan {parts[1].upper()}, bukan {algorithm}.')
        return _from_url_b64(parts[3], 'B64'), parts[1].upper()

    if text.startswith('ZAR1:'):
        parts = text.split(':', 2)
        if len(parts) != 3:
            raise ValueError('Format ZAR1 tidak lengkap. Diperlukan ZAR1:ALGORITMA:BASE64URL.')
        _, cipher_alg, payload = parts
        cipher_alg = cipher_alg.upper()
        if cipher_alg not in ALGORITHMS:
            raise ValueError(f'Algoritma pada ZAR1 tidak dikenal: {cipher_alg}.')
        if algorithm is not None and cipher_alg != algorithm:
            raise ValueError(f'File memakai {cipher_alg}, tetapi algoritma yang dipilih {algorithm}. Ubah pilihan algoritma.')
        decoded = _from_url_b64(payload, 'ZAR1')
        return decoded, cipher_alg

    if isinstance(value, bytes):
        # File biner berisi byte acak dapat saja ASCII-valid; periksa pola HEX
        # sebelum memutuskan bahwa itu teks, bukan ciphertext mentah.
        if re.fullmatch(r'(?:HEX:|0x)?[\s0-9a-fA-F]+', text, flags=re.I):
            return parse_ciphertext_hex(text), None
        return value, None
    return parse_ciphertext_hex(text), None


def pad(data, size=8):
    n = size - (len(data) % size)
    return data + bytes([n]) * n


def unpad(data, size=8):
    if not data or len(data) % size:
        raise ValueError('Ciphertext atau mode operasi tidak sesuai (panjang blok tidak valid).')
    n = data[-1]
    if n < 1 or n > size or data[-n:] != bytes([n]) * n:
        raise ValueError('Padding tidak valid. Periksa algoritma, kunci, mode, dan ciphertext.')
    return data[:-n]


def _xor(a, b):
    return bytes(x ^ y for x, y in zip(a, b))


def _load_crypto():
    try:
        from Crypto.Cipher import DES, DES3, AES
    except ImportError as e:
        raise RuntimeError('PyCryptodome belum terpasang. Di terminal jalankan: python -m pip install -r requirements.txt') from e
    return DES, DES3, AES


def _check(mode, engine, algorithm):
    if algorithm not in ALGORITHMS:
        raise ValueError('Pilih algoritma yang tersedia.')
    if engine not in ENGINES:
        raise ValueError('Implementasi harus Buatan Sendiri atau Library Crypto.')
    if mode not in MODES:
        raise ValueError('Mode harus ECB, CBC atau GCM.')
    if algorithm.startswith('AES') and engine != 'library':
        raise ValueError('AES hanya tersedia dengan implementasi library Crypto. Implementasi Feistel sendiri hanya DES dan 3DES.')
    if mode == 'GCM' and not algorithm.startswith('AES'):
        raise ValueError('Mode GCM hanya tersedia untuk AES.')


def _block_ops(key, algorithm, engine):
    _validate_key(key, algorithm)
    if engine == 'own':
        if algorithm == 'DES':
            rk = des_own.generate_round_keys(key)
            return (lambda x: des_own._crypt_block(x, rk),
                    lambda x: des_own._crypt_block(x, rk[::-1]))
        triple = des3_own.TripleDES(key)
        return triple.encrypt, triple.decrypt
    DES, DES3, AES = _load_crypto()
    module = AES if algorithm.startswith('AES') else DES if algorithm == 'DES' else DES3
    try:
        cipher_encrypt = module.new(key, module.MODE_ECB)
        cipher_decrypt = module.new(key, module.MODE_ECB)
    except ValueError as e:
        raise ValueError(f'Kunci {algorithm} ditolak oleh library: {e}') from e
    return cipher_encrypt.encrypt, cipher_decrypt.decrypt


def encrypt_bytes(data, key, mode='CBC', engine='own', iv=None, algorithm='DES'):
    """ECB=ct, CBC=IV||ct, AES-GCM=nonce||tag||ct."""
    _check(mode, engine, algorithm)
    if not isinstance(data, bytes):
        raise TypeError('Data harus bytes.')
    _validate_key(key, algorithm)
    size = block_size(algorithm)
    if mode == 'GCM':
        _, _, AES = _load_crypto()
        nonce = os.urandom(12) if iv is None else iv
        if not isinstance(nonce, bytes) or len(nonce) != 12:
            raise ValueError('Nonce AES-GCM harus tepat 12 byte / 24 digit HEX.')
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        ciphertext, tag = cipher.encrypt_and_digest(data)
        return nonce + tag + ciphertext
    enc, _ = _block_ops(key, algorithm, engine)
    data = pad(data, size)
    if mode == 'ECB':
        return b''.join(enc(data[i:i+size]) for i in range(0, len(data), size))
    iv = os.urandom(size) if iv is None else iv
    if not isinstance(iv, bytes) or len(iv) != size:
        raise ValueError(f'IV CBC untuk {algorithm} harus {size} byte / {2*size} digit HEX.')
    out = bytearray(iv)
    previous = iv
    for i in range(0, len(data), size):
        previous = enc(_xor(data[i:i+size], previous))
        out.extend(previous)
    return bytes(out)


def decrypt_bytes(raw, key, mode='CBC', engine='own', algorithm='DES'):
    _check(mode, engine, algorithm)
    if not isinstance(raw, bytes):
        raise TypeError('Ciphertext harus bytes.')
    _validate_key(key, algorithm)
    size = block_size(algorithm)
    if mode == 'GCM':
        if len(raw) < 28:
            raise ValueError('Ciphertext GCM harus memuat nonce 12 byte + tag 16 byte.')
        nonce, tag, ct = raw[:12], raw[12:28], raw[28:]
        _, _, AES = _load_crypto()
        try:
            return AES.new(key, AES.MODE_GCM, nonce=nonce).decrypt_and_verify(ct, tag)
        except ValueError as e:
            raise ValueError('Autentikasi GCM gagal. Kunci atau ciphertext salah/berubah.') from e
    _, dec = _block_ops(key, algorithm, engine)
    if mode == 'ECB':
        if not raw or len(raw) % size:
            raise ValueError(f'Ciphertext ECB harus berupa kelipatan {size} byte.')
        return unpad(b''.join(dec(raw[i:i+size]) for i in range(0, len(raw), size)), size)
    if len(raw) < 2*size or len(raw) % size:
        raise ValueError(f'Ciphertext CBC harus memuat IV {size} byte dan setidaknya satu blok ciphertext.')
    previous, ct = raw[:size], raw[size:]
    out = bytearray()
    for i in range(0, len(ct), size):
        c = ct[i:i+size]
        out.extend(_xor(dec(c), previous))
        previous = c
    return unpad(bytes(out), size)


def _ensure_distinct_files(src, dst):
    if os.path.abspath(src) == os.path.abspath(dst):
        raise ValueError('Sumber dan tujuan harus berbeda agar file asli tidak tertimpa.')


def encrypt_file(src, dst, key, mode='CBC', engine='own', iv=None, algorithm='DES'):
    _ensure_distinct_files(src, dst)
    data = Path(src).read_bytes()
    result = encrypt_bytes(data, key, mode, engine, iv, algorithm)
    Path(dst).write_bytes(result)
    return len(data), len(result)


def decrypt_file(src, dst, key, mode='CBC', engine='own', algorithm='DES'):
    _ensure_distinct_files(src, dst)
    data = Path(src).read_bytes()
    result = decrypt_bytes(data, key, mode, engine, algorithm)
    Path(dst).write_bytes(result)
    return len(data), len(result)


def files_identical(a, b):
    return Path(a).read_bytes() == Path(b).read_bytes()
