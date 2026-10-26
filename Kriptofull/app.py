
from __future__ import annotations

import base64
import hashlib
import json
import mimetypes
import os
from pathlib import Path
import threading
import time
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse

import compare
import des_own
import des3_own
import file_crypto as fc

ROOT = Path(__file__).resolve().parent
STATIC = ROOT / 'static'
SAMPLES = ROOT / 'contoh'
MAX_BODY = 12 * 1024 * 1024


def b64_encode(data):
    return base64.b64encode(data).decode('ascii')


def b64_decode(data):
    if not isinstance(data, str):
        raise ValueError('File harus diberikan dalam format Base64.')
    import binascii
    try:
        return base64.b64decode(data, validate=True)
    except (binascii.Error, ValueError) as e:
        raise ValueError('Data Base64 file tidak valid.') from e


def params(payload):
    algorithm = payload.get('algorithm', 'DES')
    mode = payload.get('mode', 'CBC')
    engine = payload.get('engine', 'own')
    key = str(payload.get('key', fc.KEY_EXAMPLES.get(algorithm, '')))
    iv_text = str(payload.get('iv', '')).strip()
    iv = bytes.fromhex(iv_text) if iv_text else None
    return algorithm, mode, engine, key, iv


def decode_cipher_input(value, algorithm, mode, input_format='AUTO'):
    raw, meta = fc.decode_input(value, input_format)
    selected_alg = meta['algorithm'] or algorithm
    selected_mode = meta['mode'] or mode
    if meta['algorithm'] and meta['algorithm'] != algorithm:
        # Header modern terpercaya untuk memilih parameter cipher tanpa menebak.
        algorithm = meta['algorithm']
    if meta['mode'] and meta['mode'] != mode:
        mode = meta['mode']
    return raw, algorithm, mode, meta


def do_process(data):
    algorithm, mode, engine, key, iv = params(data)
    action = data.get('action', 'encrypt')
    source = str(data.get('text', ''))
    export_format = str(data.get('export_format', 'HEX')).upper()
    start = time.perf_counter()
    detected = None
    if action == 'encrypt':
        plaintext = source.encode('utf-8')
        if not plaintext:
            raise ValueError('Masukkan plaintext atau pilih file .txt.')
        encrypted = fc.encrypt_user_bytes(plaintext, key, mode, engine, iv, algorithm)
        result = fc.encode_ciphertext(encrypted, algorithm, mode, export_format).decode('ascii')
        input_size, output_size = len(plaintext), len(encrypted)
        download = b64_encode(result.encode('ascii'))
        file_name = f'ciphertext_{algorithm.replace("-", "")}_{export_format}.txt'
        meta = fc.ciphertext_metadata(encrypted)
    elif action == 'decrypt':
        encrypted, algorithm, mode, meta = decode_cipher_input(source, algorithm, mode, str(data.get('input_format','AUTO')))
        plaintext, detected = fc.decrypt_auto(encrypted, key, mode, engine, algorithm, meta)
        algorithm, mode = detected['algorithm'], detected['mode']
        try:
            result = plaintext.decode('utf-8')
        except UnicodeDecodeError as e:
            raise ValueError('Hasil bukan teks UTF-8. Periksa password/kunci, mode dan ciphertext.') from e
        input_size, output_size = len(encrypted), len(plaintext)
        download = b64_encode(plaintext)
        file_name = 'plaintext_pulih.txt'
    else:
        raise ValueError('Aksi tidak dikenal.')
    return dict(result=result, duration_ms=round((time.perf_counter() - start)*1000, 3),
                input_size=input_size, output_size=output_size, download=download, name=file_name,
                algorithm=algorithm, mode=mode, engine=engine, format=(export_format if action=='encrypt' else meta['format']),
                confidence=(detected['confidence'] if detected else ''),
                key_type=(detected['key_type'] if detected else ''))


def do_file(data):
    alg, mode, engine, key, iv = params(data)
    action = data.get('action', 'encrypt')
    src = b64_decode(data.get('file_data', ''))
    filename = Path(str(data.get('filename', 'dokumen.txt'))).name
    if not src:
        raise ValueError('File kosong.')
    start = time.perf_counter()
    detected = None
    if action == 'encrypt':
        ciphertext = fc.encrypt_user_bytes(src, key, mode, engine, iv, alg)
        fmt = str(data.get('export_format', 'HEX')).upper()
        output = fc.encode_ciphertext(ciphertext, alg, mode, fmt)
        outname = filename.rsplit('.', 1)[0] + f'_{alg.replace("-", "")}_{fmt}_terenkripsi.txt'
        preview = output[:700].decode('ascii')
        if data.get('verify', False):
            recovered = fc.decrypt_user_bytes(ciphertext, key, mode, engine, alg)
            ident = recovered == src
            digest = hashlib.sha256(recovered).hexdigest()
            original_digest = hashlib.sha256(src).hexdigest()
            recovered_base64 = b64_encode(recovered)
            recovered_name = filename.rsplit('.', 1)[0] + '_pulih.txt'
        else:
            ident = None
            digest = original_digest = recovered_base64 = recovered_name = None
        cipher_input_format = fmt
    elif action == 'decrypt':
        raw, meta = fc.decode_input(src, str(data.get('input_format', 'AUTO')))
        alg = meta['algorithm'] or alg
        mode = meta['mode'] or mode
        # ZAR1 lama tanpa SLK1 metadata selalu CBC.
        original = data.get('original_data')
        expected = b64_decode(original) if original else None
        output, detected = fc.decrypt_auto(raw, key, mode, engine, alg, meta,
                                           expected_plaintext=expected)
        alg, mode = detected['algorithm'], detected['mode']
        outname = filename.rsplit('.', 1)[0] + '_pulih.txt'
        preview = output[:2000].decode('utf-8', errors='replace')
        ident = output == expected if expected is not None else None
        digest = hashlib.sha256(output).hexdigest()
        original_digest = hashlib.sha256(b64_decode(original)).hexdigest() if original else None
        recovered_base64 = recovered_name = None
        cipher_input_format = meta['format']
    else:
        raise ValueError('Aksi tidak dikenal.')
    return dict(name=outname, output=b64_encode(output), size_in=len(src), size_out=len(output),
                duration_ms=round((time.perf_counter()-start)*1000, 3), preview=preview,
                identical=ident, sha256=digest, original_sha256=original_digest,
                recovered_data=recovered_base64, recovered_name=recovered_name,
                algorithm=alg, mode=mode, engine=engine, format=cipher_input_format,
                confidence=(detected['confidence'] if detected else ''),
                key_type=(detected['key_type'] if detected else ''))


def do_convert(data):
    """Ubah bungkus teks ciphertext tanpa mengubah byte terenkripsinya."""
    file_data = b64_decode(data.get('file_data', ''))
    if not file_data:
        raise ValueError('Pilih file ciphertext untuk dikonversi.')
    raw, meta = fc.decode_input(file_data)
    algorithm = meta['algorithm'] or data.get('algorithm', 'DES')
    mode = meta['mode'] or data.get('mode', 'CBC')
    fmt = str(data.get('export_format', 'HEX')).upper()
    content = fc.encode_ciphertext(raw, algorithm, mode, fmt)
    filename = Path(str(data.get('filename', 'ciphertext.txt'))).stem
    return dict(output=b64_encode(content),name=f'{filename}_{fmt}.txt',
                export_format=fmt,algorithm=algorithm,mode=mode,size=len(content))


def do_compare(data):
    alg, mode, _engine, key, iv = params({**data, 'engine': 'own'})
    if alg not in ('DES', '3DES'):
        raise ValueError('Perbandingan buatan sendiri vs Crypto tersedia untuk DES dan 3DES.')
    plaintext = b64_decode(data['file_data']) if data.get('file_data') else str(data.get('text', '')).encode('utf-8')
    if not plaintext:
        raise ValueError('Masukkan teks atau pilih file untuk dibandingkan.')
    if mode == 'GCM':
        raise ValueError('Mode GCM bukan mode DES/3DES.')
    if mode == 'CBC' and iv is None:
        iv = bytes.fromhex('0001020304050607')
    key, key_derived = fc.derive_analysis_key(key, alg)
    start = time.perf_counter()
    a = fc.encrypt_bytes(plaintext, key, mode, 'own', iv, alg)
    t1 = time.perf_counter()
    b = fc.encrypt_bytes(plaintext, key, mode, 'library', iv, alg)
    t2 = time.perf_counter()
    cross = fc.decrypt_bytes(b, key, mode, 'own', alg) == fc.decrypt_bytes(a, key, mode, 'library', alg) == plaintext
    return dict(identical=(a == b), cross_decryption=cross, input_size=len(plaintext),
                padded_size=len(fc.pad(plaintext, 8)), output_size=len(a),
                ciphertext_head=a.hex().upper()[:128], own_ms=round((t1-start)*1000, 3),
                library_ms=round((t2-t1)*1000, 3), algorithm=alg, mode=mode,
                derived_key=key_derived)


def do_trace(data):
    alg, _mode, _engine, key, _iv = params({**data, 'engine': 'own'})
    if alg not in ('DES', '3DES'):
        raise ValueError('Feistel tersedia untuk DES dan 3DES saja.')
    if data.get('raw_hex'):
        plain = fc.parse_ciphertext_hex(data.get('text', ''))
    elif data.get('file_data'):
        plain = b64_decode(data['file_data'])
    else:
        plain = str(data.get('text','')).encode('utf-8')
    padded = fc.pad(plain, 8)
    try:
        index = int(data.get('index', 1))
    except (ValueError, TypeError) as e:
        raise ValueError('Nomor blok tidak valid.') from e
    n = len(padded) // 8
    if index < 1 or index > n:
        raise ValueError(f'Pilih blok antara 1 dan {n}.')
    block = padded[(index-1)*8:index*8]
    key, key_derived = fc.derive_analysis_key(key, alg)
    traces = []
    if alg == 'DES':
        stage = [('DES E(K)', block, key, False)]
    else:
        c1 = des_own.encrypt_block(block, key[:8]); c2 = des_own.decrypt_block(c1, key[8:16])
        stage = [('DES E(K1)', block, key[:8], False), ('DES D(K2)', c1, key[8:16], True),
                 ('DES E(K3)', c2, key[16:24], False)]
    for title, incoming, part_key, decrypt in stage:
        output, rows = des_own.trace_block(incoming, part_key, decrypt=decrypt)
        detailed = []
        for j in range(1, len(rows)):
            i, subkey, left, right, f = rows[j]
            prev_left = rows[j-1][2]
            detailed.append({'round': i, 'subkey': f'{subkey:012X}', 'l':f'{left:08X}',
                             'r':f'{right:08X}', 'f':f'{f:08X}', 'xor': f'{prev_left:08X} ⊕ {f:08X} = {right:08X}'})
        traces.append(dict(title=title, input=incoming.hex().upper(), output=output.hex().upper(), rows=detailed))
    end = traces[-1]['output']
    expected = des_own.encrypt_block(block, key) if alg == 'DES' else des3_own.encrypt_block(block, key)
    assert end == expected.hex().upper()
    return dict(algorithm=alg, total_bytes=len(plain), total_blocks=n, block_index=index,
                block_hex=block.hex().upper(), ciphertext=end, traces=traces,
                derived_key=key_derived)


def do_tests(_data):
    cases = []
    key = bytes.fromhex(fc.KEY_EXAMPLES['DES'])
    p = bytes.fromhex('0123456789ABCDEF')
    a = des_own.encrypt_block(p,key).hex().upper()
    cases.append(dict(name='Vektor uji standar DES', ok=a=='85E813540F0AB405', detail=a))
    for alg in ('DES','3DES'):
        k = fc.parse_key(fc.KEY_EXAMPLES[alg], alg)
        for mode in ('ECB','CBC'):
            for label, plain in [('Pendek',b'saya'),('Tepat blok',b'12345678'),('Teks UTF-8','dokumen contoh\nBaris — tanda baca!?'.encode())]:
                try:
                    ct=fc.encrypt_bytes(plain,k,mode,'own',algorithm=alg)
                    restored=fc.decrypt_bytes(ct,k,mode,'own',alg)
                    ok=restored==plain
                    cases.append(dict(name=f'{alg} {mode} {label}',ok=ok,detail=f'{len(plain)} byte → {len(ct)} byte'))
                except Exception as exc:
                    cases.append(dict(name=f'{alg} {mode} {label}',ok=False,detail=str(exc)))
    try:
        ok, detail = compare.cek_vektor_uji()
        cases.append(dict(name='Banding DES dengan Crypto',ok=ok,detail=detail[:150]))
    except (ImportError,RuntimeError):
        cases.append(dict(name='Banding DES dengan Crypto',ok=None,detail='PyCryptodome belum terpasang'))
    return dict(cases=cases,passed=sum(x['ok'] is True for x in cases),
                failed=sum(x['ok'] is False for x in cases), skipped=sum(x['ok'] is None for x in cases))


API = {'/api/process':do_process, '/api/file':do_file, '/api/compare':do_compare,
       '/api/feistel':do_trace, '/api/tests':do_tests, '/api/convert':do_convert}


class Handler(BaseHTTPRequestHandler):
    server_version = 'KriptofullLocal/1.0'
    def log_message(self, format, *args):
        if args and args[1:2] == ('200',):return
        super().log_message(format,*args)

    def json_result(self, obj, code=200):
        binary=json.dumps(obj,ensure_ascii=False).encode('utf-8')
        self.send_response(code);self.send_header('Content-Type','application/json; charset=utf-8')
        self.send_header('Content-Length',str(len(binary)));self.send_header('Cache-Control','no-store')
        self.send_header('X-Content-Type-Options','nosniff');self.end_headers();self.wfile.write(binary)

    def do_GET(self):
        path=urlparse(self.path).path
        if path == '/api/config':
            return self.json_result(dict(algorithms=fc.ALGORITHMS, modes=fc.MODES, keys=fc.KEY_EXAMPLES,
                                         block_sizes={'DES':8,'3DES':8,'AES-128':16,'AES-192':16,'AES-256':16}))
        if path == '/api/sample/cipher':
            name = 'contoh_ciphertext_zar1.txt'
            # Contoh interaktif dibuat dari plaintext netral, bukan ciphertext milik pihak lain.
            example_key = fc.KEY_EXAMPLES['DES']
            source = (SAMPLES / 'pesan_contoh.txt').read_bytes()
            binary = fc.encrypt_user_bytes(source, example_key, 'CBC', 'own', algorithm='DES')
            data = fc.encode_ciphertext(binary, 'DES', 'CBC', 'ZAR1')
            return self.json_result(dict(name=name, base64=b64_encode(data), bytes=len(data),
                                         example_key=example_key))
        if path in ('/api/sample/1','/api/sample/2'):
            name='pesan_contoh.txt' if path.endswith('1') else 'dokumen_contoh.txt'
            data=(SAMPLES/name).read_bytes()
            return self.json_result(dict(name=name, base64=b64_encode(data),text=data.decode('utf-8',errors='replace'),bytes=len(data)))
        if path=='/':path='/index.html'
        mapped={'/index.html':'index.html','/style.css':'style.css','/script.js':'script.js',
                '/assets/logo_nav.png':'../assets/logo_nav.png', '/assets/logo_window.png':'../assets/logo_window.png'}
        if path not in mapped:
            return self.send_error(404,'File not found')
        candidate=(STATIC/mapped[path]).resolve()
        if not candidate.is_file() or not str(candidate).startswith(str(ROOT)):
            return self.send_error(404,'File not found')
        data=candidate.read_bytes();content=mimetypes.guess_type(str(candidate))[0] or 'application/octet-stream'
        if candidate.suffix in ('.html','.css','.js'):content+='; charset=utf-8'
        self.send_response(200);self.send_header('Content-Type',content);self.send_header('Content-Length',str(len(data)))
        self.send_header('X-Content-Type-Options','nosniff');self.end_headers();self.wfile.write(data)

    def do_POST(self):
        path=urlparse(self.path).path
        if path not in API: return self.send_error(404,'API not found')
        try:
            length=int(self.headers.get('Content-Length','0'))
            if length<1 or length>MAX_BODY:raise ValueError('Data terlalu besar (maks 9 MB file).')
            data=json.loads(self.rfile.read(length).decode('utf-8'))
            if not isinstance(data,dict): raise ValueError('Data harus berupa objek JSON.')
            result=API[path](data)
            return self.json_result(dict(ok=True,**result))
        except (ValueError,UnicodeError,RuntimeError,FileNotFoundError,ImportError) as e:
            return self.json_result({'ok':False,'error':str(e)},400)
        except Exception as e:
            print('Kesalahan internal API:',type(e).__name__,str(e))
            return self.json_result({'ok':False,'error':'Terjadi kesalahan internal aplikasi.'},500)


def main(open_browser=True):
    host='127.0.0.1'
    port=int(os.environ.get('KRIPTOFULL_PORT','5000'))
    try:
        server=ThreadingHTTPServer((host,port),Handler)
    except OSError as e:
        print(f'Port {port} sedang digunakan. Tutup Kriptofull lain atau set KRIPTOFULL_PORT. Detail: {e}')
        return
    url=f'http://{host}:{port}'
    print('=' * 55)
    print('Kriptofull | GUI Browser Lokal')
    print('Buka:',url)
    print('Tekan Ctrl+C untuk menghentikan program.')
    print('=' * 55)
    if open_browser and os.environ.get('KRIPTOFULL_NO_BROWSER')!='1':
        threading.Timer(0.9,lambda:webbrowser.open(url)).start()
    try:server.serve_forever(poll_interval=.2)
    except KeyboardInterrupt:pass
    finally:server.server_close()


if __name__=='__main__':main()
