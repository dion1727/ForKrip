"""Uji kompatibilitas DES/3DES Feistel buatan sendiri vs PyCryptodome."""
import os
import file_crypto as fc
import des_own
import des3_own

VEKTOR_KUNCI = fc.KEY_EXAMPLES['DES']
VEKTOR_PLAIN = '0123456789ABCDEF'
VEKTOR_CIPHER = '85E813540F0AB405'


def cek_vektor_uji():
    k = bytes.fromhex(VEKTOR_KUNCI)
    p = bytes.fromhex(VEKTOR_PLAIN)
    own = des_own.encrypt_block(p, k)
    own_dec = des_own.decrypt_block(own, k)
    from Crypto.Cipher import DES
    lib = DES.new(k, DES.MODE_ECB).encrypt(p)
    ok = own == lib == bytes.fromhex(VEKTOR_CIPHER) and own_dec == p
    return ok, (f'Plaintext : {VEKTOR_PLAIN}\nKunci     : {VEKTOR_KUNCI}\n'
                f'Cipher own: {own.hex().upper()}\nCipher lib: {lib.hex().upper()}\n'
                f'Dekripsi sendiri: {own_dec.hex().upper()}')


def cek_blok_acak(jumlah=30):
    from Crypto.Cipher import DES, DES3
    for algorithm in ('DES', '3DES'):
        for _ in range(jumlah):
            k = os.urandom(8) if algorithm == 'DES' else fc.parse_key(fc.KEY_EXAMPLES['3DES'], '3DES')
            p = os.urandom(8)
            if algorithm == 'DES':
                a = des_own.encrypt_block(p, k)
                b = DES.new(k, DES.MODE_ECB).encrypt(p)
                d = des_own.decrypt_block(b, k)
            else:
                a = des3_own.encrypt_block(p, k)
                b = DES3.new(k, DES3.MODE_ECB).encrypt(p)
                d = des3_own.decrypt_block(b, k)
            if a != b or d != p:
                return False, f'Gagal: {algorithm}, k={k.hex()}, p={p.hex()}'
    return True, f'{jumlah} blok DES + {jumlah} blok 3DES identik dengan library.'


def cek_file(teks='kriptografi', mode='CBC', kunci=VEKTOR_KUNCI, algorithm='DES'):
    k = fc.parse_key(kunci, algorithm)
    data = teks.encode('utf-8')
    iv = bytes.fromhex('0001020304050607')
    a = fc.encrypt_bytes(data, k, mode, 'own', iv, algorithm)
    b = fc.encrypt_bytes(data, k, mode, 'library', iv, algorithm)
    decr_own = fc.decrypt_bytes(b, k, mode, 'own', algorithm)
    decr_lib = fc.decrypt_bytes(a, k, mode, 'library', algorithm)
    ok = (a == b and decr_own == decr_lib == data)
    sample = a.hex().upper()
    if len(sample) > 160:
        sample = sample[:160] + f'... [total {len(a)} byte]'
    return ok, (f'Algoritma: {algorithm} | Mode: {mode}\n'
                f'Plaintext: {len(data)} byte | padded: {len(fc.pad(data))} byte\n'
                f'Ciphertext: {len(a)} byte\n'
                f'Ciphertext (HEX, potongan): {sample}\n'
                f'Cipher identik: {a == b}\n'
                f'Dekripsi silang & byte-for-byte: {decr_own == decr_lib == data}')


def jalankan_semua():
    result = []
    tests = [
        ('Vektor uji resmi DES', cek_vektor_uji),
        ('Blok acak DES dan 3DES', cek_blok_acak),
    ]
    for algorithm in ('DES', '3DES'):
        for mode in ('ECB', 'CBC'):  # GCM hanya untuk AES, bukan DES/3DES
            for label, msg in (
                ('Kurang dari 8 byte', 'saya'),
                ('Tepat 8 byte', '12345678'),
                ('Lebih dari 8 byte', 'kriptografi'),
                ('Multi-line UTF-8', 'Contoh uji enkripsi.\nBaris baru!\nAngka: 123 — é'),
            ):
                tests.append((f'{algorithm} {mode}: {label}',
                              lambda a=algorithm, m=mode, t=msg: cek_file(
                                  t, m, fc.KEY_EXAMPLES[a], a)))
    for title, func in tests:
        try:
            ok, detail = func()
        except Exception as e:
            ok, detail = False, str(e)
        result.append((title, ok, detail))
    return result


if __name__ == '__main__':
    result = jalankan_semua()
    for title, ok, detail in result:
        print(f"[{'LULUS' if ok else 'GAGAL'}] {title}\n{detail}\n")
    print(f'Total: {sum(ok for _, ok, _ in result)}/{len(result)} lulus')
