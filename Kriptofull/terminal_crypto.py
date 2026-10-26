"""Program terminal/prompt DES, 3DES dan tambahan AES dengan library PyCryptodome.
Program terminal DES dan 3DES. Jalankan: python terminal_crypto.py
"""
from pathlib import Path
import file_crypto as fc


def pilih(title, options):
    while True:
        print(f'\n{title}: ' + ', '.join(options))
        value = input('Pilihan > ').strip().upper()
        if value in options:
            return value
        print('Pilihan tidak tersedia.')


def main():
    print('='*68)
    print(' KRIPTOFULL / TERMINAL - LIBRARY PYCRYPTODOME')
    print(' DES, 3DES + AES-128/192/256 (tambahan)')
    print('='*68)
    print('CBC menyimpan IV di awal ciphertext. GCM menyimpan nonce dan tag.')
    while True:
        algorithm = pilih('ALGORITMA', (*fc.ALGORITHMS, '0'))
        if algorithm == '0': break
        modes = ('ECB', 'CBC', 'GCM') if algorithm.startswith('AES') else ('ECB', 'CBC')
        mode = pilih('MODE', modes)
        action = pilih('AKSI', ('E', 'D'))
        source = pilih('SUMBER', ('T', 'F'))
        key_input = input(f'Kunci HEX atau password teks bebas (Enter = contoh): ').strip()
        try:
            key = key_input or fc.KEY_EXAMPLES[algorithm]
            if source == 'T':
                if action == 'E':
                    text = input('Plaintext: ').encode('utf-8')
                    result = fc.encrypt_user_bytes(text, key, mode, 'library', algorithm=algorithm)
                    print('\nCIPHERTEXT HEX:\n' + result.hex().upper())
                    print(f'Asli: {len(text)} byte | Hasil: {len(result)} byte')
                else:
                    ciphertext = fc.parse_ciphertext_hex(input('Ciphertext HEX: '))
                    result = fc.decrypt_user_bytes(ciphertext, key, mode, 'library', algorithm)
                    print('\nPLAINTEXT:\n' + result.decode('utf-8'))
            else:
                src = Path(input('Path file input: ').strip().strip('"'))
                target = input('Path hasil (Enter = otomatis): ').strip().strip('"')
                dst = Path(target) if target else Path(str(src) + ('.terenkripsi.txt' if action == 'E' else '.pulih.txt'))
                if action == 'E':
                    data = src.read_bytes()
                    encrypted = fc.encrypt_user_bytes(data, key, mode, 'library', algorithm=algorithm)
                    dst.write_text(encrypted.hex().upper(), encoding='utf-8')
                    before, after = len(data), dst.stat().st_size
                else:
                    data = src.read_bytes()
                    encrypted, annotated_alg = fc.parse_ciphertext_input(data, algorithm)
                    if annotated_alg and mode != 'CBC':
                        raise ValueError('ZAR1 harus menggunakan mode CBC.')
                    plaintext = fc.decrypt_user_bytes(encrypted, key, mode, 'library', algorithm)
                    dst.write_bytes(plaintext)
                    before, after = len(data), len(plaintext)
                print(f'BERHASIL: {dst}\n{before} byte -> {after} byte')
        except (ValueError, FileNotFoundError, RuntimeError, UnicodeError) as err:
            print('GAGAL:', err)
    print('Selesai.')


if __name__ == '__main__':
    try: main()
    except (KeyboardInterrupt, EOFError): print('\nSelesai.')
