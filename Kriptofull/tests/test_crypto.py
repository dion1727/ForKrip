"""Pengujian otomatis: python -m unittest discover -s tests -v"""
import os
from pathlib import Path
import tempfile
import unittest

import des_own
import des3_own
import file_crypto as fc


class DES3DESTests(unittest.TestCase):
    def test_des_known_answer(self):
        key = bytes.fromhex('133457799BBCDFF1')
        plain = bytes.fromhex('0123456789ABCDEF')
        expected = bytes.fromhex('85E813540F0AB405')
        self.assertEqual(des_own.encrypt_block(plain, key), expected)
        self.assertEqual(des_own.decrypt_block(expected, key), plain)

    def test_3des_ede_manual(self):
        key = fc.parse_key(fc.KEY_EXAMPLES['3DES'], '3DES')
        plain = b'12345678'
        expected = des_own.encrypt_block(
            des_own.decrypt_block(
                des_own.encrypt_block(plain, key[:8]), key[8:16]), key[16:])
        self.assertEqual(des3_own.encrypt_block(plain, key), expected)
        self.assertEqual(des3_own.decrypt_block(expected, key), plain)

    def test_roundtrace(self):
        key = bytes.fromhex(fc.KEY_EXAMPLES['DES'])
        block = bytes.fromhex('0123456789ABCDEF')
        out, trace = des_own.trace_block(block, key)
        self.assertEqual(out.hex().upper(), '85E813540F0AB405')
        self.assertEqual(len(trace), 17)  # ronde 0 ... ronde 16
        self.assertEqual(des_own.trace_block(out, key, decrypt=True)[0], block)

    def test_roundtrip_all_sizes_modes(self):
        examples = (b'', b'a', b'1234567', b'12345678', b'123456789',
                    b'x'*15, b'x'*16, b'x'*17, b'x'*33, b'\0'*128,
                    'Ini teks panjang.\nAyat 1: á é, !?\r\nAyat 2: akhir.'.encode('utf-8'))
        for algorithm in ('DES', '3DES'):
            key = fc.parse_key(fc.KEY_EXAMPLES[algorithm], algorithm)
            for mode in ('ECB', 'CBC'):
                for message in examples:
                    with self.subTest(alg=algorithm, mode=mode, n=len(message)):
                        ct = fc.encrypt_bytes(message, key, mode, 'own', algorithm=algorithm)
                        restored = fc.decrypt_bytes(ct, key, mode, 'own', algorithm)
                        self.assertEqual(restored, message)
                        self.assertEqual(len(ct) % 8, 0)
                        self.assertEqual(len(ct), len(fc.pad(message)) + (8 if mode == 'CBC' else 0))

    def test_3des_degenerate_key_rejected(self):
        k = bytes.fromhex(fc.KEY_EXAMPLES['DES'])
        with self.assertRaises(ValueError):
            fc.parse_key((k + k + os.urandom(8)).hex(), '3DES')

    def test_same_file_not_overwritten(self):
        with tempfile.TemporaryDirectory() as dir:
            path = Path(dir) / 'original.txt'
            raw = b'Teks asli\nbaris kedua' + bytes(range(32))
            path.write_bytes(raw)
            k = fc.parse_key(fc.KEY_EXAMPLES['3DES'], '3DES')
            with self.assertRaises(ValueError):
                fc.encrypt_file(path, path, k, algorithm='3DES')
            self.assertEqual(path.read_bytes(), raw)

    def test_file_exact_bytes(self):
        with tempfile.TemporaryDirectory() as dir:
            original = Path(dir) / 'dokumen_contoh.txt'
            cipher = Path(dir) / 'dokumen_contoh.enc'
            restored = Path(dir) / 'dokumen_contoh_kembali.txt'
            source = ('Baris 1\r\n' + 'Pasal 1: tanda baca, ä, (abc)!\n' * 500).encode('utf-8')
            original.write_bytes(source)
            for algorithm in ('DES', '3DES'):
                key = fc.parse_key(fc.KEY_EXAMPLES[algorithm], algorithm)
                fc.encrypt_file(original, cipher, key, 'CBC', 'own', algorithm=algorithm)
                fc.decrypt_file(cipher, restored, key, 'CBC', 'own', algorithm)
                self.assertTrue(fc.files_identical(original, restored))
                self.assertEqual(restored.read_bytes(), source)

    def test_ciphertext_hex_user_error(self):
        self.assertEqual(fc.parse_ciphertext_hex('HEX: 0A 10 ff'), b'\x0a\x10\xff')
        with self.assertRaisesRegex(ValueError, 'CIPHERTEXT HEX'):
            fc.parse_ciphertext_hex('kriptografi')

    def test_aes_own_not_supported(self):
        key = fc.parse_key(fc.KEY_EXAMPLES['AES-128'], 'AES-128')
        with self.assertRaisesRegex(ValueError, 'AES hanya'):
            fc.encrypt_bytes(b'test', key, 'CBC', 'own', algorithm='AES-128')

    def test_aes_key_sizes_and_roundtrip_with_reference(self):
        # Cross-reference with cryptography package when PyCryptodome exists.
        try:
            from Crypto.Cipher import AES
        except ImportError:
            self.skipTest('PyCryptodome tidak tersedia di lingkungan ini')
        for algorithm in ('AES-128', 'AES-192', 'AES-256'):
            key = fc.parse_key(fc.KEY_EXAMPLES[algorithm], algorithm)
            for mode in ('ECB', 'CBC', 'GCM'):
                msg = 'dokumen contoh. Baris baru!\nHuruf é dan simbol.'.encode('utf-8')
                cipher = fc.encrypt_bytes(msg, key, mode, 'library', algorithm=algorithm)
                self.assertEqual(fc.decrypt_bytes(cipher, key, mode, 'library', algorithm), msg)
                if mode == 'GCM':
                    corrupted = bytearray(cipher)
                    corrupted[-1] ^= 1
                    with self.assertRaises(ValueError):
                        fc.decrypt_bytes(bytes(corrupted), key, mode, 'library', algorithm)

    @unittest.skipUnless(__import__('importlib').util.find_spec('Crypto'), 'PyCryptodome belum terpasang')
    def test_crypto_library_match(self):
        import compare
        results = compare.jalankan_semua()
        failures = [(title, detail) for title, ok, detail in results if not ok]
        self.assertFalse(failures, failures)


if __name__ == '__main__':
    unittest.main()
