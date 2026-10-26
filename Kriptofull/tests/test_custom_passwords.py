"""Regression tests untuk password teks bebas Kriptofull."""
import base64
import unittest

import app
import file_crypto as fc


class CustomPasswordTests(unittest.TestCase):
    def params(self, algorithm, key, mode='CBC'):
        return dict(algorithm=algorithm, mode=mode, engine='own', key=key)

    def test_des_direct_text_key_roundtrip(self):
        args = self.params('DES', 'Kunci123')
        src = 'SAYA belajar DES!\ndokumen contoh'
        encrypted = app.do_process({**args, 'action':'encrypt', 'text':src})
        self.assertFalse(bytes.fromhex(encrypted['result']).startswith(fc.PASSPHRASE_MAGIC))
        self.assertEqual(app.do_process({**args,'action':'decrypt', 'text':encrypted['result']})['result'],src)
        key = fc.parse_key('text:Kunci123','DES')
        self.assertEqual(key, b'Kunci123')

    def test_3des_arbitrary_password_roundtrip(self):
        args = self.params('3DES', 'Passphrase3DES-Panjang')
        src = 'Baris 1\nBaris 2 — Bab 1:?!'
        enc1 = app.do_process({**args, 'action':'encrypt', 'text':src})['result']
        enc2 = app.do_process({**args, 'action':'encrypt', 'text':src})['result']
        self.assertNotEqual(enc1,enc2)  # salt acak setiap enkripsi
        self.assertTrue(bytes.fromhex(enc1).startswith(fc.PASSPHRASE_MAGIC))
        self.assertEqual(app.do_process({**args, 'action':'decrypt', 'text':enc1})['result'],src)
        self.assertEqual(app.do_process({**args, 'action':'decrypt', 'text':enc2})['result'],src)

    def test_password_all_algorithms_and_modes_own(self):
        for alg in ('DES', '3DES'):
            for mode in ('ECB', 'CBC'):
                with self.subTest(alg=alg,mode=mode):
                    key = 'my own phrase with spaces'
                    args=self.params(alg,key,mode)
                    msg='Teks, spasi\nUnicode ✓'
                    enc=app.do_process({**args,'action':'encrypt','text':msg})['result']
                    self.assertEqual(app.do_process({**args,'action':'decrypt','text':enc})['result'],msg)

    def test_wrong_password_and_tampering_rejected(self):
        args=self.params('3DES','Passphrase3DES-Panjang')
        e=app.do_process({**args,'action':'encrypt','text':'Rahasia'})['result']
        with self.assertRaisesRegex(ValueError,'Password salah'):
            app.do_process({**args,'key':'Passphrase-Salah-123','action':'decrypt','text':e})
        raw=bytearray.fromhex(e)
        raw[-1] ^= 3
        with self.assertRaisesRegex(ValueError,'ciphertext berubah'):
            app.do_process({**args,'action':'decrypt','text':raw.hex()})
        self.assertEqual(app.do_process({**args,'mode':'ECB','action':'decrypt','text':e})['result'],'Rahasia')
        self.assertEqual(app.do_process({**args,'algorithm':'DES','action':'decrypt','text':e})['result'],'Rahasia')

    def test_3des_short_password_new_encryption_rejected_but_old_decryption_supported(self):
        args=self.params('3DES','Kunci123')
        with self.assertRaisesRegex(ValueError,'minimal 13'):
            app.do_process({**args,'action':'encrypt','text':'baru'})
        # Rekonstruksi format lama: versi sebelumnya memang menerima password pendek.
        import hashlib, hmac
        salt=b'0123456789ABCDEF'
        key, auth=fc._stretch_key(b'Kunci123',salt,'3DES')
        payload=fc.encrypt_bytes(b'file lama',key,'CBC','own',algorithm='3DES')
        header=b'SLK1'+bytes([fc.ALGORITHM_IDS['3DES'],fc.MODE_IDS['CBC']])+salt
        signature=hmac.new(auth,header+payload,hashlib.sha256).digest()[:16]
        legacy=(header+signature+payload).hex()
        self.assertEqual(app.do_process({**args,'action':'decrypt','text':legacy})['result'],'file lama')

    def test_3des_repeated_24_chars_treated_as_password(self):
        args=self.params('3DES','A'*24)
        e=app.do_process({**args,'action':'encrypt','text':'hello'})['result']
        self.assertEqual(app.do_process({**args,'action':'decrypt','text':e})['result'],'hello')

    def test_old_hex_remains_compatible(self):
        args=self.params('3DES',fc.KEY_EXAMPLES['3DES'])
        e=app.do_process({**args,'action':'encrypt','text':'legacy 3DES'})['result']
        self.assertFalse(bytes.fromhex(e).startswith(fc.PASSPHRASE_MAGIC))
        self.assertEqual(app.do_process({**args,'action':'decrypt','text':e})['result'],'legacy 3DES')

    def test_analysis_trace_with_password(self):
        r=app.do_trace(dict(algorithm='3DES',mode='ECB',engine='own',key='Passphrase3DES-Panjang',
                            text='KRIPTO12', index=1))
        self.assertTrue(r['derived_key'])
        self.assertEqual(len(r['traces']),3)
        self.assertTrue(all(len(stage['rows'])==16 for stage in r['traces']))

    def test_default_hex_force_text(self):
        raw=fc._user_key_kind('hex:133457799BBCDFF1','DES')
        self.assertEqual(raw[0],'direct')
        self.assertEqual(raw[1],bytes.fromhex('133457799BBCDFF1'))
        text=fc._user_key_kind('text:133457799BBCDFF1','DES')
        self.assertEqual(text[0],'password')


if __name__=='__main__': unittest.main()
