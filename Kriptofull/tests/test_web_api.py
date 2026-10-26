"""Tes kontrak API browser (tanpa browser dan Flask)."""
import base64
import hashlib
import unittest
from pathlib import Path

import app
import file_crypto as fc


class BrowserAPI(unittest.TestCase):
    def test_text_process_des(self):
        key=fc.KEY_EXAMPLES['DES']
        p=dict(algorithm='DES',mode='CBC',engine='own',key=key,text='kriptografi',action='encrypt')
        c=app.do_process(p)
        d=app.do_process({**p,'text':c['result'],'action':'decrypt'})
        self.assertEqual(d['result'],'kriptografi')

    def test_sample_document_roundtrip(self):
        b=(app.SAMPLES/'pesan_contoh.txt').read_bytes()
        d=dict(algorithm='3DES',mode='CBC',engine='own',key=fc.KEY_EXAMPLES['3DES'],
               action='encrypt',filename='pesan_contoh.txt',file_data=app.b64_encode(b),verify=True)
        enc=app.do_file(d)
        self.assertTrue(enc['identical'])
        dec=app.do_file({**d,'action':'decrypt','filename':enc['name'],
                        'file_data':enc['output'],'original_data':app.b64_encode(b)})
        self.assertTrue(dec['identical'])
        self.assertEqual(base64.b64decode(dec['output']),b)

    def test_export_ciphertext_txt_roundtrip_all_modes(self):
        original = (app.SAMPLES / 'pesan_contoh.txt').read_bytes()
        for alg in ('DES', '3DES'):
            for mode in ('ECB', 'CBC'):
                with self.subTest(algorithm=alg, mode=mode):
                    settings=dict(algorithm=alg,mode=mode,engine='own',key=fc.KEY_EXAMPLES[alg])
                    encrypted=app.do_file({**settings, 'action':'encrypt', 'filename':'pesan_contoh.txt',
                        'file_data':app.b64_encode(original), 'verify':True})
                    self.assertTrue(encrypted['name'].endswith('_terenkripsi.txt'))
                    self.assertTrue(encrypted['identical'])
                    ciphertext_text=base64.b64decode(encrypted['output'])
                    self.assertTrue(ciphertext_text.isascii())
                    self.assertTrue(all(c in b'0123456789ABCDEF' for c in ciphertext_text))
                    self.assertEqual(len(ciphertext_text) % 2, 0)
                    self.assertEqual(encrypted['size_out'], len(ciphertext_text))
                    decrypted=app.do_file({**settings,'action':'decrypt','filename':encrypted['name'],
                        'file_data':encrypted['output'],'original_data':app.b64_encode(original)})
                    self.assertTrue(decrypted['identical'])
                    self.assertEqual(base64.b64decode(decrypted['output']),original)

    def test_legacy_enc_binary_still_decrypts(self):
        original=b'Legacy .enc binary\n'
        settings=dict(algorithm='DES',mode='CBC',engine='own',key=fc.KEY_EXAMPLES['DES'])
        key=fc.parse_key(settings['key'],'DES')
        ciphertext=fc.encrypt_bytes(original,key,'CBC','own',algorithm='DES')
        decrypted=app.do_file({**settings,'action':'decrypt','filename':'legacy.enc',
            'file_data':app.b64_encode(ciphertext)})
        self.assertEqual(base64.b64decode(decrypted['output']),original)

    def test_trace_des_and_3des(self):
        for alg, expected in [('DES',1),('3DES',3)]:
            r=app.do_trace(dict(algorithm=alg,mode='ECB',engine='own',key=fc.KEY_EXAMPLES[alg],
                                index=1,text='KRIPTO12'))
            self.assertEqual(len(r['traces']),expected)
            self.assertTrue(all(len(s['rows'])==16 for s in r['traces']))
            self.assertIn('⊕',r['traces'][0]['rows'][0]['xor'])

    def test_zar1_sample_roundtrip(self):
        source = (app.SAMPLES / 'pesan_contoh.txt').read_bytes()
        key = fc.KEY_EXAMPLES['DES']
        data = fc.encode_ciphertext(fc.encrypt_user_bytes(source, key, 'CBC', 'own', algorithm='DES'), 'DES', 'CBC', 'ZAR1')
        response = app.do_file(dict(algorithm='DES',mode='CBC',engine='own',key=key,
             action='decrypt',filename='contoh_ciphertext_zar1.txt',file_data=app.b64_encode(data)))
        self.assertEqual(base64.b64decode(response['output']), source)


if __name__=='__main__':unittest.main()
