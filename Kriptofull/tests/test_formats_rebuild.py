import unittest, base64, json
import app, file_crypto as fc

class FormatRoundtrip(unittest.TestCase):
    def perform(self, alg, mode, key, fmt, engine='own'):
        plaintext='Kalimat dokumen contoh\nTanda baca: !?, 𓀀 akhir.'.encode('utf-8')
        p={'algorithm':alg,'mode':mode,'key':key,'engine':engine}
        enc=app.do_process({**p,'action':'encrypt','export_format':fmt,'text':plaintext.decode('utf-8')})
        self.assertEqual(enc['format'],fmt)
        recovered=app.do_process({**p,'action':'decrypt','input_format':'AUTO','text':enc['result']})
        self.assertEqual(recovered['result'].encode('utf-8'),plaintext)
        self.assertEqual(recovered['algorithm'],alg)
        self.assertEqual(recovered['mode'],mode)
        # Metadata dari ciphertext mengalahkan pilihan GUI yang salah untuk SLK1/ZAR1/B64
        fallback={'algorithm':'DES' if alg=='3DES' else '3DES', 'mode':'ECB' if mode=='CBC' else 'CBC','key':key,'engine':engine}
        if fmt in ('ZAR1','SLK1','B64') or fc.PASSPHRASE_MAGIC.hex().upper() in enc['result'][:10]:
            restored=app.do_process({**fallback,'action':'decrypt','text':enc['result']})
            self.assertEqual(restored['result'].encode('utf-8'),plaintext)
        return enc
    def test_password_des_3des_modes_formats(self):
        for alg,key in [('DES','p4ssw0rd panjang'),('3DES','Passphrase3DES-Panjang')]:
            for mode in ('ECB','CBC'):
                for fmt in ('HEX','SLK1','B64')+ (('ZAR1',) if mode=='CBC' else ()):
                    with self.subTest(alg=alg,mode=mode,fmt=fmt):self.perform(alg,mode,key,fmt)
    def test_direct_key_formats(self):
        for alg,key in [('DES','Kunci123'),('3DES',fc.KEY_EXAMPLES['3DES'])]:
            for mode in ('ECB','CBC'):
                for fmt in ('HEX','B64')+(('ZAR1',) if mode=='CBC' else ()):
                    with self.subTest(alg=alg,mode=mode,fmt=fmt):self.perform(alg,mode,key,fmt)
    def test_minimum_13_for_3des_only(self):
        for key in ('panjang12chr','Kunci123','abc'):
            with self.subTest(key=key):
                with self.assertRaisesRegex(ValueError,'minimal 13'):
                    app.do_process({'algorithm':'3DES','mode':'CBC','engine':'own','key':key,'text':'hello','action':'encrypt'})
        self.perform('3DES','CBC','1234567890123','SLK1')
        self.perform('DES','CBC','abc','SLK1')
    def test_file_modes_and_formats_both_algorithms(self):
        source=(app.SAMPLES/'dokumen_contoh.txt').read_bytes()
        for alg,key in [('DES','Kunci123'),('3DES','Passphrase3DES-Panjang')]:
            for fmt in ('HEX','ZAR1','B64'):
                with self.subTest(alg=alg,fmt=fmt):
                    p={'algorithm':alg,'mode':'CBC','engine':'own','key':key}
                    file_enc=app.do_file({**p,'action':'encrypt','filename':'dokumen_contoh.txt','file_data':app.b64_encode(source),'export_format':fmt,'verify':True})
                    self.assertTrue(file_enc['identical'])
                    result=app.do_file({**p,'action':'decrypt','filename':file_enc['name'],'file_data':file_enc['output'], 'input_format':'AUTO','original_data':app.b64_encode(source)})
                    self.assertEqual(base64.b64decode(result['output']),source)
                    self.assertTrue(result['identical'])
            if alg=='3DES':
                q={**p,'key':key,'export_format':'SLK1','filename':'secret.txt','file_data':app.b64_encode(b'my secret') ,'action':'encrypt'}
                result=app.do_file(q)
                self.assertIn(b'SLK1:',base64.b64decode(result['output'])[:6])
                back=app.do_file({**p,'action':'decrypt','filename':result['name'],'file_data':result['output']})
                self.assertEqual(base64.b64decode(back['output']),b'my secret')
    def test_zar1_header_is_detected(self):
        key = fc.KEY_EXAMPLES['3DES']
        sample = b'Contoh file interoperabilitas'
        raw = fc.encrypt_user_bytes(sample, key, 'CBC', 'own', algorithm='3DES')
        encoded = fc.encode_ciphertext(raw, '3DES', 'CBC', 'ZAR1')
        payload, meta = fc.decode_input(encoded)
        self.assertEqual(meta['algorithm'], '3DES')
        self.assertEqual(meta['mode'], 'CBC')
        self.assertEqual(meta['format'], 'ZAR1')
        self.assertEqual(payload, raw)
    def test_wrong_password_rejected(self):
        encrypted=self.perform('3DES','CBC','Passphrase3DES-Panjang','SLK1')
        with self.assertRaisesRegex(ValueError,'Password salah'):
            app.do_process({'algorithm':'DES','mode':'ECB','engine':'own','key':'Password-Salah-ABC','action':'decrypt','text':encrypted['result']})
    def test_export_unavailable_options_have_clear_error(self):
        with self.assertRaisesRegex(ValueError,'hanya untuk DES/3DES'):
            fc.encode_ciphertext(b'xyz','AES-128','CBC','ZAR1')
        with self.assertRaisesRegex(ValueError,'hanya untuk enkripsi memakai password'):
            fc.encode_ciphertext(b'xyz','DES','CBC','SLK1')
        with self.assertRaisesRegex(ValueError,'hanya untuk DES/3DES mode CBC'):
            fc.encode_ciphertext(b'xyz','DES','ECB','ZAR1')

if __name__=='__main__':unittest.main()

class ConvertFeature(unittest.TestCase):
    def test_convert_without_reencrypt_preserves_ciphertext(self):
        p={'algorithm':'3DES','mode':'CBC','engine':'own','key':'Passphrase3DES-Panjang'}
        enc=app.do_file({**p,'action':'encrypt','export_format':'HEX','filename':'hello.txt','file_data':app.b64_encode(b'halo dunia')})
        file_data=enc['output']
        for fmt in ('HEX','ZAR1','SLK1','B64'):
            with self.subTest(fmt=fmt):
                c=app.do_convert({**p,'file_data':file_data,'export_format':fmt,'filename':enc['name']})
                original,_=fc.decode_input(base64.b64decode(file_data))
                converted,_=fc.decode_input(base64.b64decode(c['output']))
                self.assertEqual(original,converted)
                dec=app.do_file({**p,'action':'decrypt','file_data':c['output'],'filename':c['name']})
                self.assertEqual(base64.b64decode(dec['output']),b'halo dunia')
    def test_direct_key_forbids_slk1_conversion(self):
        p={'algorithm':'DES','mode':'CBC','engine':'own','key':'Kunci123'}
        enc=app.do_file({**p,'action':'encrypt','export_format':'HEX','filename':'hello.txt','file_data':app.b64_encode(b'halo dunia')})
        with self.assertRaisesRegex(ValueError,'hanya untuk enkripsi memakai password'):
            app.do_convert({**p,'file_data':enc['output'],'export_format':'SLK1'})
