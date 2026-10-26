"""Independent validation without PyCryptodome for the educational DES/3DES cores."""
import os
import unittest
try:
    from cryptography.hazmat.primitives.ciphers import Cipher, modes
    from cryptography.hazmat.decrepit.ciphers.algorithms import TripleDES
    HAS_REFERENCE = True
except ImportError:
    HAS_REFERENCE = False
import des_own
import des3_own
import file_crypto as fc


@unittest.skipUnless(HAS_REFERENCE, "Paket cryptography opsional tidak tersedia")
class IndependentReference(unittest.TestCase):
    def test_random_des_and_3des_reference(self):
        for alg in ('DES', '3DES'):
            for _ in range(80):
                key = os.urandom(8) if alg == 'DES' else os.urandom(24)
                if alg == '3DES':
                    try: des3_own._keys(key)
                    except ValueError: continue
                block = os.urandom(8)
                reference = Cipher(TripleDES(key if alg == '3DES' else key * 3), modes.ECB())
                expected = reference.encryptor().update(block)
                actual = (des3_own.encrypt_block(block, key) if alg == '3DES'
                          else des_own.encrypt_block(block, key))
                self.assertEqual(actual, expected, alg)
                restored = (des3_own.decrypt_block(actual, key) if alg == '3DES'
                            else des_own.decrypt_block(actual, key))
                self.assertEqual(restored, block)

    def test_modes_cross_with_reference(self):
        def xor(a,b): return bytes(x ^ y for x,y in zip(a,b))
        for alg in ('DES','3DES'):
            key = fc.parse_key(fc.KEY_EXAMPLES[alg], alg)
            tref = Cipher(TripleDES(key if alg == '3DES' else key*3), modes.ECB())
            for msg in (b'',b'abc',b'12345678',b'123456789','Contoh! \n 1:1 — ê'.encode('utf8')):
                data = fc.pad(msg,8)
                iv = bytes(range(8))
                for mode in ('ECB','CBC'):
                    out = bytearray()
                    prev = iv
                    for i in range(0,len(data),8):
                        block = data[i:i+8]
                        if mode=='CBC': block = xor(block,prev)
                        block = tref.encryptor().update(block)
                        out.extend(block)
                        prev = block
                    expected = (iv + bytes(out)) if mode=='CBC' else bytes(out)
                    self.assertEqual(fc.encrypt_bytes(msg,key,mode,'own', iv if mode=='CBC' else None,alg),expected)
                    self.assertEqual(fc.decrypt_bytes(expected,key,mode,'own',alg),msg)


if __name__ == '__main__': unittest.main()
