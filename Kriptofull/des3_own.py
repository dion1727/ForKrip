"""3DES EDE (3-key) buatan sendiri, memakai DES Feistel pada des_own.py.

Enkripsi: E(K3, D(K2, E(K1, P)))
Dekripsi: D(K1, E(K2, D(K3, C)))
Tidak memakai Crypto atau implementasi DES pustaka.
"""

import des_own


def _keys(key):
    if len(key) != 24:
        raise ValueError("Kunci 3DES harus tepat 24 byte: K1, K2, K3 masing-masing 8 byte.")
    k1, k2, k3 = key[:8], key[8:16], key[16:24]
    # Bit paritas terakhir tiap byte tidak masuk key schedule DES.
    material = [bytes(b & 0xFE for b in k) for k in (k1, k2, k3)]
    if material[0] == material[1] or material[1] == material[2]:
        raise ValueError("Kunci 3DES tidak valid: K1=K2 atau K2=K3 (berdegenerasi menjadi DES).")
    return k1, k2, k3


class TripleDES:
    """Pra-hitung subkunci ronde agar file besar tidak regenerasi tiap blok."""
    def __init__(self, key):
        self.key = key
        k1, k2, k3 = _keys(key)
        self.r1 = des_own.generate_round_keys(k1)
        self.r2 = des_own.generate_round_keys(k2)
        self.r3 = des_own.generate_round_keys(k3)

    def encrypt(self, block):
        x = des_own._crypt_block(block, self.r1)
        x = des_own._crypt_block(x, self.r2[::-1])
        return des_own._crypt_block(x, self.r3)

    def decrypt(self, block):
        x = des_own._crypt_block(block, self.r3[::-1])
        x = des_own._crypt_block(x, self.r2)
        return des_own._crypt_block(x, self.r1[::-1])


def encrypt_block(block, key):
    return TripleDES(key).encrypt(block)


def decrypt_block(block, key):
    return TripleDES(key).decrypt(block)


if __name__ == '__main__':
    key = bytes.fromhex('0123456789ABCDEFFEDCBA98765432100011223344556677')
    p = bytes.fromhex('0123456789ABCDEF')
    c = encrypt_block(p, key)
    print('3DES ciphertext:', c.hex().upper())
    print('3DES dekripsi:', decrypt_block(c, key).hex().upper())
    assert decrypt_block(c, key) == p
