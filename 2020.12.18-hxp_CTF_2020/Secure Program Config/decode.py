#!/usr/bin/env python3
import base64

from Crypto.Cipher import AES


def main():
    encpass_b64 = "a+otqmLSU92rzNnOXGwaCehJjoX8FIlazg+TCelmsEryWnRfLLyXEsqs9mu4dQqJ"
    encpass = base64.b64decode(encpass_b64)
    EncryptDataEncKeyBin = bytes(
        (
            205,
            222,
            131,
            56,
            249,
            206,
            86,
            87,
            236,
            217,
            75,
            147,
            16,
            136,
            195,
            255,
            167,
            74,
            167,
            174,
            73,
            190,
            157,
            32,
            13,
            168,
            39,
            103,
            67,
            81,
            116,
            8,
        )
    )
    EncryptDataEncIVBin = bytes(
        (137, 165, 130, 90, 239, 22, 245, 229, 14, 115, 14, 96, 33, 12, 55, 143)
    )
    aes = AES.new(key=EncryptDataEncKeyBin, mode=AES.MODE_CBC, iv=EncryptDataEncIVBin)
    print(aes.decrypt(encpass))  # hxp{4t_least_it_was_n0t_pla1ntext}


if __name__ == "__main__":
    main()
