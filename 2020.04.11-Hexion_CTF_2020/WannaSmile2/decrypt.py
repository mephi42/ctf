#!/usr/bin/env python3
import sys

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers import algorithms, Cipher, modes

data = open(sys.argv[1], 'rb').read()
sig = data[:10]
assert sig == b'WANNASMILE'
# https://cryptography.io/en/latest/hazmat/primitives/asymmetric/rsa/
rsa = serialization.load_pem_private_key(data=b'''
-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEAujCxmc9GU2RHVWRgQKhHkU+vrD35XbAbWIGFu+a5mghCvLWc
aCm0HDW7zU8t8InSXkCa03mUrZLtERl00JviFEdREYpV3ATpKM9CG7WCMmCvT7+k
j9ReKhqNwmJTfYxf/yEN3STMtl8d2UUDAXLDX6RMijuVF4r1hhHJcmzbQsfi4SzL
xmBkTEdr+0P+8WyLGb6eI1NsCPhLw5ctma2Sf/iAuN1VZ4EFrhP8DMQR683Ha0w5
zllh6Olz15d6AoMtOAKpt1/d+oebmimnweUdoUji3M09g0RlzcbkcjGdydFmkTfl
RfXruneYwx/1ajbkzOIKSYtvsQ68qfutEv5UYwIDAQABAoIBAHV45YUavs88lLku
xH/m7IilEzyEOYI/63Dy/3KnRvEFRz4TA6TAsy+dQ2ltDJoYCs+GyWil7AV7jvFb
81TvFTwgJuj/M97GhmlGIvqikYvBbrrNOkG5BtRfvpMnQHAVEjhBHaMqZbKm3olH
vna6dsQwQE5y+0VIWlKFhGkaf1ho+HlghrTs1hp8q53LjYOkSzIiLC2llSqX+TJI
4likIe3SJc9I3tvBcNXjKE4lDtJv8UVvvOX870Okaiz4gcezghWKAP0jlBnjGt4h
aNPyCLN2QN5AsF6cL+VN6vKQqiTP6IO/Z27RvmZpFnZCS4lCdxIWVQplZSAQvhZr
S3vlU0kCgYEA/fP/Gum81jsZILHYQyHXD7c+mpDMsF9q8UcEgJWhsFwl7gpmXhKF
UkbbaAZ41LdRLEMULN9lrj9KsZgUSL+q1dbgg58QfeWeT23GrBryOLc4+73O2tDY
GLKlm1iDbzUcH90rt9N/l1P1mchum5yhPgce9s/Vxd+FsT+JrdKa2E0CgYEAu7Dg
TOIwZGkkAPChuzvgGwQc5zyB2W9JMIu6f/vjv5sO9ULml7YPNKLl5lQb3tLClLKE
mLH+km5Ktt9aSegxFMYxHBOjbPNHiQzNucziFld/gnLxZH2VecqAztu1eIaRLFsO
RN+M08Ci5AIcgNELopihwRWoOBIlxIm1YGPqN28CgYEAkz6ZCJLD8fccL6/Oc8Y4
Ox2Fh/szI4R/rlv+CUw5DtevCmEvT5YvhTAeYSd3gea0gxR1qzrwauK5vVUvVasE
M66+SLK+zjCH5QgCbKHHFgluWdCJEqiK028pxHPC6YUCxJrpkVFpJmYA/mSPdVyQ
xTU9x99j1LIwg0AS5R06uPUCgYBbwCJV0zh+zVr5TqhxI9rwufj7HPwI87rejV+1
EsiJsN4GDRc2UJxsSbmC99jL+1F9aSsijdh5cor5jIPRnzzm/9+f7wWzy9VLbMPg
sQRQkaNWfKP+UNnSOKjw9jxm17l96mE2T+XC2eeG+HVAj3BVorFn9xNNnalywzK0
FQO45wKBgGSNstScPA8i1Jrqa0NaMMbRvP1ifhID/snDt3mfgybvD1GEUcNIQUDu
1hUE/K5lMaijtcbsuvpW+9y8mL0ZTI3kk8voOV8VkJ8cMy8/RH7zRMC2lC+GU7es
nGUfgUSTuxJ06sNCNF3AqGwRmaIrQ/e7qRBmzrcU3QmkXTBiaEL9
-----END RSA PRIVATE KEY-----
''', password=None, backend=default_backend())
aes_iv_pos = 10 + rsa.key_size // 8
aes_key = rsa.decrypt(
    data[10:aes_iv_pos], padding=padding.PKCS1v15())
iv = b'\0' * 16
cipher = Cipher(
    algorithms.AES(aes_key),
    mode=modes.CBC(iv),
    backend=default_backend()
)
decryptor = cipher.decryptor()
with open(sys.argv[2], 'wb') as fp:
    fp.write(
        decryptor.update(data[aes_iv_pos:]) +
        decryptor.finalize())
