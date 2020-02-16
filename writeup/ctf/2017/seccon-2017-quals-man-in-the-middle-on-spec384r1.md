---
layout: post
redirect_from:
  - /blog/2017/12/10/seccon-2017-quals-man-in-the-middle-on-spec384r1/
date: "2017-12-10T15:19:24+09:00"
tags: [ "ctf", "writeup", "seccon", "seccon-quals", "crypto", "ppc", "spec384r1", "man-in-the-middle", "elliptic-curve", "elliptic-curve-diffie-hellman" ]
"target_url": [ "https://ctftime.org/event/512/" ]
---

# SECCON 2017 Online CTF: Man-in-the-middle on SECP384R1

## problem

A template of man-in-the-middle attack is given. Fill blanks.

## solution

Attack to the [ECDH](https://en.wikipedia.org/wiki/Elliptic-curve_Diffie%E2%80%93Hellman).
The point is: use CBC mode for the AES, and the initialization vector is decided by comparing to the flag format `SECCON{...}`.

## note

[konjo](https://twitter.com/konjo_p) solves almost all.
I've only found about CBC mode.

## implementation

`exploit.py`:

``` python
#!/usr/bin/python3
import mitm
import socket

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
host = "mitm.pwn.seccon.jp"
s.connect((host, 8000))

def fixed(msg):
    data = s.recv(len(msg))
    assert data

fixed(b"[dev0 to dev1]:")
data = s.recv(120)
payload = mitm.payload(data, 0)  ## todo
s.send(payload)
fixed(b"\n[dev1 to dev0]: OK\n")

fixed(b"[dev1 to dev0]:")
data = s.recv(120)
payload = mitm.payload(data, 1)  ## todo
s.send(payload)
fixed(b"\n[dev0 to dev1]: OK\n")

fixed(b"[KBKDF: SHA256, Encryption: AES]\n")
mitm.derive_keys()  ## derive keys

fixed(b"[dev0 to dev1]:")
data = s.recv(256)

ct = mitm.mitm(data)  ## todo
s.send(ct)

fixed(b"\n[dev1 to dev0]: OK\n")
fixed(b"[dev1 to dev0]:")

data = s.recv(256)
mitm.decrypt(data)  ## todo
```


`mitm.py`:

``` python
# Python Version: 3.x
# https://pypi.python.org/pypi/cryptography
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import ec

endian = 'big'

my_q = ec.generate_private_key(ec.SECP384R1(), default_backend())
peer_q = [ None, None ]
def payload(data, i):
    # recv
    header = data[: 24]
    x = int.from_bytes(data[24 :][: 48], endian)
    y = int.from_bytes(data[24 + 48 :], endian)
    peer_q[i] = ec.EllipticCurvePublicNumbers(x, y, ec.SECP384R1()).public_key(default_backend())
    # send
    my_q_x = my_q.public_key().public_numbers().x
    my_q_y = my_q.public_key().public_numbers().y
    return header + my_q_x.to_bytes(48, endian) + my_q_y.to_bytes(48, endian)

def sha256(data):
    digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
    digest.update(data)
    return digest.finalize()
shared_key = [ None, None ]
def derive_keys():
    for i in range(2):
        digest = sha256(my_q.exchange(ec.ECDH(), peer_q[i]))
        shared_key[i] = Cipher(algorithms.AES(digest), modes.CBC(b'0000000000000000'), default_backend())
def run_crypto(cryptor, data):
    buf = bytearray(4098)
    len_crypted = cryptor.update_into(data, buf)
    return bytes(buf[: len_crypted]) + cryptor.finalize()

def mitm(data):
    data = run_crypto(shared_key[0].decryptor(), data)
    print(data)
    data = run_crypto(shared_key[1].encryptor(), data)
    return data

def decrypt(data):
    data = run_crypto(shared_key[1].decryptor(), data)
    print(data)
```
