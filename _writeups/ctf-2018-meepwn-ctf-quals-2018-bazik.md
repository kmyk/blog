---
redirect_from:
  - /writeup/ctf/2018/meepwn-ctf-quals-2018-bazik/
layout: post
date: 2018-07-18T19:01:49+09:00
tags: [ "ctf", "writeup", "crypto", "meepwn-ctf", "rsa", "coppersmith", "coppersmith-short-pad-attack" ]
"target_url": [ "https://ctftime.org/task/6293" ]
---

# Meepwn CTF Quals 2018: Bazik

## solution

$m$ がすべて `Your OTP for transaction #731337 in ABCXYZ Bank is ?????????.` の形をしていることをgeussingすればあとはCoppersmithの定理やるだけ。気付けない場合は平文が似通ってることを信じてCoppersmith's Short Pad Attack。

## note

sageの起動が遅い問題はserverとして建てれば解決することに気付いた

## implementation

### main.py

``` python
#!/usr/bin/env python3
import argparse
import ast
import sys
import telnetlib
import Crypto.PublicKey.RSA
import Crypto.Util.number

parser = argparse.ArgumentParser()
parser.add_argument('host', nargs='?', default='206.189.92.209')
parser.add_argument('port', nargs='?', default=31333, type=int)
parser.add_argument('--sage-host', default='localhost')
parser.add_argument('--sage-port', default=8000, type=int)
args = parser.parse_args()

def solve(sage_tn):
    def coppersmiths_short_pad_attack(n, e, c1, c2):
        sage_tn.write((' '.join(map(str, [ n, e, c1, c2 ])) + '\n').encode())
        result = ast.literal_eval(sage_tn.read_until(b'\n').decode())
        if result:
            m1, m2 = result
            return m1

    with telnetlib.Telnet(args.host, args.port) as tn:

        def test_the_otp():
            tn.read_until(b'Choose one:')
            tn.write(b'1\n')
            tn.read_until(b'otp should be:')
            otp = int(tn.read_until(b'\n').strip())
            tn.read_until(b'encrypted dat:')
            encrypted_dat = tn.read_until(b'\n').strip()
            tn.read_until(b'decrypted dat:')
            decrypted_dat = tn.read_until(b'\n').strip()
            return otp, encrypted_dat, decrypted_dat

        def get_the_public_key():
            tn.read_until(b'Choose one:')
            tn.write(b'2\n')
            BEGIN = b'-----BEGIN PUBLIC KEY-----'
            END = b'-----END PUBLIC KEY-----'
            tn.read_until(BEGIN)
            key = BEGIN + tn.read_until(END)
            return Crypto.PublicKey.RSA.importKey(key)

        def get_flag(callback):
            tn.read_until(b'Choose one:')
            tn.write(b'3\n')
            tn.read_until(b'encrypted dat:')
            encrypted_dat = tn.read_until(b'\n').strip()
            tn.read_until(b'send me otp to get flag >>> ')
            otp = callback(encrypted_dat)
            tn.write(str(otp).encode() + b'\n')
            return tn.read_until(b'\n').decode().strip()

        pubkey = get_the_public_key()
        e = pubkey.e
        n = pubkey.n
        print('[*] e =', e)
        print('[*] n =', hex(n))
        assert e == 3

        for _ in range(0):
            otp, encrypted_dat, decrypted_dat = test_the_otp()
            c = int(encrypted_dat, 16)
            m = Crypto.Util.number.bytes_to_long(decrypted_dat)
            print('[*] otp =', hex(otp))
            print('[*] c =', hex(c))
            print('[*] m =', hex(m))
            assert pow(m, e, n) == c

        def solve_otp(encrypted_dat, cs=[]):
            c1 = int(encrypted_dat, 16)
            print('[*] c =', hex(c1))
            for c2 in cs:
                m1 = coppersmiths_short_pad_attack(n, e, c1, c2)
                if m1:
                    msg = Crypto.Util.number.long_to_bytes(m1).decode()
                    otp = int(msg.split()[-1].rstrip('.'))
                    print('[*] otp =', otp)
                    return otp
            else:
                cs += [ c1 ]
                return 0

        while True:
            try:
                result = get_flag(solve_otp)
            except EOFError:
                break
            print('[+]', result)
            if not result.startswith('Sorry, '):
                return result

with telnetlib.Telnet(args.sage_host, args.sage_port) as tn:
    while True:
        flag = solve(sage_tn=tn)
        if flag:
            print('[+]', flag)
            break
```

### coppersmiths_short_pad_attack.sage

<http://inaz2.hatenablog.com/entry/2016/01/20/022936> から借りてきたものを修正

``` python
#!/usr/bin/env sage
# http://inaz2.hatenablog.com/entry/2016/01/20/022936

import sys

def short_pad_attack(c1, c2, e, n):
    PRxy.<x,y> = PolynomialRing(Zmod(n))
    PRx.<xn> = PolynomialRing(Zmod(n))
    PRZZ.<xz,yz> = PolynomialRing(Zmod(n))

    g1 = x^e - c1
    g2 = (x+y)^e - c2

    q1 = g1.change_ring(PRZZ)
    q2 = g2.change_ring(PRZZ)

    h = q2.resultant(q1)
    h = h.univariate_polynomial()
    h = h.change_ring(PRx).subs(y=xn)
    h = h.monic()

    kbits = n.nbits()//(2*e*e)
    diff = h.small_roots(X=2^kbits, beta=0.5)[0]  # find root < 2^kbits with factor >= n^0.5

    return diff

def related_message_attack(c1, c2, diff, e, n):
    PRx.<x> = PolynomialRing(Zmod(n))
    g1 = x^e - c1
    g2 = (x+diff)^e - c2

    def gcd(g1, g2):
        while g2:
            g1, g2 = g2, g1 % g2
        return g1.monic()

    return -gcd(g1, g2)[0]


def main():
    n, e, c1, c2 = map(ZZ, raw_input().split())
    nbits = n.nbits()
    kbits = nbits//(2*e*e)

    try:
        diff = short_pad_attack(c1, c2, e, n)
        m1 = related_message_attack(c1, c2, diff, e, n)
        m2 = m1 + diff

        assert pow(m1, e, n) == c1
        assert pow(m2, e, n) == c2
        print [ m1, m2 ]
    except:
        print []
    sys.stdout.flush()

if __name__ == '__main__':
    while True:
        main()
```
