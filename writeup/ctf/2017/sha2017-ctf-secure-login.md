---
layout: post
redirect_from:
  - /blog/2017/08/07/sha2017-ctf-secure-login/
date: "2017-08-07T16:50:23+09:00"
tags: [ "ctf", "writeup", "sha-ctf", "crypto", "rsa" ]
---

# SHA2017 CTF: crypto 200 - Secure Login

## problem

RSA暗号。padding付き復号oracle $f : m \mapsto \mathrm{dec}(\text{"\backslash xff"} \oplus m)$および$g : (a, b) \mapsto \mathrm{dec}(\text{"ticket:user\|"} \oplus a \oplus \text{"\|"} \oplus b)$が与えられるので、$s = \mathrm{enc}( c)$が$\text{"ticket:admin\|root\|"}$から始まるような$c$を求めよ。

## solution

暗号化/復号の別はあまり気にしなくてよい。
$\mathrm{dec}(m) = m^d \bmod n$なので乗法的、つまり$\mathrm{dec}(ab) = \mathrm{dec}(a) \mathrm{dec}(b) \bmod n$。

作る目標の$s$に対して$\mathrm{dec}(k)$と$\mathrm{dec}(ks)$が共に得られるような$k$があれば$\mathrm{dec}(s) = c$も得られる。
これを見つけるには$k = a^b$として、$a$は適当な文字列で整数$b$は文字列$ks = a^bs$が`\xff`から始まるように適当に決める。長さの制限などから$a = 257 = (255 + 256 + 255) \cdot 255^{-1}$が良いだろう。


## implementation

``` python
#!/usr/bin/env python2
import gmpy2
from pwn import * # https://pypi.python.org/pypi/pwntools
import argparse
parser = argparse.ArgumentParser()
parser.add_argument('host', nargs='?', default='secure-login.stillhackinganyway.nl')
parser.add_argument('port', nargs='?', default=12345, type=int)
parser.add_argument('-n', default=25504352309535290475248970674346405639150033303276037621954645287836414954584485104061261800020387562499019659311665606506084209652278825297538342995446093360707480284955051977871508969158833725741319229528482243960926606982225623875037437446029764584076579733157399563314682454896733000474399703682370015847387660034753890964070709371374885394037462378877025773834640334396506494513394772275132449199231593014288079343099475952658539203870198753180108893634430428519877349292223234156296946657199158953622932685066947832834071847602426570899103186305452954512045960946081356967938725965154991111592790767330692701669, type=int)
parser.add_argument('--log-level', default='debug')
args = parser.parse_args()
context.log_level = args.log_level
p = remote(args.host, args.port)

n = args.n
e = 65537
def num2str(n):
    d = ('%x' % n)
    if len(d) % 2 == 1:
        d = '0' + d
    return d.decode('hex')
def str2num(s):
    return int(s.encode('hex'),16)

def register_user(uname, full):
    p.recvuntil('Choice: ')
    p.sendline('1')
    p.recvuntil('Pick a username: ')
    p.sendline(uname)
    p.recvuntil('Enter your full name: ')
    p.sendline(full)
    p.recvuntil('Your ticket:\n')
    return int(p.recvline().rstrip(), 16)
def collect_flag(ticket):
    p.recvuntil('Choice: ')
    p.sendline('2')
    p.recvuntil('Enter your ticket: ')
    p.sendline(hex(ticket)[2 :])
def sign_a_message(msg):
    p.recvuntil('Choice: ')
    p.sendline('3')
    p.recvuntil('Enter your message, hex encoded (i.e. 4142 for AB): ')
    p.sendline(msg)
    p.recvuntil('Your signature:\n')
    return int(p.recvline().rstrip(), 16)
def exit_chall():
    p.recvuntil('Choice: ')
    p.sendline('4')

enc = {}
enc[0xff] = sign_a_message('')
enc[0xffff] = sign_a_message('ff')
enc[0x101] = enc[0xffff] * gmpy2.invert(enc[0xff], n) % n
key = str2num('ticket:admin|root|')
k = 0
while True:
    shifted = key * 0x101 ** k
    if hex(shifted).startswith('0xff'):
        break
    k += 1
enc[shifted] = sign_a_message(hex(shifted)[4 :])
enc[key] = enc[shifted] * gmpy2.invert(pow(enc[0x101], k, n), n) % n
collect_flag(enc[key])
exit_chall()
```
