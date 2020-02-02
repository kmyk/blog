---
layout: post
alias: "/blog/2017/05/28/whitehat-summer-contest-2017-cat-ba-island/"
date: "2017-05-28T23:24:14+09:00"
title: "WhiteHat Summer Contest 2017: Cat Ba island"
tags: [ "ctf", "writeup", "whitehat-wargame", "crypto", "aes", "cbc-mode" ]
---

## problem

お金を貯める感じのゲーム。
ivを指定して鯖でAES復号をし、これによる平文中にある整数(正規表現 `\d+`)だけ獲得。

## solution

Wikipediaに[図](https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Cipher_Block_Chaining_.28CBC.29)付きで載ってるので眺める。
ivを指定しての復号なので先頭blockに自由にxorできるということ。
これをやる。
`from data import query` とされている平文は固定であるようなので解ける。

## implementation

``` python
#!/usr/bin/env python2
from pwn import * # https://pypi.python.org/pypi/pwntools
import argparse
parser = argparse.ArgumentParser()
parser.add_argument('host', nargs='?', default='hackmymoney.wargame.whitehat.vn')
parser.add_argument('port', nargs='?', default=1337, type=int)
parser.add_argument('--log-level', default='debug')
args = parser.parse_args()
context.log_level = args.log_level
p = remote(args.host, args.port)

def get_secret_code():
    p.recvuntil('Choose:\n')
    p.sendline('1')
    p.recvuntil('Your secret code: ')
    code = p.recvline().rstrip()
    log.info('Your secret code: %s', (code))
    return code
def get_money(secret_code):
    p.recvuntil('Choose:\n')
    p.sendline('2')
    p.recvuntil('Give me your secret code: \n')
    p.sendline(secret_code)
    result = p.recvuntil(' ').strip()
    if result == 'Can':
        log.info('Can not get money')
        return None
    else:
        assert result == 'You'
        p.recvuntil('got:')
        got = p.recvline().strip()
        log.info('You got: %s', repr(got))
        p.recvuntil('You have: ')
        have = int(p.recvline().rstrip())
        log.info('You have: %d', have)
        return got

code = get_secret_code()
iv = bytearray(code.decode('hex'))
log.info('iv: %s', repr(iv))

got = get_money(bytes(iv).encode('hex'))
assert got == '1'
iv[4] ^= 88
iv[5] ^= 8
iv[6] ^= 88
iv[7] ^= 88
iv[8] ^= 75
iv[9] ^= 64
iv[10] ^= 80
iv[11] ^= 88
iv[12] ^= 64
iv[13] ^= 64
iv[14] ^= 24

got = get_money(bytes(iv).encode('hex'))
while True:
    n = random.randint(0, 255)
    log.info('xor: %d', n)
    modified_iv = bytearray(iv)
    modified_iv[3] ^= n
    modified_got = get_money(bytes(modified_iv).encode('hex'))
    if modified_got is not None and int(modified_got) > int(got):
        break
```
