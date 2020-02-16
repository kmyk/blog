---
layout: post
redirect_from:
  - /blog/2016/10/29/ekoparty-ctf-2016-fuckzing-reverse/
date: "2016-10-29T13:00:35+09:00"
tags: [ "ctf", "writeup", "ekoparty-ctf", "rev", "angr" ]
"target_url": [ "https://ctf.ekoparty.org/tasks/rev/250" ]
---

# EKOPARTY CTF 2016: Fuckzing reverse

-   Sun Oct 30 00:19:55 JST 2016
    -   The constraint for the payload seems to be misunderstanding of me.

## problem

A simple program checks the input.
It requires a `libget_flag.so`.

``` sh
$ file FUck_binary
 FUck_binary: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 2.6.32, BuildID[sha1]=583997ea22be0b90670780cb91b36de37e1100d2, not stripped
$ gcc -fpic -shared get_flag.c -o libget_flag.so
$ LD_LIBRARY_PATH=. ./FUck_binary
Hello, what's your team name? foo
Goodbye!
```

``` c
// get_flag.c
#include <string.h>
const char flag[] = "EKO{3277860e23b44e91baeeaf2e1b578ae1}";
void get_flag(char *dest) {
    strcpy(dest, flag);
}
```

Also, the remote server has a trick. You can confirm this using the echo-back.
It filters some bytes. For example, a null byte `\x00` becomes a printable string `^@`, a byte `\x01` becomes a string `^A`.
It seems that some kind of editor, like vim, is used.

``` sh
$ echo -n $'\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f0123ABCDEFabcdef\xff\xfe\xfd\xfc' | nc 7e0a98bb084ec0937553472e7aafcf68ff96baf4.ctf.site 10000 | xxd
00000000: 5e43 5e45 5e46 5e47 5e48 090d 0a5e 4b5e  ^C^E^F^G^H...^K^
00000010: 4c0d 0a5e 4e5e 4f30 3132 3341 4243 4445  L..^N^O0123ABCDE
00000020: 4661 6263 6465 66ff fefd fc48 656c 6c6f  Fabcdef....Hello
00000030: 2c20 7768 6174 2773 2079 6f75 7220 7465  , what's your te
00000040: 616d 206e 616d 653f 20                   am name?
```

## solution

Use angr.
You need to add a constraint about the filter.

## implementation

``` python
#!/usr/bin/env python2
import angr # angr-5.6.8.22
import simuvex

p = angr.Project("./FUck_binary")
state = p.factory.entry_state()

key_length = 300
key = state.se.BVS(name="key", size=key_length*8)
for i in range(key_length):
    c = key[i*8+7 : i*8]
    state.se.add(0x20 <= c)
    state.se.add(c != 0x7e)
state.se.simplify()

class read(simuvex.SimProcedure):
    def run(self, fd, buf, count):
        self.state.memory.store(buf, key)
p.hook_symbol('read', read)

get_flag = 0x403a23
goodbye = 0x4051f1
pathgroup = p.factory.path_group(state)
pathgroup.explore(find=get_flag, avoid=goodbye)

for path in pathgroup.found:
    print repr(path.state.se.any_str(key))
```
