---
layout: post
alias: "/blog/2017/01/30/seccon-finals-2016-pidrandom/"
date: "2017-01-30T03:49:25+09:00"
tags: [ "ctf", "writeup", "seccon", "rev" ]
---

# SECCON finals 2016: 六(6) pidrandom

## problem

実行時のPIDを元に文字列を変換するプログラムが与えられるので逆変換する問題。入力は`flag.txt` (とPID`$$`)で、出力は`encrypted.txt`。

``` sh
$ cat encrypted.txt
dc21110bdac4c91f45895063a68859075880721652e643b6ccedc7849d228917d9529a2cc73baf1572a255bfe0dc70ab3f652716ad5c4b

$ echo foo > flag.txt

$ ./encrypt
pid=30298

$ cat encrypted.txt
9518f9
```

## solution

PIDはそう大きくならないので総当たりする。
入力文字列は`SECCON{***********************************************}`とでもしておいて、出力の先頭 (特にその前から$14$文字)が逆変換対称と一致するようなPIDを探す。
これは$3273$であった。
PIDを好きに固定するには`LD_PRELOAD`を使って`getpid()`をoverrideする。

また、文字はそれぞれ独立に変換されるようなので、`SECCON{AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA}`や`SECCON{BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB}`のように可能な文字を全て試してみればよい。

flag: `SECCON{U 5h0u1d B Carefu1 2 Initia1ize 7he Rand0m 5eed}`

## implementation

``` sh
$ cat getpid.c
#include <stdlib.h>
int getpid(void) {
    return atoi(getenv("FIXED_PID"));
}

$ gcc -m32 -shared -fPIC getpid.c -o getpid.so

$ LD_PRELOAD=./getpid.so FIXED_PID=1234 ./encrypt
pid=1234
```

``` python
#!/usr/bin/env python2
from pwn import * # https://pypi.python.org/pypi/pwntools
import argparse
parser = argparse.ArgumentParser()
parser.add_argument('--log-level', default='debug')
parser.add_argument('--binary', default='./encrypt')
parser.add_argument('--libc')
args = parser.parse_args()
context.log_level = args.log_level

encrypted = 'dc21110bdac4c91f45895063a68859075880721652e643b6ccedc7849d228917d9529a2cc73baf1572a255bfe0dc70ab3f652716ad5c4b'
#            dc21110bdac4c90b24fd791292f87c665be1703661c26482bc8cb4e5950da122f172ea04fc1fce635b8634acc0f355da1304533289794b
#            S E C C O N {                                                                                               } 

def encrypt(flag, pid):
    with open('flag.txt', 'w') as fh:
        fh.write(flag + '\n')
    with process(args.binary, env={ 'LD_PRELOAD': './getpid.so', 'FIXED_PID': str(pid) }) as p:
        pass
    with open('encrypted.txt') as fh:
        return fh.read().strip()

# f = []
# for pid in range(50000):
#     f += [ encrypt('SECCON{AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA}', pid) ]
#     if f[-1][: 14] == encrypted[: 14]:
#         break
pid = 3273

l = len(encrypted) / 2
flag = [ None ] * l
for c in range(256):
    c = chr(c)
    s = encrypt(c * l, pid)
    for i in range(l):
        if s[i*2:][:2] == encrypted[i*2:][:2]:
            flag[i] = c
print(flag)
print(''.join(flag))
```
