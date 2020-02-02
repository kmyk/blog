---
category: blog
layout: post
date: "2016-09-20T21:41:45+09:00"
title: "Entropies of ASLR/PIE in Ubuntu 16.04"
tags: [ "pwn", "ctf", "aslr", "pie" ]
---

## x86_64

All entropies are too high to bruteforce.
However, only the offset between shared libraries is fixed.

The entropies of heap addresses are relatively small ($13$bit, $8192$) than others.
I suspect, this depends on the implementation of libc.

## x86

The entropies of text or libc is $8$bit. It is hit with only $256$ trials (feasible).
The stack has entropy of $11$bit ($2048$), and the heap is the same to the one of x86\_64.

## data

``` sh
$ uname -a
Linux localhost 4.4.0-36-generic #55-Ubuntu SMP Thu Aug 11 18:01:55 UTC 2016 x86_64 x86_64 x86_64 GNU/Linux
$ gcc --version
gcc (Ubuntu 5.4.1-2ubuntu1~16.04) 5.4.1 20160904
```

``` asm
$ gcc a.c -o x64
$ ./a.py ./x64
text:	[0x400000, 0x400000] (0x0)
heap:	[0x604000, 0x2600000] (0x1ffc000)
libc:	[0x7efc24547000, 0x7ffbedc1d000] (0xffc96d6000)
ld:	[0x7efc24910000, 0x7ffbedfe6000] (0xffc96d6000)
stack:	[0x7ffc028e8000, 0x7ffffe1e5000] (0x3fb8fd000)
heap - text:	[0x204000, 0x2200000] (0x1ffc000)
libc - text:	[0x7efc24147000, 0x7ffbed81d000] (0xffc96d6000)
ld - text:	[0x7efc24510000, 0x7ffbedbe6000] (0xffc96d6000)
stack - text:	[0x7ffc024e8000, 0x7ffffdde5000] (0x3fb8fd000)
libc - heap:	[0x7efc231d8000, 0x7ffbec94c000] (0xffc9774000)
ld - heap:	[0x7efc235a1000, 0x7ffbecd15000] (0xffc9774000)
stack - heap:	[0x7ffc00c22000, 0x7ffffcd79000] (0x3fc157000)
ld - libc:	[0x3c9000, 0x3c9000] (0x0)
stack - libc:	[0x15d3d9000, 0x103cd61b000] (0x10270242000)
stack - ld:	[0x15d010000, 0x103cd252000] (0x10270242000)
```

``` asm
$ gcc -m32 a.c -o x86
$ ./a.py ./x86
text:	[0x8048000, 0x8048000] (0x0)
heap:	[0x8058000, 0xa03c000] (0x1fe4000)
libc:	[0xf74fa000, 0xf75f9000] (0xff000)
ld:	[0xf76db000, 0xf77da000] (0xff000)
stack:	[0xff7df000, 0xfffdc000] (0x7fd000)
heap - text:	[0x10000, 0x1ff4000] (0x1fe4000)
libc - text:	[0xef4b2000, 0xef5b1000] (0xff000)
ld - text:	[0xef693000, 0xef792000] (0xff000)
stack - text:	[0xf7797000, 0xf7f94000] (0x7fd000)
libc - heap:	[0xed4e7000, 0xef559000] (0x2072000)
ld - heap:	[0xed6c8000, 0xef73a000] (0x2072000)
stack - heap:	[0xf57f3000, 0xf7f18000] (0x2725000)
ld - libc:	[0x1e1000, 0x1e1000] (0x0)
stack - libc:	[0x8208000, 0x8abf000] (0x8b7000)
stack - ld:	[0x8027000, 0x88de000] (0x8b7000)
```

``` asm
$ gcc -fPIE -pie a.c -o x64pie
$ ./a.py ./x64pie
text:   [0x5555ad0d9000, 0x5655488f9000] (0xff9b820000)
heap:   [0x5555af197000, 0x5655496f3000] (0xff9a55c000)
libc:   [0x7efbf9679000, 0x7ffbcf5d1000] (0xffd5f58000)
ld:     [0x7efbf9a42000, 0x7ffbcf99a000] (0xffd5f58000)
stack:  [0x7ffc00658000, 0x7ffffef0e000] (0x3fe8b6000)
heap - text:    [0x217000, 0x21fb000] (0x1fe4000)
libc - text:    [0x28b3a813f000, 0x2a9ee4af7000] (0x1eb3c9b8000)
ld - text:      [0x28b3a8508000, 0x2a9ee4ec0000] (0x1eb3c9b8000)
stack - text:   [0x29a82af0d000, 0x2aa94fdbb000] (0x10124eae000)
libc - heap:    [0x28b3a735a000, 0x2a9ee383c000] (0x1eb3c4e2000)
ld - heap:      [0x28b3a7723000, 0x2a9ee3c05000] (0x1eb3c4e2000)
stack - heap:   [0x29a82a4ac000, 0x2aa94dcfd000] (0x10123851000)
ld - libc:      [0x3c9000, 0x3c9000] (0x0)
stack - libc:   [0xeeba8000, 0x10238acd000] (0x10149f25000)
stack - ld:     [0xee7df000, 0x10238704000] (0x10149f25000)
```

``` asm
$ gcc -m32 -fPIE -pie a.c -o x86pie
$ ./a.py ./x86pie
text:   [0x56555000, 0x56654000] (0xff000)
heap:   [0x56569000, 0x58639000] (0x20d0000)
libc:   [0xf74fa000, 0xf75f9000] (0xff000)
ld:     [0xf76db000, 0xf77da000] (0xff000)
stack:  [0xff7dc000, 0xfffda000] (0x7fe000)
heap - text:    [0x13000, 0x1ffa000] (0x1fe7000)
libc - text:    [0xa0eb2000, 0xa1093000] (0x1e1000)
ld - text:      [0xa1093000, 0xa1274000] (0x1e1000)
stack - text:   [0xa91aa000, 0xa9a78000] (0x8ce000)
libc - heap:    [0x9ef37000, 0xa0fe6000] (0x20af000)
ld - heap:      [0x9f118000, 0xa11c7000] (0x20af000)
stack - heap:   [0xa725e000, 0xa993d000] (0x26df000)
ld - libc:      [0x1e1000, 0x1e1000] (0x0)
stack - libc:   [0x8209000, 0x8ad2000] (0x8c9000)
stack - ld:     [0x8028000, 0x88f1000] (0x8c9000)
```

``` c
#include <stdio.h>
int main(void) {
    printf("Hello, world!\n");
    scanf("%*c");
    return 0;
}
```

``` python
#!/usr/bin/env python3
import sys
import os
import re
import time
import subprocess

def vmmap(s, log=False):
    acc = []
    with subprocess.Popen([ s ], stdout=subprocess.DEVNULL) as p:
        time.sleep(0.1)
        path = '/proc/%d/maps' % p.pid
        if log:
            sys.stderr.write('$ cat %s\n' % path)
        with open(path) as fh:
            for line in fh:
                if log:
                    sys.stderr.write(line)
                addr, permission, _, _, _, *name = line.split()
                addr = tuple(map(lambda s: int(s, 16), addr.split('-')))
                name = name[0] if name else None
                acc += [( addr, permission, name )]
        p.kill()
    return acc

def gather(command, n, log=False):
    f = {}
    f['text'] = []
    f['heap'] = []
    f['libc'] = []
    f['ld'] = []
    f['stack'] = []
    for i in range(n):
        for addr, permission, name in vmmap(command, log=log):
            if permission == 'r-xp' and name.endswith(os.path.basename(command)):
                f['text'] += [ addr[0] ]
            if name == '[heap]':
                f['heap'] += [ addr[0] ]
            if permission == 'r-xp' and re.search(r'/libc-\d\.\d\d\.so$', name):
                f['libc'] += [ addr[0] ]
            if permission == 'r-xp' and re.search(r'/ld-\d\.\d\d\.so$', name):
                f['ld'] += [ addr[0] ]
            if name == '[stack]':
                f['stack'] += [ addr[0] ]
    return f

import argparse
parser = argparse.ArgumentParser()
parser.add_argument('command')
parser.add_argument('-v', '--verbose', action='store_true')
parser.add_argument('-n', type=int, default=1024)
args = parser.parse_args()

f = gather(args.command, args.n, log=args.verbose)
ks = sorted(f.keys(), key=lambda k: min(f[k]))
for k in ks:
    l, r = min(f[k]), max(f[k])
    print('%s:\t[%#x, %#x] (%#x)' % (k, l, r, r-l))
for k1 in ks:
    for k2 in ks:
        if ks.index(k1) < ks.index(k2):
            diff = list(map(lambda x1, x2: x2 - x1, f[k1], f[k2]))
            l, r = min(diff), max(diff)
            print('%s - %s:\t[%#x, %#x] (%#x)' % (k2, k1, l, r, r-l))
```
