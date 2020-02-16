---
layout: post
alias: "/blog/2017/04/10/asis-ctf-quals-2017-shacolla/"
date: "2017-04-10T02:45:22+09:00"
tags: [ "ctf", "writeup", "asis-ctf", "ppc", "sha1" ]
"target_url": [ "https://asis-ctf.ir/challenges/" ]
---

# ASIS CTF Quals 2017: ShaColla

## problem

```
$ ./a.py --log-level info
[+] Opening connection to 66.172.27.77 on port 52317: Done
[*] Hi all, let's go to sha1ing!!
    Are you ready? [Y]es or [N]o:
[*] Send us two distinct string with same length and same sha1 hash, with given condition :)
    ----------------------------------------------------------------------------------------
[*] the sha1 hash shoud be started with 469e8
    Send the first string:
[*] prefix: 469e8
[+] Starting local process './a.out': Done
[*] Process './a.out' stopped with exit code 0
[*] Send the second string:
[*] Good job, you got the flag :)
    ASIS{U_mus7_kn0w_sha1_pr0p3r71es_l1ke_hack3rZ!}
    Quiting ...
[*] Closed connection to 66.172.27.77 port 52317
```

## solution

shattered (<https://shattered.io/>) から衝突する文字列を借りてきて、指示されたprefixになるよう末尾をいじる。
SHA1はblockごとに前から処理していくのでそれが可能。
先頭$320$byteだけ切り出して使わないと遅い。

## implementation

``` python
#!/usr/bin/env python2
import zlib
import hashlib
import itertools
from pwn import * # https://pypi.python.org/pypi/pwntools
import argparse
parser = argparse.ArgumentParser()
parser.add_argument('host', nargs='?', default='66.172.27.77')
parser.add_argument('port', nargs='?', default=52317, type=int)
parser.add_argument('--log-level', default='debug')
args = parser.parse_args()
context.log_level = args.log_level
p = remote(args.host, args.port)

log.info('%s', zlib.decompress(p.recv()))
p.send(zlib.compress('Y'))

log.info('%s', zlib.decompress(p.recv()))
s = zlib.decompress(p.recv())
log.info('%s', s)
prefix = s.splitlines()[0].split()[7]
log.info('prefix: %s', prefix)

with process('a.out') as shattered:
    shattered.sendline(prefix)
    suffix = shattered.recvline().rstrip()
shattered = []
with open('shattered-1.pdf') as fh:
    shattered += [ fh.read() ]
with open('shattered-2.pdf') as fh:
    shattered += [ fh.read() ]
assert hashlib.sha1(shattered[0][: 320] + suffix).hexdigest().startswith(prefix)
assert hashlib.sha1(shattered[1][: 320] + suffix).hexdigest().startswith(prefix)
p.send(zlib.compress(shattered[0][: 320] + suffix))
log.info('%s', zlib.decompress(p.recv()))
p.send(zlib.compress(shattered[1][: 320] + suffix))

log.info('%s', zlib.decompress(p.recv()))
```

``` c
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <openssl/sha.h>
int xctoi(char c) {
    switch (c) {
        case '0': case '1': case '2': case '3': case '4': case '5': case '6': case '7': case '8': case '9':
            return c - '0';
        case 'A': case 'B': case 'C': case 'D': case 'E': case 'F':
            return c - 'A' + 10;
        case 'a': case 'b': case 'c': case 'd': case 'e': case 'f':
            return c - 'a' + 10;
        default:
            exit(EXIT_FAILURE);
    }
}
int main(void) {
    // input
    char prefix_string[2 * SHA_DIGEST_LENGTH + 1];
    scanf("%s", prefix_string);
    uint8_t prefix_0 = (xctoi(prefix_string[0]) << 4) | xctoi(prefix_string[1]);
    uint8_t prefix_1 = (xctoi(prefix_string[2]) << 4) | xctoi(prefix_string[3]);
    uint8_t prefix_2 = (xctoi(prefix_string[4]) << 4);
    // load shattered
    int pdf_length = 320;
    int text_length = pdf_length + 8;
    unsigned char *s = malloc(text_length + 1);
    FILE *fh = fopen("shattered-1.pdf", "r");
    for (int i = 0; i < pdf_length; ++ i) {
        s[i] = fgetc(fh);
    }
    // search
    uint8_t digest[SHA_DIGEST_LENGTH];
#define repeat(c) for (c = 'A'; c <= 'Z'; ++ c)
    repeat (s[pdf_length + 0]) {
    repeat (s[pdf_length + 1]) {
    repeat (s[pdf_length + 2]) {
    repeat (s[pdf_length + 3]) {
    repeat (s[pdf_length + 4]) {
    repeat (s[pdf_length + 5]) {
    repeat (s[pdf_length + 6]) {
    repeat (s[pdf_length + 7]) {
#undef repeat
        SHA1(s, text_length, digest);
        if (digest[0] == prefix_0 && digest[1] == prefix_1 && (digest[2] & 0xf0) == prefix_2) {
            goto done;
        }
    }}}}}}}}
done:
    // output
    s[text_length] = 0;
    printf("%s\n", s + pdf_length);
    return 0;
}
```
