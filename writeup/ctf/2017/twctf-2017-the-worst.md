---
layout: post
redirect_from:
  - /blog/2017/09/04/twctf-2017-the-worst/
date: "2017-09-04T13:34:22+09:00"
tags: [ "ctf", "writeup", "twctf", "crypto", "rsa", "coppersmiths-attack" ]
---

# Tokyo Westerns CTF 3rd 2017: The Worst

## problem

RSA暗号。
暗号化に使われたコード `encrypt.c` が与えられるので復号せよ。

## solution

1.  `srand()`がないのでflag長を仮定すればpaddingが定まる
2.   Coppersmith's attack

paddingは`rand()`により生成されているが`srand()`がないので予測できる。
flag長$\lt 32$を総当たりすればpaddingは決定できる。
このpaddingはflag長に対して十分長いので、平文のほとんどが分かっていることになる。

特に平文$m$の下位bitが$n$のbit数の $1-1/e$ 以上分かっていることになり、Coppersmith's attackが使える。
$\overline{m} = \mathrm{padding}$で$k = (\text{paddingのbit数})$とすれば多項式$f(x) = (\overline{m} + 2^k x)^e - c \equiv 0 \pmod{n}$の解$x$を使って$m = \overline{m} + 2^k x$であり、解$x$がflagである。
これはsagemathに投げれば解いてくれるのでflagが得られる。

参考: <http://inaz2.hatenablog.com/entry/2016/01/20/022936>

## implementation

``` c
#include <gmp.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#define BITS 1024
#define N "d1e44ef6c387eeff8b4852372a68cfdcfe3c14da22f1933e3d0fb11d434f480e3415ab08ee42e8d5a7a5ad34e1c114e5d7f2fa970eb968d492542089325301f4090c850c4ece500388d720fb7b5e2772a063ecf238675b8bcde0cb8ba54eb663d74b80e459c803980d7f5cbe4fc76aa036dfc3d6e7a7ec750f2a4ef2658c9029"
#define e 3

char flag[BITS / 8];
char message[BITS];
void read_flag() {
  int i = 0;
  fgets(flag, 32, stdin);
  for(i = strlen(flag); i < sizeof(flag); i++) {
    flag[i] = rand() % 256;
  }
}

int main() {
  int i, j;
  mpz_t m, n, c;
  mpz_init(m);
  mpz_init(n);
  mpz_init(c);

  read_flag();
  for(i = 0; i < sizeof(flag); i++) {
    sprintf(&message[i * 2], "%02x", (unsigned int)flag[i]);
  }
  mpz_set_str(n, N, 16);
  mpz_set_str(m, message, 16);
  mpz_powm_ui(c, m, e, n);
  fprintf(stderr, "m = 0x");
  mpz_out_str(stdout, 16, m);
  puts("");
  fprintf(stderr, "c = 0x");
  mpz_out_str(stdout, 16, c);
  puts("");
}
```

``` python
#!/usr/bin/env python3
import subprocess

def encrypt(s):
    proc = subprocess.run('./a.out', input=s, stdout=subprocess.PIPE)
    lines = proc.stdout.decode().splitlines()
    m = int(lines[0], 16)
    c = int(lines[1], 16)
    return m, c

e = 3
n = 0xd1e44ef6c387eeff8b4852372a68cfdcfe3c14da22f1933e3d0fb11d434f480e3415ab08ee42e8d5a7a5ad34e1c114e5d7f2fa970eb968d492542089325301f4090c850c4ece500388d720fb7b5e2772a063ecf238675b8bcde0cb8ba54eb663d74b80e459c803980d7f5cbe4fc76aa036dfc3d6e7a7ec750f2a4ef2658c9029
c = 0x998225e156e8d77d3d936283a3f04aba11da3365e776ee5f779dcda44176698908d0970ad5daa32b774e023351b1237783c876e8be62cccddcad6adb362925b6b611e82995a53a1df97b15af55394fe0b544d59b6fd6d3057a5e448b40b2405ffcc3a7e8115cfb57b43729dcfe410c17063cf6d63fdc6c621e2e845934b7c32f
for newline in [ '', '\n', '\r\n', '\r' ]:
    for l in range(32):
        flag = 'A' * l + newline
        mbar, _ = encrypt(flag.encode())
        print(e)
        print(n)
        print(c)
        print(mbar)
        print(len(flag) * 8)
```

``` python
#!/usr/bin/env sagemath
from sage.all import *

while True:
    e = input()
    n = input()
    c = input()
    mbar = input()
    kbits = input()
    e, n, c, mbar, kbits = map(sage.rings.integer.Integer, [ e, n, c, mbar, kbits ])

    nbits = n.nbits()
    beta = 0.5
    epsilon = beta^2/7

    PR.<x> = PolynomialRing(Zmod(n))
    f = (mbar + 2 ^ (nbits - kbits - 10) * x)^e - c
    f = f.monic()

    xs = f.small_roots(X=2^(kbits + 20), beta=beta)
    for x in xs:
        m = mbar + 2 ^ (nbits - kbits - 10) * x
        print m
        if pow(m, e, n) == c:
            print 'found'
            print 'm =', hex(int(m))
```
