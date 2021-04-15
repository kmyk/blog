---
layout: post
redirect_from:
  - /writeup/ctf/2016/seccon-2016-online-vigenere/
  - /blog/2016/12/11/seccon-2016-online-vigenere/
date: "2016-12-11T22:06:03+09:00"
tags: [ "ctf", "writeup", "seccon", "crypto", "vigenere-cipher" ]
"target_url": [ "https://score-quals.seccon.jp/question/a5480aaca0b46d7785bd9916186ede557a91835f" ]
---

# SECCON 2016 Online CTF: Vigenere

CODEVS帰りの新幹線でCTFの布教をしながら解いた。
影白さんとhikaliumさんが途中までやって残りは実装だけになっていて、その続きをした。

## problem

Vigenere暗号。

鍵$k$, 平文$p$, 暗号文$c$が以下のように与えられ、確認用の$\mathrm{md5}(p)$と変換表が与えられる。

```
k: ????????????
p: SECCON{???????????????????????????????????}
c: LMIG}RPEDOEEWKJIQIWKJWMNDTSR}TFVUFWYOCBAJBQ

k=key, p=plain, c=cipher, md5(p)=f528a6ab914c1ecf856a1d93103948fe

 |ABCDEFGHIJKLMNOPQRSTUVWXYZ{}
-+----------------------------
A|ABCDEFGHIJKLMNOPQRSTUVWXYZ{}
B|BCDEFGHIJKLMNOPQRSTUVWXYZ{}A
C|CDEFGHIJKLMNOPQRSTUVWXYZ{}AB
D|DEFGHIJKLMNOPQRSTUVWXYZ{}ABC
E|EFGHIJKLMNOPQRSTUVWXYZ{}ABCD
F|FGHIJKLMNOPQRSTUVWXYZ{}ABCDE
G|GHIJKLMNOPQRSTUVWXYZ{}ABCDEF
H|HIJKLMNOPQRSTUVWXYZ{}ABCDEFG
I|IJKLMNOPQRSTUVWXYZ{}ABCDEFGH
J|JKLMNOPQRSTUVWXYZ{}ABCDEFGHI
K|KLMNOPQRSTUVWXYZ{}ABCDEFGHIJ
L|LMNOPQRSTUVWXYZ{}ABCDEFGHIJK
M|MNOPQRSTUVWXYZ{}ABCDEFGHIJKL
N|NOPQRSTUVWXYZ{}ABCDEFGHIJKLM
O|OPQRSTUVWXYZ{}ABCDEFGHIJKLMN
P|PQRSTUVWXYZ{}ABCDEFGHIJKLMNO
Q|QRSTUVWXYZ{}ABCDEFGHIJKLMNOP
R|RSTUVWXYZ{}ABCDEFGHIJKLMNOPQ
S|STUVWXYZ{}ABCDEFGHIJKLMNOPQR
T|TUVWXYZ{}ABCDEFGHIJKLMNOPQRS
U|UVWXYZ{}ABCDEFGHIJKLMNOPQRST
V|VWXYZ{}ABCDEFGHIJKLMNOPQRSTU
W|WXYZ{}ABCDEFGHIJKLMNOPQRSTUV
X|XYZ{}ABCDEFGHIJKLMNOPQRSTUVW
Y|YZ{}ABCDEFGHIJKLMNOPQRSTUVWX
Z|Z{}ABCDEFGHIJKLMNOPQRSTUVWXY
{|{}ABCDEFGHIJKLMNOPQRSTUVWXYZ
}|}ABCDEFGHIJKLMNOPQRSTUVWXYZ{
```

## solution

以下のように判明している平文から、鍵が`VIGENERE????`だということまでは分かる。

```
k: ????????????
p: SECCON{?????
   ????????????
   ????????????
   ??????}
```

一方で、この時点で`????`であるような$4$文字については自由に決めてしまえる。
よって、$\mathrm{md5}(p)$: `f528a6ab914c1ecf856a1d93103948fe`であるものを全探索するしかない。
$26^4 \approx 4.6 \times 10^5$と小さいので可能。

## implementation

``` python
#!/usr/bin/env python3
import hashlib
l = 12
c = 'LMIG}RPEDOEEWKJIQIWKJWMNDTSR}TFVUFWYOCBAJBQ'
md5_p = 'f528a6ab914c1ecf856a1d93103948fe'

at = lambda xs, i: xs[i % len(xs)]
alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ{}'
def encrypt(k, p):
    return ''.join([at(alphabet, + alphabet.index(at(k, i)) + alphabet.index(p[i])) for i in range(len(p))])
def decrypt(k, p):
    return ''.join([at(alphabet, - alphabet.index(at(k, i)) + alphabet.index(p[i])) for i in range(len(p))])

k_base = 'VIGENERE????'
for k0 in alphabet:
    for k1 in alphabet:
        for k2 in alphabet:
            for k3 in alphabet:
                k = k_base.replace('????', k0 + k1 + k2 + k3)
                p = decrypt(k, c)
                if hashlib.md5(p.encode()).hexdigest() == md5_p:
                    print('k:', k)
                    print('p:', p)
```
