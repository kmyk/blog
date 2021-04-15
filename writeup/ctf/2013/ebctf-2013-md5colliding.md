---
layout: post
redirect_from:
  - /writeup/ctf/2013/ebctf-2013-md5colliding/
  - /blog/2016/08/28/ebctf-2013-md5colliding/
date: "2016-08-28T15:29:33+09:00"
tags: [ "ctf", "writeup", "crypto", "katagaitai", "hash" ]
"target_url": [ "http://ebctf.nl/challenges/BIN400" ]
---

# ebctf 2013 md5colliding

[katagaitai CTF勉強会 #5 - 関西|med](https://atnd.org/events/77452)で解いた。

MD5を5重に衝突させろという問題。
MD5には文字列$\alpha$に対し$\mathrm{MD5}(\alpha \oplus \beta) = \mathrm{MD5}(\alpha \oplus \gamma)$な組$(\beta, \gamma)$を求める方法が存在する。Xiaoyun Wangによって発見された手法で、いくつか実装が公開されているので、これを使う。

MD5は入力をchunkに分け前からreduceの様に処理していく構造なので、padding等がからむとどうなるかは分からないが基本的に、$\mathrm{MD5}(\alpha) = \mathrm{MD5}(\beta) \to \mathrm{MD5}(\alpha \oplus \gamma) = \mathrm{MD5}(\beta \oplus \gamma)$が成り立つようだ。
基本となる文字列$\alpha$に対し、$\mathrm{MD5}(\alpha \oplus \beta_1) = \mathrm{MD5}(\alpha \oplus \beta_2)$な$(\beta_1, \beta_2)$、$\mathrm{MD5}(\alpha \oplus \beta_1 \oplus \gamma_1) = \mathrm{MD5}(\alpha \oplus \beta_1 \oplus \gamma_2)$な$(\gamma_1, \gamma_2)$、といくつか求めていき、$\\{ \alpha \oplus \beta_i \oplus \gamma_j \dots \mid i, j, \dots \in 2 \\}$とすると、$n$回の衝突の計算で$O(2^n)$個の全て衝突した文字列が得られる。

衝突には[fastcoll](https://marc-stevens.nl/research/)を用いた。
`MS Windows, PE32 executable, console`でやれ、ということだが、面倒だし本質的ではないので`ELF 64-bit LSB executable`で行った。
これらは末尾に文字列を追加しても変りなく実行できるので、自分自身を読み込んでxorによる総和で分岐するようなコードを$\alpha$としてやればよい。

``` sh
$ md5sum ?.bin
ada244203f79f974859ab0637f6e7c3c  1.bin
ada244203f79f974859ab0637f6e7c3c  2.bin
ada244203f79f974859ab0637f6e7c3c  3.bin
ada244203f79f974859ab0637f6e7c3c  4.bin
ada244203f79f974859ab0637f6e7c3c  5.bin
$ sha1sum ?.bin 
89d3269755f86aa2f785077602589b6a1d24f29f  1.bin
3624954052d77380ed98ae3f71db152e26567a18  2.bin
e31fa7af2fffcc6d43ffe86b954c063b70992728  3.bin
062b6a204bd83a043e324a503d94b0fc8d9771cf  4.bin
e66cfc6cf49c35786192ec074036d3aa5381a678  5.bin
$ for i in {1..5} ; do ./$i.bin ; done
All Eindbazen are wearing wooden shoes
All Eindbazen live in a windmill
All Eindbazen grow their own tulips
All Eindbazen smoke weed all day
All Eindbazen are cheap bastards
```

``` python
#!/usr/bin/env python3
import os
import stat
import tempfile
import functools
import operator
import subprocess
import hashlib
import struct

md5 = lambda s: hashlib.md5(s).hexdigest()
sha1 = lambda s: hashlib.sha1(s).hexdigest()

def fastcoll(s):
    with tempfile.TemporaryDirectory() as dr:
        x = os.path.join(dr, 'x')
        y = os.path.join(dr, 'y')
        z = os.path.join(dr, 'z')
        with open(x, 'w') as fh:
            fh.buffer.write(s)
        subprocess.run(['fastcoll', x, '-o', y, z])
        with open(y) as fh:
            t = fh.buffer.read()[ len(s) : ]
        with open(z) as fh:
            u = fh.buffer.read()[ len(s) : ]
        return t, u

code = '''\
#include <stdio.h>
const char *msgs[5] = {
    "All Eindbazen are wearing wooden shoes",
    "All Eindbazen live in a windmill",
    "All Eindbazen grow their own tulips",
    "All Eindbazen smoke weed all day",
    "All Eindbazen are cheap bastards" };
int main(int argc, char **argv) {
    FILE *fh = fopen(argv[0], "rb");
    int acc = 0;
    for (int c; (c = fgetc(fh)) != EOF; ) acc ^= c;
    puts(msgs[acc % 5]);
    return 0;
}
'''

with tempfile.TemporaryDirectory() as dr:
    x = os.path.join(dr, 'a.c')
    y = os.path.join(dr, 'a.out')
    with open(x, 'w') as fh:
        print(code, file=fh)
    subprocess.run(['gcc', x, '-o', y])
    with open(y) as fh:
        compiled = fh.buffer.read()

def go(s, i):
    if i == 0:
        return [ s ]
    else:
        p, q = fastcoll(s)
        xs = go(s+p, i-1)
        ys = [ s+q + x[len(s+p):]  for x in xs ]
        return xs + ys

while True:
    result = [ None ] * 5
    for binary in go(compiled, 5):
        acc = functools.reduce(operator.xor, binary)
        print(sha1(binary), md5(binary), acc % 5 + 1)
        result[acc % 5] = binary
    if all(result):
        break
for i, binary in enumerate(result):
    name = '%d.bin' % (i + 1)
    with open(name, 'w') as fh:
        fh.buffer.write(binary)
    os.chmod(name, os.stat(name).st_mode | stat.S_IEXEC)
```
