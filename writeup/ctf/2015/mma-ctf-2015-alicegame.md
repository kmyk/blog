---
layout: post
alias: "/blog/2016/11/23/mma-ctf-2015-alicegame/"
date: "2016-11-23T03:31:05+09:00"
title: "MMA CTF 2015: Alicegame"
tags: [ "ctf", "writeup", "mmactf", "crypto", "elgamal-encryption", "discrete-logarithm-problem", "baby-step-giant-step", "pohlig-hellman" ]
"target_url": [ "https://github.com/ctfs/write-ups-2015/tree/master/mma-ctf-2015/crypto/alice-game-250" ]
---

安全素数を使わなかったときのElGamal暗号を破る問題。

## solution

`server.py`が用いているのは[ElGamal暗号](https://ja.wikipedia.org/wiki/ElGamal%E6%9A%97%E5%8F%B7)である。
離散対数問題の難しさを根拠とする公開鍵暗号で、公開鍵を$(g, g^x, p)$、秘密鍵を$(x, p)$とする。
平文$m$に対し、乱数$r \in \\{ 0, 1, \dots, p-1 \\}$を使って暗号文は$(g^r, mg^{xr})$。

離散対数問題が解ければElGamal暗号は破れるのだが、素数$p$の性質が悪いと比較的簡単に解ける。
Eular関数を素因数分解して$\phi(p) = p-1 = \prod q_i$であるとして$O(\sum_i \sqrt{q_i} \log{q_i})$になる(Pohlig-Hellman algorithm)。
これに耐性のある$p = 2q+1$の形の素数を安全素数と呼ぶ。

encryption oracleを適当にすれば公開鍵$(g, g^x, p)$が得られ、またこれ以上は何も得られない。
接続終了時に得られる暗号文$(g^r, mg^{xr})$と合わせて複合化する。
素数$p$は単に`Crypto.Util.number.getPrime(201)`で生成されているので、ガチャをすれば非安全素数にできる。

### Pohlig-Hellman algorithm

離散対数問題$g^x \equiv y \pmod{p}$を解く手法。

$p$のEular関数$\phi(p)$は因数分解して$\phi(p) = p-1 = \prod q_i$であるとする。各$q_i$は(素数である必要はないが)互いに素とする。

各$q_i$について$x$を割り、$x = a_i q_i + b_i$で$0 \le b_i \lt q_i$とする。$\phi(p)$の性質$g^{\phi(p)} \equiv 1 \pmod{p}$を使い:
$$ \begin{array}{rcl}
y^{\frac{\phi(p)}{q_i}} & = & {(g^x)}^{\frac{phi(p)}{q_i}} \pmod{p} \\\\
                        & = & g^{a_i\phi(p) + b_i\frac{phi(p)}{q_i}} \pmod{p} \\\\
                        & = & g^{a_i\phi(p)} g^{b_i\frac{phi(p)}{q_i}} \pmod{p} \\\\
                        & \equiv & g^{b_i\frac{phi(p)}{q_i}} \pmod{p}
\end{array} $$

これは$y_i = y^{\frac{\phi(p)}{q_i}}, g_i = g^{\frac{phi(p)}{q_i}}$と書けば$y_i \equiv g_i^{b_i} \pmod{p}$という離散対数問題に帰着する。
しかし$g_i$の位数は小さい、つまり$g_i^{q_i} = g^{\phi(p)} \equiv 1 \pmod{p}$であるので、この問題は$p = q_i$だった場合と同程度の速度$O(\sqrt{q_i} \log{q_i})$で解ける(baby-step giant-step法)。

これらを解いてまとめると$x$と$a_0, a_1, \dots, a\_{k-1}$が変数の連立方程式になる:
$$ \begin{cases}
x & = & a_0 q_0 + b_0 \\\\
x & = & a_1 q_1 + b_1 \\\\
  & \vdots & \\\\
x & = & a\_{k-1} q\_{k-1} + b\_{k-1}
\end{cases} $$
未知変数が多いため単純には解けない。

しかし各$i$について$b_i \lt q_i$であったので、各等式で$q_i$で剰余を取ると:
$$ \begin{cases}
x & \equiv & b_0 \pmod{q_0} \\\\
x & \equiv & b_1 \pmod{q_1} \\\\
  & \vdots & \\\\
x & \equiv & b\_{k-1} \pmod{q\_{k-1}}
\end{cases} $$
各$q_i$は互いに素に取ると約束していたのでこれは中国人剰余定理で解け、$x$が求まる。


## implementation

素因数分解はPARI/GPに任せた。Pohlig Hellmanはやってくれないぽいので自分で書いた。
素数ガチャはけっこう時間がかかる。

``` c++
#include <iostream>
#include <vector>
#include <algorithm>
#include <tuple>
#include <cassert>
#include <boost/multiprecision/cpp_int.hpp>
#include <experimental/optional>
#define repeat(i,n) for (int i = 0; (i) < (n); ++(i))
#define whole(f,x,...) ([&](decltype((x)) whole) { return (f)(begin(whole), end(whole), ## __VA_ARGS__); })(x)
typedef long long ll;
using namespace std;
using namespace std::experimental;

namespace mp = boost::multiprecision;
using integer = mp::cpp_int;

template <class Integer>
Integer powi(Integer x, Integer y, Integer p) { // O(log y)
    assert (y >= 0);
    x = (x % p + p) % p;
    Integer z = 1;
    for (Integer i = 1; i <= y; i <<= 1) {
        if (y & i) z = z * x % p;
        x = x * x % p;
    }
    return z;
}
optional<integer> baby_step_giant_step(integer g, integer y, integer n, ll order = 0) {
    assert (0 <= g and g < n);
    assert (0 <= y and y < n);
    if (not order) order = ll(n);
    int h = sqrt(order) + 3;
    vector<pair<integer,int> > p(h+1);
    p[0] = { y, 0 };
    repeat (b,h) p[b+1] = { p[b].first * g % n, b+1 };
    whole(sort, p);
    integer gh = powi<integer>(g, h, n);
    integer gah = 1;
    repeat (a,h) {
        auto it = whole(lower_bound, p, make_pair(gah, -1));
        if (a != 0 and it != p.end()) {
            integer b = it->second;
            if (powi<integer>(g, a * h - b, n) == y) return optional<integer>( a *(ll) h - b );
        }
        gah = gah * gh % n;
    }
    return optional<integer>();
}

pair<integer,integer> extgcd(integer a, integer b) {
    if (b == 0) return { 1, 0 };
    integer na, nb; tie(na, nb) = extgcd(b, a % b);
    return { nb, na - a/b * nb };
}
integer modinv(integer a, integer n) { // a and n must be relatively prime, O(log n)
    return (extgcd(a, n).first % n + n) % n;
}
integer chinese_remainder_theorem(vector<pair<integer,integer> > const & eqn) {
    integer x = 1;
    integer m = 1;
    for (auto it : eqn) {
        integer a, n; tie(a, n) = it;
        x += m * (a - x) * modinv(m, n);
        m *= n;
    }
    return (x % m + m) % m;
}

integer pohlig_hellman(integer g, integer y, integer p, vector<integer> qs) {
    // make pairwise relatively prime for chinese remainder theorem
    for (int i = 1; i < qs.size(); ++ i) {
        repeat (j, i) {
            if (gcd(qs[i-1], qs[i]) != 1) {
                qs[i-1] *= qs[i];
                qs.erase(qs.begin() + i);
                i = 0;
                break;
            }
        }
    }
    repeat (i, qs.size()) repeat (j, i) assert (gcd(qs[i], qs[j]) == 1);
    // baby-step giant-step
    vector<pair<integer,integer> > eqn;
    for (integer qi : qs) {
        assert ( (p-1) % qi == 0 );
        integer gi = powi<integer>(g, (p-1)/qi, p);
        integer yi = powi<integer>(y, (p-1)/qi, p);
        integer xi; { auto it = baby_step_giant_step(gi, yi, p, ll(qi)); assert (it); xi = *it; }
        assert (powi<integer>(gi, xi, p) == yi);
        eqn.emplace_back(xi, qi);
    }
    // chinese remainder theorem
    integer x = chinese_remainder_theorem(eqn);
    assert (powi<integer>(g, x, p) == y);
    return x;
}

int main() {
    integer g, y, p; cin >> g >> y >> p;
    int n; cin >> n;
    vector<integer> qs(n); repeat (i,n) cin >> qs[i];
    integer x = pohlig_hellman(g, y, p, qs);
    assert (powi<integer>(g, x, p) == y);
    cout << x << endl;
    return 0;
}
```

``` python
#!/usr/bin/env python2
import ast
import tempfile
from pwn import * # https://pypi.python.org/pypi/pwntools
import argparse
parser = argparse.ArgumentParser()
parser.add_argument('host', nargs='?', default='cry1.chal.mmactf.link')
parser.add_argument('port', nargs='?', default=39985, type=int)
args = parser.parse_args()

while True:
    try:
        with remote(args.host, args.port) as proc:
            assert proc.recvline().strip() == 'Encryption Oracle'
            def encrypt(m, r):
                proc.recvuntil('m = ')
                proc.sendline(str(m))
                proc.recvuntil('r = ')
                proc.sendline(str(r))
                c1, c2 = ast.literal_eval(proc.recvline())
                return c1, c2

            # get g, h
            g, h = encrypt(1, 1)
            log.info('g = %d', g)
            log.info('h = %d', h)

            # get p
            h1 = h
            for k in range(10-1):
                _, h2 = encrypt(2**(k+1), 1)
                p = 2*h1 - h2
                if p == 0:
                    h1 = h2
                else:
                    break
            log.info('p = %d', p)
            assert p > 0

            # get ciphertext
            proc.sendline()
            proc.recvuntil('My Secret Message: ')
            c1, c2 = ast.literal_eval(proc.recvline())
            log.info('c1 = %d', c1)
            log.info('c2 = %d', c2)

        # use PARI/GP for factorization
        qs = []
        with tempfile.NamedTemporaryFile(suffix='.gp') as fh:
            fh.write('allocatemem(800000000)\n')
            fh.write('p = {}\n'.format(p))
            fh.write('v = [p-1, factor(p-1)]\n')
            fh.write('print(factor(p-1))\n')
            fh.write('quit\n')
            fh.flush()
            with process([ 'gp', '--quiet', fh.name ]) as proc:
                assert 'new stack size' in proc.recvline()
                factor = proc.recvline().strip().strip('[]').split(';')
                for s in factor:
                    try:
                        q, cnt = map(int, s.split(','))
                    except ValueError:
                        assert False
                    qs += [ q ] * cnt
        log.info('prime factors of p-1: %s', str(qs))
        if max(qs) > 10**14:  # expect small factors
            log.error('too large')

        # do Pohlig Hellman
        with process('./a.out') as proc:
            proc.sendline(str(g))
            proc.sendline(str(h))
            proc.sendline(str(p))
            proc.sendline(str(len(qs)))
            for q in qs:
                proc.sendline(str(q))
            x = int(proc.recvline())
        log.info('x = %d', x)
        assert pow(g, x, p) == h

        # get plaintext
        m = c2 * pow(pow(c1, x, p), p-2, p) % p
        log.info('m = %d', m)
        log.info('flag = %s', hex(m)[2:].decode('hex'))

        break
    except AssertionError:
        pass
    except pwnlib.exception.PwnlibException:
        pass
```
