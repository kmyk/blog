---
layout: post
alias: "/blog/2017/09/12/twctf-2017-backpackers-problem/"
date: "2017-09-12T21:28:33+09:00"
title: "Tokyo Westerns CTF 3rd 2017: Backpacker's Problem"
tags: [ "ctf", "writeup", "ppc", "meet-in-the-middle", "overflow" ]
---

## note

-   本番では解けず
    -   チームの人が全探索を書いてた
    -   `scryptos.crypto.attack.knapsackutil.merkle_hellman_low_density_CLOS` とかしたけどだめだった
    -   焼き鈍しっぽくしてみたけどだめだった
    -   overflowには気付いた
    -   LLLだと思って知らないからと後回しした
-   次を参考にして解いた: <http://qiita.com/kusano_k/items/b1fff79d535f4b26cdd0#backpackers-problem>
-   別解としては疑似乱数の解析によるものがあった。好き。<https://github.com/ymgve/ctf-writeups/tree/master/tokyowesterns2017/ppc-backpackers_problem>。
-   LLLでも解けるんじゃないかなと思ってる (writeup見つけてないので確証はなし)
-   flag: `TWCTF{CPP_have_some_traps}`

## solution

生成などでは `__int128` が用いられているが、$125$行目: `check(!std::accumulate(b.begin(), b.end(), 0));` で`int`にcastされてしまっている。
これによりちょうど$x = 0$でなくて$x \equiv 0 \pmod{2^{32}}$な解を提出するのでよい。

最大で$200$個の整数が与えられるが、勝手に$40$個とかだけ選んできてその中だけで解けばよい。$2^{32} \ll 2^{40}$なので解は十分含まれる。
これは半分全列挙が間に合う。
$20$個$20$個に分けて$2^{20}$要素の辞書を$2^{20}$回引けばよい。

## implementation

``` c++
#include <cassert>
#include <cstdint>
#include <iostream>
#include <tuple>
#include <unordered_map>
#include <vector>
#define repeat(i, n) for (int i = 0; (i) < int(n); ++(i))
#define repeat_from(i, m, n) for (int i = (m); (i) < int(n); ++(i))
#define whole(x) begin(x), end(x)

using namespace std;
typedef __int128 int128_t;

std::istream &operator>>(std::istream &is, int128_t &x) {
    std::string s;
    is >> s;
    bool neg = false;
    if(s.size() > 0 && s[0] == '-') {
        neg = true; s = s.substr(1);
    }
    x = 0;
    for(char t: s) x = x * 10 + t - '0';
    if(neg) x = -x;
    return is;
}

std::ostream &operator<<(std::ostream &os, int128_t x) {
    if(x < 0) return os << "-" << (-x);
    else if(x == 0) return os << "0";
    else {
        std::string s = "";
        while(x > 0) {
            s = static_cast<char>('0' + x % 10) + s;
            x /= 10;
        }
        return os << s;
    }
}

int main() {
    // input
    int n; cin >> n;
    vector<int128_t> a(n); repeat (i, n) cin >> a[i];
    // prepare
    vector<uint32_t> b(n);
    repeat (i, n) {
        b[i] = a[i] & 0xffffffff;
    }
    auto generate = [&](int l, int r) {
        vector<pair<uint32_t, uint32_t> > acc;
        acc.emplace_back(0, 0);
        repeat_from (i, l, r) {
            for (int j = acc.size() - 1; j >= 0; -- j) {
                uint32_t sum, used; tie(sum, used) = acc[j];
                acc.emplace_back(sum + b[i], used | (1 << (i - l)));
            }
        }
        return acc;
    };
    // solve
    // // meet in the middle
    int l = min(20, n);
    int r = min(20, max(0, n - l));
    auto acc = generate(0, l);
    unordered_map<uint32_t, uint32_t> dict(acc.begin() + 1, acc.end());
    acc = generate(l, l + r);
    uint64_t result = 0;
    for (auto it : acc) {
        uint32_t sum, used; tie(sum, used) = it;
        if (dict.count(- sum)) {
            result = ((uint64_t)used << l) | dict[- sum];
            break;
        }
    }
    assert (result);
    // output
    cout << __builtin_popcountll(result);
    repeat (i, l + r) {
        if (result & (1ull << i)) {
            cout << ' ' << a[i];
        }
    }
    cout << endl;
    return 0;
}
```

``` python
#!/usr/bin/env python2
import scryptos
from pwn import * # https://pypi.python.org/pypi/pwntools
import argparse
parser = argparse.ArgumentParser()
parser.add_argument('host', nargs='?', default='backpacker.chal.ctf.westerns.tokyo')
parser.add_argument('port', nargs='?', default=39581, type=int)
parser.add_argument('--log-level', default='debug')
args = parser.parse_args()
context.log_level = args.log_level

p = remote(args.host, args.port)

for i in range(20):
    p.recvuntil('[Problem %d]\n' % (i + 1))
    p.recvline()
    s = p.recvline()
    log.info('input: %s', s)
    with process('./a.out', stderr=sys.stderr) as solver:
        solver.sendline(s)
        t = solver.recvline()
    log.info('output: %s', t)
    p.sendline(t)
p.recvall()
```
