---
layout: post
alias: "/blog/2017/01/16/dwacon-2017-finals-c/"
date: "2017-01-16T23:15:27+09:00"
tags: [ "competitive", "writeup", "dwacon", "atcoder", "reactive", "binary-search" ]
"target_url": [ "https://beta.atcoder.jp/contests/dwacon2017-honsen/tasks/dwango2017final_c" ]
---

# 第3回 ドワンゴからの挑戦状 本選: C - ドワンGo

## solution

1.  とりあえずテレビちゃんに近い$1$点を見つける
    -   空間を円に内接する$R\sqrt{2} \times R\sqrt{2}$の長方形に切ってしらみつぶしにやる
2.  テレビちゃんを円周上に乗せる点を$2$つ見つける
    -   ふつうに二分探索
    -   一方の軸$x$は固定してこれと共に条件を満たす$y_1,y_2$を見つけると後が楽
3.  見つけた$2$円の交点の周囲を試す
    -   三平方の定理とかでいい感じにする

基本的には上でよい。ただしときおり誤差で失敗する。
テレビちゃんを円周上に乗せる点を$(y_1,x), (y_2,x)$としたとき、$y_t \approx \frac{y_1 + y_2}{2}$とすれば誤差は$\pm 1$程度だが、$x_t \approx x \pm \sqrt{R^2 - {\|y_1 - y_2\|}^2}$の誤差は大きい。
この$x_t$の誤差が大きくなるのは特に$\sqrt{R^2 - {\|y_1 - y_2\|}^2}$が小さいときであるというのが観察から分かる。
そこで、1.と2.の間で適当に$x \gets x + \alpha$とするなどして、テレビちゃんを$x$軸方向に見て端に追い遣っておくとよい。

## implementation

### 手元テスト用 ジャッジコード

``` python
#!/usr/bin/env python2
from pwn import * # https://pypi.python.org/pypi/pwntools
import random
import sys
import argparse

L = 1000000
R = 100000
xt = random.randint(0, L)
yt = random.randint(0, L)
log.info('xt = %d', xt)
log.info('yt = %d', yt)

parser = argparse.ArgumentParser()
parser.add_argument('binary', nargs='?', default='./a.out')
parser.add_argument('--log-level', default='debug')
args = parser.parse_args()

context.log_level = args.log_level
p = process(args.binary, stderr=sys.stderr)
for q in range(200):
    try:
        x, y = map(int, p.recvline().split())
    except:
        log.failure('RE')
        sys.exit(1)
    if x == xt and y == yt:
        p.sendline('found')
        log.success('AC')
        log.info('%d queries used', q+1)
        sys.exit(0)
    if (xt - x) ** 2 + (yt - y) ** 2 < R ** 2:
        p.sendline('close')
    else:
        p.sendline('far')
p.sendline('kill')
log.failure('QLE')
sys.exit(1)
```

### 回答

``` c++
#include <iostream>
#include <cmath>
#include <functional>
#include <random>
#include <cassert>
#define repeat(i,n) for (int i = 0; (i) < int(n); ++(i))
#define repeat_from(i,m,n) for (int i = (m); (i) < int(n); ++(i))
using namespace std;

int binsearch(int l, int r, function<bool (int)> p) { // [l, r), p is monotone
    assert (l < r);
    -- l; -- r; // (l, r]
    while (l + 1 < r) {
        int m = (l + r) / 2;
        // (p(m) ? r : l) = m;
        bool it = p(m) ;
        assert ((it ? r : l) != m);
        (it ? r : l) = m;
    }
    return r; // = min { x | p(x) }
}
const int L = 1000001;
const int R =  100000;
const int l = R * sqrt(2) - 3;
bool query(int y, int x) {
    cout << x << ' ' << y << endl;
    cout.flush();
    string s; cin >> s;
    if (s == "found") exit(0);
    if (s == "close") return true;
    if (s == "far")   return false;
    assert (false);
}
pair<int,int> find_close() {
    default_random_engine gen((random_device()()));
    uniform_int_distribution<int> dist(- R/20, 0);
    for (int y = dist(gen); y < L; y += l) {
        for (int x = dist(gen); x < L; x += l) {
            if (query(y + l/2, x + l/2)) {
                return { y + l/2, x + l/2 };
            }
        }
    }
    assert (false);
}
int main() {
    int y, x; tie(y, x) = find_close();
    repeat (i,20) {
        if (query(y, x+R/10)) {
            x += R/10;
        } else {
            if (query(y+R/10, x)) {
                y += R/10;
            } else if (query(y-R/10, x)) {
                y -= R/10;
            } else {
                break;
            }
        }
    }
    int y1 = binsearch(y, y+2*R+1, [&](int y) { return not query(y, x); });
    int y2 = binsearch(y-2*R, y+1, [&](int y) { return     query(y, x); });
    int dy = y1 - y2;
    int dx = sqrt(pow(R, 2) - pow(dy/2.0, 2));
    repeat_from (i, -1, 1+1) {
        repeat_from (j, -5, 5+1) {
            for (int pm : { +1, -1 }) {
                query((y1 + y2) / 2 + i, x + pm*dx + j);
            }
        }
    }
    return 1;
}
```
