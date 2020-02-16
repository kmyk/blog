---
layout: post
date: 2018-09-01T22:54:45+09:00
tags: [ "competitive", "writeup", "atcoder", "arc" ]
"target_url": [ "https://beta.atcoder.jp/contests/arc102/tasks/arc102_a" ]
---

# AtCoder Regular Contest 102: C - Triangular Relationship

## 解法

$a + b \equiv b + c \equiv c + a \equiv 0 \pmod{K}$ を整理すると少なくとも $a \equiv - b \equiv c \pmod{K}$ であることが分かる。
$a$ だけ決めれば他が決まるのでこれを数えれば $O(N)$。
特に $a \equiv -a \equiv b \equiv -b \equiv c \equiv -c \pmod{K}$ も言えるので $K$ の偶奇で場合分けすれば $O(1)$。

## メモ

「$a + b, b + c, c + a$ がすべて $K$ の倍数」でなくて「$a + b + c$ が $K$ の倍数」だと難しくなります。
コンテスト本番中しばらく考えていましたが分かりませんでした。

## 実装

``` c++
#include <iostream>
#include <vector>
#define REP(i, n) for (int i = 0; (i) < (int)(n); ++ (i))
#define REP3(i, m, n) for (int i = (m); (i) < (int)(n); ++ (i))
using ll = long long;
using namespace std;

ll solve(ll n, ll k) {
    vector<ll> f(k);
    REP3 (i, 1, n + 1) {
        f[i % k] += 1;
    }
    ll cnt = 0;
    REP (a, k) {
        int b = (- a + k) % k;
        int c = a;
        if ((a + c) % k == 0) {
            cnt += f[a] * f[b] * f[c];
        }
    }
    return cnt;
}

int main() {
    int n, k; cin >> n >> k;
    cout << solve(n, k) << endl;
    return 0;
}
```
