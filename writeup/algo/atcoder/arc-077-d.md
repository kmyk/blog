---
layout: post
alias: "/blog/2017/07/20/arc-077-d/"
title: "AtCoder Regular Contest 077: D - 11"
date: "2017-07-20T03:11:57+09:00"
tags: [ "competitive", "writeup", "atcoder", "arc", "combination", "inclusion-exclusion-principle" ]
"target_url": [ "https://beta.atcoder.jp/contests/arc077/tasks/arc077_b" ]
---

## solution

組み合わせと包除原理。組合せが前処理$O(n)$で実行$O(1)$なら全体で$O(n)$。

部分列の長さ$k$を固定して独立に解く。
この問題の困難は元の数列中に重複があることである。そうでなければ${}\_nC\_k$が答えであるのだが、重複されて数えられてしまう部分列の数を引かなくてはならない。
重複がちょうどひとつだけなので、そのような部分列の数は重複して出現する数を$a_i = a_j$ ($0 \le i \lt j \lt n + 1$)とすると${}\_{i + (n + 1 - (j + 1))}C\_{k - 1}$となる。

## implementation

``` c++
#include <cassert>
#include <cstdio>
#include <vector>
#define repeat(i, n) for (int i = 0; (i) < int(n); ++(i))
#define repeat_from(i, m, n) for (int i = (m); (i) < int(n); ++(i))
using ll = long long;
using namespace std;

ll powmod(ll x, ll y, ll p) { // O(log y)
    assert (0 <= x and x < p);
    assert (0 <= y);
    ll z = 1;
    for (ll i = 1; i <= y; i <<= 1) {
        if (y & i) z = z * x % p;
        x = x * x % p;
    }
    return z;
}
ll inv(ll x, ll p) { // p must be a prime, O(log p)
    assert ((x % p + p) % p != 0);
    return powmod(x, p-2, p);
}
constexpr int mod = 1e9+7;
int fact(int n) {
    static vector<int> memo(1, 1);
    if (memo.size() <= n) {
        int l = memo.size();
        memo.resize(n+1);
        repeat_from (i, l, n+1) memo[i] = memo[i-1] *(ll) i % mod;
    }
    return memo[n];
}
int choose(int n, int r) { // O(n) at first time, otherwise O(\log n)
    if (n < r) return 0;
    r = min(r, n - r);
    return fact(n) *(ll) inv(fact(n-r), mod) % mod *(ll) inv(fact(r), mod) % mod;
}

int main() {
    // input
    int n; scanf("%d", &n);
    vector<int> a(n + 1); repeat (i, n + 1) scanf("%d", &a[i]);
    // solve
    int dup[2]; {
        vector<int> used(n, -1);
        repeat (i, n + 1) {
            if (used[a[i] - 1] != -1) {
                dup[0] = used[a[i] - 1];
                dup[1] = i;
                break;
            }
            used[a[i] - 1] = i;
        }
    }
    int l = dup[0];
    int m = dup[1] - (dup[0] + 1);
    int r = n + 1 - (dup[1] + 1);
    repeat_from (k, 1, n + 2) {
        ll result = choose(n + 1, k) - choose(l + r, k - 1);
        result = (result + mod) % mod;
        printf("%lld\n", result);
    }
    return 0;
}
```
