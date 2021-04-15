---
layout: post
redirect_from:
  - /writeup/algo/yukicoder/498/
  - /blog/2017/03/29/yuki-498/
date: "2017-03-29T01:39:22+09:00"
tags: [ "competitive", "writeup", "yukicoder", "combination" ]
"target_url": [ "http://yukicoder.me/problems/no/498" ]
---

# Yukicoder No.498 ワープクリスタル (給料日編)

## solution

クリスタルの使う数を全列挙し、使う順番は組み合わせ${}\_nC_r$で計算。$O(\prod\_{1 \le i \le K} N_i)$。
$K \le 5$かつ$N_i \le 15$なので$\prod N_i \le 7.6 \times 10^5$と小さい。

## implementation

``` c++
#include <cstdio>
#include <vector>
#include <array>
#include <cassert>
#define repeat(i,n) for (int i = 0; (i) < int(n); ++(i))
#define repeat_from(i,m,n) for (int i = (m); (i) < int(n); ++(i))
using ll = long long;
using namespace std;

constexpr int mod = 1e9+7;
ll powmod(ll x, ll y) { // O(log y)
    assert (0 <= x and x < mod);
    assert (0 <= y);
    ll z = 1;
    for (ll i = 1; i <= y; i <<= 1) {
        if (y & i) z = z * x % mod;
        x = x * x % mod;
    }
    return z;
}
ll inv(ll x) { // p must be a prime, O(log p)
    return powmod(x, mod-2);
}
int fact(int n) {
    static vector<int> memo(1,1);
    if (memo.size() <= n) {
        int l = memo.size();
        memo.resize(n+1);
        repeat_from (i,l,n+1) memo[i] = memo[i-1] *(ll) i % mod;
    }
    return memo[n];
}
int choose(int n, int r) { // O(n) at first time, otherwise O(\log n)
    if (n < r) return 0;
    r = min(r, n - r);
    return fact(n) *(ll) inv(fact(n-r)) % mod *(ll) inv(fact(r)) % mod;
}

int main() {
    int w, h, k; scanf("%d%d%d", &w, &h, &k);
    assert (k <= 5);
    array<int, 5> x = {};
    array<int, 5> y = {};
    array<int, 5> n = {};
    repeat (i,k) scanf("%d%d%d", &x[i], &y[i], &n[i]);
    ll acc = 0;
    array<int, 5> i;
    for (i[4] = 0; i[4] <= n[4]; ++ i[4])
    for (i[3] = 0; i[3] <= n[3]; ++ i[3])
    for (i[2] = 0; i[2] <= n[2]; ++ i[2])
    for (i[1] = 0; i[1] <= n[1]; ++ i[1])
    for (i[0] = 0; i[0] <= n[0]; ++ i[0]) {
        ll x_acc = 0;
        ll y_acc = 0;
        repeat (j,k) {
            x_acc += i[j] *(ll) x[j];
            y_acc += i[j] *(ll) y[j];
        }
        if (x_acc == w and y_acc == h) {
            ll cnt = 1;
            int i_acc = 0;
            repeat (j,k) {
                i_acc += i[j];
                cnt = cnt * choose(i_acc, i[j]) % mod;
            }
            acc += cnt;
        }
    }
    acc %= mod;
    printf("%lld\n", acc);
    return 0;
}
```
