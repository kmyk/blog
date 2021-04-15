---
layout: post
redirect_from:
  - /writeup/algo/codeforces/815-b/
  - /blog/2017/06/18/cf-815-b/
date: "2017-06-18T03:07:25+09:00"
tags: [ "competitive", "writeup", "codeforces", "experiment", "combination", "linearity" ]
---

# Codeforces Round #419 (Div. 1): B. Karen and Test

九条カレンちゃん回だった。ratingは$+54$して$2146$で王手。

## solution

線形性。実験。$N \equiv 1 \mod 4$のときがとても綺麗な形になるので、高々$3$回愚直にやったあと規則性。$O(N \log N)$。

長さ$N$の数列$a = ( a\_i )\_{i \lt N}$を処理するが操作は全て線形。
数列$e\_i$を$i$番目の項だけ$1$でそれ以外$0$な列とすると、答え$f(a) = \sum\_{i \lt N} a\_i f(e\_i)$となる。
このような入力$e\_i$に関して実験する。
$N \equiv 1 \mod 4$のとき、$0$-basedで奇数番目の$f(e\_i) = 0$、偶数$2i$番目なら$f(e\_i) = {}\_{N/2}C\_{i/2}$が分かる。
よって$O(N \log N)$。

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
template <int mod>
int fact(int n) {
    static vector<int> memo(1,1);
    if (memo.size() <= n) {
        int l = memo.size();
        memo.resize(n+1);
        repeat_from (i,l,n+1) memo[i] = memo[i-1] *(ll) i % mod;
    }
    return memo[n];
}
template <int mod>
int choose(int n, int r) { // O(n) at first time, otherwise O(\log n)
    if (n < r) return 0;
    r = min(r, n - r);
    return fact<mod>(n) *(ll) inv(fact<mod>(n-r), mod) % mod *(ll) inv(fact<mod>(r), mod) % mod;
}

constexpr int mod = 1e9+7;
int main() {
    int n; scanf("%d", &n);
    vector<int> a(n); repeat (i, n) scanf("%d", &a[i]);
    {
        int op = +1;
        while (n % 4 != 1) {
            vector<int> b(n-1);
            repeat (i, n-1) {
                b[i] = (a[i] + op * a[i+1] +(ll) mod) % mod;
                op *= -1;
            }
            -- n;
            a = move(b);
        }
        assert (a.size() == n);
    }
    ll result = 0;
    repeat (i, n/2+1) {
        result += a[2*i] *(ll) choose<mod>(n/2, i) % mod;
    }
    result %= mod;
    printf("%lld\n", result);
    return 0;
}
```
