---
layout: post
alias: "/blog/2017/04/27/srm-713-easy/"
date: "2017-04-27T11:50:22+09:00"
title: "TopCoder SRM 711 Div1 Easy: PowerEquation"
tags: [ "competitive", "writeup", "topcoder", "srm" ]
---

Div 1/2共に荒れた回。

私の提出よりもっと簡潔な提出もあった。

## solution

$a \le \sqrt{n}$なら愚直に。$a \gt \sqrt{n}$なら$a = c$かつ$1 \le b = d \le n$となる。時間/空間共に$O(\sqrt{n})$。

$a = 1$のときは例外として処理。
$p \ge 2$として、$p = a^b$となる自然数$a, b$が$a = p \land b = 1$以外に存在しないような$p$を非累乗数と呼ぶことにする。
非累乗数$p \le n$に対し$a = p^e \land c = p^f$として$p, e, f$を動かせば有効な組$(a, c)$を尽くせ、特に$e, f \le \log\_a{n}$と十分小さい。
このような$(a, c)$に対し有効な組$(b, d)$の個数は$gcd(e, f)$を使って$O(1)$で求まる。

ただし$p$を$n$まで動かすと間に合わない。
そこで$p \gt \sqrt{n}$なら常に$a = c = p$となることを使ってまとめる。
区間$(\sqrt{n}, n]$中の非累乗数の数を$k$とすると、それらから見つかる組$(a, b, c, d)$の数は$kn$となる。


## implementation

検算にはHaskellが最強

``` haskell
>>> let n = 10 in length $ do { a <- [1..n]; c <- [1..n]; b <- [1..n]; d <- [1..n]; guard (a^b == c^d) }
222
```

``` c++
#include <bits/stdc++.h>
#define repeat(i,n) for (int i = 0; (i) < (n); ++(i))
#define repeat_from(i,m,n) for (int i = (m); (i) < (n); ++(i))
typedef long long ll;
using namespace std;
class PowerEquation { public: int count(int n); };
template <typename T> T gcd(T a, T b) { while (a) { b %= a; swap(a, b); } return b; }
template <typename T> T lcm(T a, T b) { return (a * b) / gcd(a,b); }

constexpr int mod = 1e9+7;
int PowerEquation::count(int n) {
    int sqrt_n = ceil(sqrt(n));
    // perfect powers
    vector<int> is_perfect_power(sqrt_n+1);
    int large_perfect_power = 0;
    is_perfect_power[0] = true;
    is_perfect_power[1] = true;
    repeat_from (a,2,sqrt_n+1) if (not is_perfect_power[a]) {
        ll a_k = a*a;
        for (; a_k <= sqrt_n; a_k *= a) {
            is_perfect_power[a_k] = true;
        }
        for (; a_k <= n; a_k *= a) {
            large_perfect_power += 1;
        }
    }
    // count
    ll result = 0;
    // // for a = c = 1
    result += n *(ll) n % mod;
    // // small not-perfect-power numbers
    repeat (p,sqrt_n+1) if (not is_perfect_power[p]) {
        int log_a = 1;
        for (ll a = p; a <= n; a *= p, ++ log_a) {
            int log_c = 1;
            for (ll c = p; c <= n; c *= p, ++ log_c) {
                int d = gcd(log_a, log_c);
                result += n / max(log_a/d, log_c/d);
            }
        }
    }
    result %= mod;
    // // large not-perfect-power numbers
    result += ((n - sqrt_n) - large_perfect_power) *(ll) n % mod;
    result %= mod;
    return result;
}
```
