---
layout: post
redirect_from:
  - /writeup/algo/atcoder/arc-060-d/
  - /blog/2018/01/04/arc-060-d/
date: "2018-01-04T11:55:17+09:00"
tags: [ "competitive", "writeup", "atcoder", "arc", "square-root" ]
"target_url": [ "https://beta.atcoder.jp/contests/arc060/tasks/arc060_b" ]
---

# AtCoder Regular Contest 060: D - 桁和 / Digit Sum

## 反省

実験すると$f(b, n)$の値は$b$に従って基本的には単調減少したまに跳ね上がるのこぎり波のような形。
波の$1$周期を切り出して二分探索を繰り返せば通るかなと思ったが、バグるしちょっと遅いしでだめだった。

## solution

$b \gt \sqrt{n}$なら$n$は$b$進数$2$桁なので具体的に処理できる。$O(\sqrt{n})$。

$2 \le b \le \sqrt{n}$なら愚直に探索。
$\sqrt{n} \lt b$なら$n \lt b^2$なので$n = pb + q$な$0 \le p, q \lt b$が存在して$f(b, n) = p + q$。
$s = p + q = p + (n - pb)$とすれば$b = \frac{s - n}{p} + 1$であり、$b$を$p \lt \sqrt{n}$からの関数で書ける。
この$p$を総当たりすればよい。

$n \le s$の場合に注意。
TLEしたらたぶんどこかで$b = 1$になってしまっている。

## implementation

``` c++
#include <bits/stdc++.h>
#define REP3(i, m, n) for (int i = (m); (i) < int(n); ++ (i))
#define REP3R(i, m, n) for (int i = int(n) - 1; (i) >= int(m); -- (i))
using ll = long long;
using namespace std;

ll f(ll b, ll n) {
    if (b < 2) return -1;
    ll acc = 0;
    for (; n; n /= b) acc += n % b;
    return acc;
}

ll solve(ll n, ll s) {
    // search lower half
    int sqrt_n = min<ll>(n, sqrt(n) + 3);
    REP3 (b, 2, sqrt_n) if (f(b, n) == s) return b;
    // search upper half
    if (s == n) return n + 1;
    REP3R (a, 1, sqrt_n) {
        ll b = (n - s) / a + 1;
        if (f(b, n) == s) return b;
    }
    return -1;
}

int main() {
    ll n, s; scanf("%lld%lld", &n, &s);
    ll result = solve(n, s);
    printf("%lld\n", result);
    return 0;
}
```
