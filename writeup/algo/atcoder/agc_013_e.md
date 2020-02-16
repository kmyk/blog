---
layout: post
redirect_from:
  - /writeup/algo/atcoder/agc-013-e/
  - /blog/2017/06/13/agc-013-e/
date: "2017-06-13T02:39:40+09:00"
tags: [ "competitive", "writeup", "atcoder", "arc", "optimization", "dp", "linearity" ]
"target_url": [ "https://beta.atcoder.jp/contests/agc013/tasks/agc013_e" ]
---

# AtCoder Grand Contest 013: E - Placing Squares

$N = 10^9$で剰余が実質ないのでぎりぎり通せる。
意図せず最短コードを得た。

## solution

差分を取って線形な形にしてDP。定数倍最適化。$O(N)$。

愚直なDPを考えると$\mathrm{dp}\_{r}$は区間$[0, r]$での結果と定義し$\mathrm{dp}\_{N}$が全体の答え。
印が付いている位置では$\mathrm{dp}\_{r} = 0$、それ以外では漸化式$\mathrm{dp}\_{r} = \sum\_{0 \le l \lt r} \mathrm{dp}\_{l}(r - l)^2$となる。
これを愚直にやると$O(N^2)$。

以下のように変形する。
$$
    \begin{array}{ccl}
    \mathrm{dp}\_{r+1} & = & \sum\_{0 \le l \lt r+1} \mathrm{dp}\_{l}(r+1 - l)^2 \\\\
                     & = & \sum\_{0 \le l \lt r} \mathrm{dp}\_{l}(r+1 - l)^2 + \mathrm{dp}\_{r} \\\\
                     & = & \sum\_{0 \le l \lt r} \mathrm{dp}\_{l}((r-l)^2 + 2(r-l) + 1) + \mathrm{dp}\_{r} \\\\
                     & = & \sum\_{0 \le l \lt r} \mathrm{dp}\_{l}(r-l)^2 + 2 \sum\_{0 \le l \lt r} \mathrm{dp}\_{l}(r-l) + \sum\_{0 \le l \lt r} \mathrm{dp}\_{l} + \mathrm{dp}\_{r} \\\\
    \end{array}
$$

ここで次のように定義すると、それぞれ単純な漸化式で計算できる。

-   $\mathrm{dp'}\_{r} = \sum\_{0 \le l \lt r} \mathrm{dp}\_{l}(r - l)$
-   $\mathrm{dp''}\_{r} = \sum\_{0 \le l \lt r} \mathrm{dp}\_{l}$

また$\hat{\mathrm{dp}}\_{r} = \sum\_{0 \le l \lt r} \mathrm{dp}\_{l}(r-l)^2$とする。印が付いている位置を考えれば、これは$\mathrm{dp}$とは必ずしも一致しないことに注意。
これにより、

$$
    \mathrm{dp}\_{r+1} = \hat{\mathrm{dp}}\_{r} + \mathrm{dp'}\_{r} + \mathrm{dp''}\_{r} + \mathrm{dp}\_{r}
$$

このようにすれば組$(\hat{\mathrm{dp}}\_{r}, \mathrm{dp'}\_{r}, \mathrm{dp''}\_{r}, \mathrm{dp}\_{r})$から$(\hat{\mathrm{dp}}\_{r+1}, \mathrm{dp'}\_{r+1}, \mathrm{dp''}\_{r+1}, \mathrm{dp}\_{r+1})$を得るのは$O(1)$となる。
よって全体で$O(N)$で解ける。

## implementation

-   毎回`if (x >= mod) x -= mod;`よりもまとめて`x %= mod;`の方が速かった。分岐予測の影響か
-   `if (j < m and x[j] == i+1) ...`よりも番兵を置いて`if (x[j] == i+1) ...`の方が速かった。それはそう
-   `x[j]`よりも`int x_j = x[j];`をおいた方が速かった。これはコンパイラがしてくれてもよさそう

``` c++
#include <cstdio>
#include <vector>
#define repeat(i, n) for (int i = 0; (i) < int(n); ++(i))
using ll = long long;
using namespace std;

constexpr int mod = 1e9+7;
int main() {
    // input
    int n, m; scanf("%d%d", &n, &m);
    vector<int> x(m+1); repeat (i, m) scanf("%d", &x[i]); // x[m] is a sentinel
    // solve
    ll result = 1;
    ll preserved = 0;
    ll delta = 0;
    ll acc = 0;
    int j = 0;
    int x_j = x[j];
    repeat (i, n) {
        acc += result;
        preserved += 2 * delta + acc;
        delta += acc;
        if (i % 17 == 0) {
            preserved %= mod;
            delta %= mod;
            acc %= mod;
        }
        result = preserved;
        if (x_j == i+1) {
            result = 0;
            x_j = x[++ j];
        }
    }
    // output
    printf("%lld\n", result % mod);
    return 0;
}
```
