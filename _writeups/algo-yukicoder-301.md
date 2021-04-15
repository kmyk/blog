---
layout: post
redirect_from:
  - /writeup/algo/yukicoder/301/
  - /blog/2016/07/07/yuki-301/
date: "2016-07-07T23:23:12+09:00"
tags: [ "competitive", "writeup", "yukicoder", "dp", "experiment", "expected-value", "probability", "dice" ]
"target_url": [ "http://yukicoder.me/problems/no/301" ]
---

# Yukicoder No.301 サイコロで確率問題 (1)

[Yukicoder No.75 回数の期待値の問題](http://yukicoder.me/problems/129)の制約を強めたもの。

漸化式が線形なDPなので行列化して繰り返し二乗法だろうと思ったが、誤差によりWAした。
対角化すると加算が消えて誤差が減るよと教えてもらったが、
Wolfram Alpha曰く<a href="https://www.wolframalpha.com/input/?i=((1%2F6,1%2F6,1%2F6,1%2F6,1%2F6,1%2F6,1),(1,0,0,0,0,0,0),(0,1,0,0,0,0,0),(0,0,1,0,0,0,0),(0,0,0,1,0,0,0),(0,0,0,0,1,0,0),(0,0,0,0,0,0,1))">対角化不能</a>とのことだったので諦めた。

## solution

$N \le 200$であれば、DPをすればよい。$O(N)$。
$N \gt 200$であれば、$\mathrm{ans}\_n$はその収束先$n + \frac{5}{3}$にすでに十分近いので、$n + \frac{5}{3}$を出力すればよい。

DP部分に関して、これは答えを変数として持って走って再帰的な等式を作るDP。
出目の和が$N$を目指すとして、現在の出目の和が$k$である状態からのさいころを振る回数の期待値を$E_k$とする。
このとき、

-   $E_k = 1 + \Sigma\_{1 \le d \le 6} \frac{1}{6} E\_{k+d}$ for $k \lt N$
-   $E_N = 0$
-   $E_k = E_0$ for $k \gt N$

という漸化式が立つ。
ここで、$E_0 = x$という変数を置くと、

-   $E_k = 1 + \Sigma\_{1 \le d \le 6} \frac{1}{6} E\_{k+d}$ for $k \lt N$
-   $E_N = 0$
-   $E_k = x$ for $k \gt N$

という多項式に関する単純なDPになる。
$x$を含む式として$E_0$が求まるので、$E_0 = x$という等式を解けば答えが求まる。

## implementation

``` c++
#include <cstdio>
#include <vector>
#define repeat(i,n) for (int i = 0; (i) < (n); ++(i))
#define repeat_reverse(i,n) for (int i = (n)-1; (i) >= 0; --(i))
typedef long long ll;
using namespace std;
int main() {
    int t; scanf("%d", &t);
    while (t --) {
        ll n; scanf("%lld", &n);
        long double ans;
        if (n <= 200) {
            vector<long double> e(n+6);
            vector<long double> p(n+6);
            e[n  ] = 0; p[n  ] = 1;
            e[n+1] = 0; p[n+1] = 0;
            e[n+2] = 0; p[n+2] = 0;
            e[n+3] = 0; p[n+3] = 0;
            e[n+4] = 0; p[n+4] = 0;
            e[n+5] = 0; p[n+5] = 0;
            repeat_reverse (i,n) {
                e[i] = 1;
                p[i] = 0;
                repeat (j,6) {
                    e[i] += e[i+1+j] / 6;
                    p[i] += p[i+1+j] / 6;
                }
            }
            ans = e[0] / p[0];
        } else {
            ans = n + 5./3;
        }
        printf("%.13Lf\n", ans);
    }
    return 0;
}
```
