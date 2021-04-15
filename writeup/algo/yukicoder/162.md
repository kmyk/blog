---
layout: post
redirect_from:
  - /writeup/algo/yukicoder/162/
  - /blog/2017/01/05/yuki-162/
date: "2017-01-05T01:23:07+09:00"
tags: [ "competitive", "writeup", "yukicoder", "dp", "bit", "lie" ]
"target_url": [ "http://yukicoder.me/problems/no/162" ]
---

# Yukicoder No.162 8020運動

想定誤解法扱いされてたのでeditorial撃墜みたいなところがあって楽しい。

## solution

愚直をbit演算の魔法で加速。経過年数$A\_{\Delta}$と歯の数$K = 14$に対し$O(A\_{\Delta}2^{2K})$。

## implementation

``` c++
#include <cstdio>
#define repeat(i,n) for (int i = 0; (i) < int(n); ++(i))
using namespace std;
const int K = 14;
int main() {
    int a; scanf("%d", &a);
    double p[3]; repeat (i,3) { scanf("%lf", &p[i]); p[i] /= 100; }
    double dp[1<<K] = {};
    dp[(1<<K) - 1] = 1;
    for (; a < 80; ++ a) {
        repeat (s, 1<<K) {
            double q = 0;
            for (int t = s; t < (1<<K); ++ t |= s) { // s \subseteq t
                double r = dp[t];
                for (int i = t & - t; i; i = t ^ (t & (t - (i << 1)))) { // i \in t
                    int j = bool(t & (i>>1)) + bool(t & (i<<1));
                    r *= (s & i ? 1 - p[j] : p[j]);
                }
                q += r;
            }
            dp[s] = q;
        }
    }
    double acc = 0;
    repeat (s, 1<<K) acc += __builtin_popcount(s) * dp[s];
    printf("%.9lf\n", acc * 2);
    return 0;
}
```
