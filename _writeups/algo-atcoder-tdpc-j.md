---
layout: post
redirect_from:
  - /writeup/algo/atcoder/tdpc-j/
  - /blog/2016/06/10/tdpc-j/
date: 2016-06-10T21:12:28+09:00
tags: [ "competitive", "writeup", "atcoder", "typical-dp-contest", "math", "dp", "expected-value", "bit-dp" ]
"target_url": [ "https://beta.atcoder.jp/contests/tdpc/tasks/tdpc_ball" ]
---

# Typical DP Contest J - ボール

良い問題。
教科書の例題のような期待値DP。
このあたりの基本的な話は以前[ちゃんとやった](https://kimiyuki.net/blog/2016/04/28/dice-and-expected-value/)ので、読み返すだけだった。

## solution

期待値でbit-DP。$O(2^N)$。

与えられたピンの位置の集合$X = \\{ x_1, \dots, x_N \\}$に対し、その部分集合$s \subseteq X$の要素を全て倒すために投げるボールの期待値の関数$\operatorname{dp} : \mathcal{P}(X) \to \mathbb{R}$のDP。

>   確率$p$で起こるものが起こるまで試行し続けるとき、その回数の期待値$E = \Sigma\_{k=1}^{\infty} kp(1-p)^{k-1} = \frac{1}{p}$である。

ことを使って更新。

## implementation

``` c++
#include <iostream>
#include <array>
#include <cmath>
#include <cstdio>
#define repeat(i,n) for (int i = 0; (i) < (n); ++(i))
#define repeat_from(i,m,n) for (int i = (m); (i) < (n); ++(i))
template <class T> bool setmin(T & l, T const & r) { if (not (r < l)) return false; l = r; return true; }
using namespace std;
#define N 16
int main() {
    array<double,1<<N> e = {};
    e[0] = 0;
    repeat_from (s,1,1<<N) {
        e[s] = INFINITY;
        repeat (x,N) {
            int cnt = 0;
            repeat_from (nx, max(0,x-1), min(N,x+2)) if (s & (1 << nx)) {
                cnt += 1;
            }
            if (not cnt) continue;
            double acc = 3./cnt;
            repeat_from (nx, max(0,x-1), min(N,x+2)) if (s & (1 << nx)) {
                acc += 1./cnt * e[s & ~ (1 << nx)];
            }
            setmin(e[s], acc);
        }
    }
    // input / output
    int n; cin >> n;
    int x = 0; repeat (i,n) { int j; cin >> j; x |= 1 << j; }
    printf("%.9lf\n", e[x]);
    return 0;
}
```
