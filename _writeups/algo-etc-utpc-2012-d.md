---
layout: post
redirect_from:
  - /writeup/algo/etc/utpc-2012-d/
  - /blog/2017/12/31/utpc-2012-d/
date: "2017-12-31T17:55:53+09:00"
tags: [ "competitive", "writeup", "utpc", "atcoder", "geometry", "affine-transformation", "fixed-point" ]
"target_url": [ "https://beta.atcoder.jp/contests/utpc2012/tasks/utpc2012_04" ]
---

# 東京大学プログラミングコンテスト2012: D - 地図が２枚

## solution

拡大回転平行移動のみであるのでAffine変換である。
反転はないことが分かっているので$2$点の行き先が分かれば変形$f$の全体が分かる。
その不動点$x = f(x)$を求めればよいので収束するまで$x \gets f(x)$と更新し続ければよい。
計算量は収束速度によるがよく分からず。まじめに方程式を解くなら$O(1)$。


## implementation

``` c++
#include <bits/stdc++.h>
#define REP(i, n) for (int i = 0; (i) < int(n); ++ (i))
using namespace std;

int main() {
    // input
    int n; scanf("%d", &n);
    vector<double> x1(n), y1(n); REP (i, n) scanf("%lf%lf", &x1[i], &y1[i]);
    vector<double> x2(n), y2(n); REP (i, n) scanf("%lf%lf", &x2[i], &y2[i]);
    // solve
    complex<double> z10(x1[0], y1[0]);
    complex<double> z11(x1[1], y1[1]);
    complex<double> z20(x2[0], y2[0]);
    complex<double> z21(x2[1], y2[1]);
    auto f = [&](complex<double> z) {
        double scale = 0.5;
        double angle = arg(z21 - z20) - arg(z11 - z10);
        return (z - z10) * polar<double>(scale, angle) + z20;
    };
    complex<double> z = z10;
    REP (iteration, 10000) z = f(z);
    // output
    printf("%.8lf %.8lf\n", real(z), imag(z));
    return 0;
}
```
