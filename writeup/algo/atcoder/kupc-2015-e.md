---
layout: post
alias: "/blog/2015/10/24/kupc-2015-e/"
title: "京都大学プログラミングコンテスト2015 E - マッサージチェア2015"
date: 2015-10-24T23:55:35+09:00
tags: [ "kupc", "competitive", "writeup", "ternary-search" ]
---

始めて三分探索した。次書くときは黄金分割探索っての使ってみたい。

<!-- more -->

## [E - マッサージチェア2015](https://beta.atcoder.jp/contests/kupc2015/tasks/kupc2015_e) {#e}

### 問題

$H \times W$の長方形内に3点配置したときの、点と点の距離の最小値の最大値を求めよ。

### 解法

1点が角に位置し、残りの2点は異なる辺上に位置するのは明らかである。
また、点と点の距離の最小値は、ある点の辺上の位置に関して凸な関数になっていることが分かる。
三分探索すればよい。
二分探索は単調なものにしか適用できないことに注意。

### 実装

``` c++
#include <iostream>
#include <cstdio>
#include <complex>
#define repeat_from(i,m,n) for (int i = (m); (i) < (n); ++(i))
#define repeat(i,n) repeat_from(i,0,n)
using namespace std;
constexpr double eps = 1e-8;
double dist(double h, double w, double y, double x) {
    complex<double> p = { h, w };
    complex<double> q = { y, 0 };
    complex<double> r = { 0, x };
    return min(abs(p - q), min(abs(q - r), abs(r - p)));
}
double bar(int h, int w, double y) {
    double xl = 0, xr = w;
    while (xr - xl >= eps) {
        double x1 = (2 * xl + xr) / 3;
        double x2 = (xl + 2 * xr) / 3;
        double d1 = dist(h, w, y, x1);
        double d2 = dist(h, w, y, x2);
        if (d1 < d2) {
            xl = x1;
        } else {
            xr = x2;
        }
    }
    return dist(h, w, y, (xl + xr) / 2);
}
double foo(int h, int w) {
    double yl = 0, yr = h;
    while (yr - yl >= eps) {
        double y1 = (2 * yl + yr) / 3;
        double y2 = (yl + 2 * yr) / 3;
        double d1 = bar(h, w, y1);
        double d2 = bar(h, w, y2);
        if (d1 < d2) {
            yl = y1;
        } else {
            yr = y2;
        }
    }
    return bar(h, w, (yl + yr) / 2);
}
int main() {
    int datasets; cin >> datasets;
    repeat (dataset, datasets) {
        int h, w; cin >> h >> w;
        printf("%.16lf\n", foo(h, w));
    }
    return 0;
}
```
