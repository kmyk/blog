---
layout: post
alias: "/blog/2017/11/10/tanka1-2017-e/"
date: "2017-11-10T22:24:50+09:00"
title: "Tenka1 Programmer Contest: E - CARtesian Coodinate"
tags: [ "competitive", "writeup", "atcoder", "tenka1", "simd", "optimization", "median" ]
"target_url": [ "https://beta.atcoder.jp/contests/tenka1-2017/tasks/tenka1_2017_e" ]
---

## solution

$x$軸と$y$軸は独立。$x$座標$y$座標のそれぞれについて交点の座標の中央値を取ればよい。$O(N^2)$。定数倍最適化。

## 知見

-   `#pragma clang loop vectorize(enable)` は、付けなくてもvectorizeされているためあまり速度は変わらないだが、
-   `vector<T>.push_back` をloop内でするとvectorizeできないので、flagを作って外に出すテク

## 他

-   tanakhさんの[提出](https://beta.atcoder.jp/contests/tenka1-2017/submissions/1642764)をとても参考にした。ほとんど同じと言ってよい。
-   $23$WA $2$RE
-   速度は足りてたが普通にバグ

## implementation

``` c++
#include <algorithm>
#include <cassert>
#include <cstdio>
#include <random>
#include <vector>
#define repeat(i, n) for (int i = 0; (i) < int(n); ++(i))
#define whole(x) begin(x), end(x)
using namespace std;

int main() {
    // input
    int n; scanf("%d", &n);
    vector<int16_t> a(n), b(n), c(n);
    repeat (i, n) scanf("%hd%hd%hd", &a[i], &b[i], &c[i]);

    // solve

    // // find the windows
    constexpr int sample_size = 500000;
    constexpr int window_radius = 1000;
    vector<double> samples_x(sample_size);
    vector<double> samples_y(sample_size);
    mt19937 gen;
    repeat (iteration, sample_size) {
        int i, j;
        do {
            i = uniform_int_distribution<int>(0, n - 1)(gen);
            j = uniform_int_distribution<int>(0, n - 1)(gen);
        } while (i == j);
        double den = a[i] * b[j] - a[j] * b[i];
        double x = (b[j] * c[i] - b[i] * c[j]) / den;
        double y = (a[j] * c[i] - a[i] * c[j]) / - den;
        samples_x[iteration] = x;
        samples_y[iteration] = y;
    }
    sort(whole(samples_x));
    sort(whole(samples_y));
    double dlx = samples_x[sample_size / 2 - window_radius];
    double drx = samples_x[sample_size / 2 + window_radius];
    double dly = samples_y[sample_size / 2 - window_radius];
    double dry = samples_y[sample_size / 2 + window_radius];
    bool determined_x = (dlx == drx);
    bool determined_y = (dly == dry);
    float lx = dlx;
    float rx = drx;
    float ly = dly;
    float ry = dry;

    // // get points in them
    int low_count_x = 0;
    int low_count_y = 0;
    vector<double> bucket_x;
    vector<double> bucket_y;
    vector<int> flag(n);
    repeat (j, n) {
        {
            int aj = a[j];
            int bj = b[j];
            int cj = c[j];
            repeat (i, j) {
                float den = a[i] * bj - aj * b[i];
                float x = (bj * c[i] - b[i] * cj) / den;
                float y = (aj * c[i] - a[i] * cj) / - den;
                low_count_x += (x < lx);
                low_count_y += (y < ly);
                flag[i] = (int(lx <= x and x <= rx) << 1) | int(ly <= y and y <= ry);
            }
        }
        {
            double aj = a[j];
            double bj = b[j];
            double cj = c[j];
            if (not determined_x) repeat (i, j) if (flag[i] & 2) {
                double x = (bj * c[i] - b[i] * cj) / (a[i] * bj - aj * b[i]);
                bucket_x.push_back(x);
            }
            if (not determined_y) repeat (i, j) if (flag[i] & 1) {
                double y = (aj * c[i] - a[i] * cj) / (aj * b[i] - a[i] * bj);
                bucket_y.push_back(y);
            }
        }
    }

    // // make results
    int half = (n * (n - 1) / 2 - 1) / 2;
    double x;
    if (determined_x) {
        x = dlx;
    } else {
        int ix = half - low_count_x;
        assert (0 <= ix and ix < bucket_x.size());
        nth_element(bucket_x.begin(), bucket_x.begin() + ix, bucket_x.end());
        x = bucket_x[ix];
    }
    double y;
    if (determined_y) {
        y = dly;
    } else {
        int iy = half - low_count_y;
        assert (0 <= iy and iy < bucket_y.size());
        nth_element(bucket_y.begin(), bucket_y.begin() + iy, bucket_y.end());
        y = bucket_y[iy];
    }

    // output
    printf("%.15lf %.15lf\n", x, y);
    return 0;
}
```
