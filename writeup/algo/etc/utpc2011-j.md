---
layout: post
redirect_from:
  - /writeup/algo/etc/utpc2011-j/
  - /blog/2017/12/29/utpc2011-j/
date: "2017-12-29T07:48:34+09:00"
tags: [ "competitive", "writeup", "utpc", "aoj", "dp", "treap", "fast-fourier-transformation", "probability" ]
---

# 東京大学プログラミングコンテスト2011: J. 乱択平衡分二分探索木

-   <http://www.utpc.jp/2011/problems/treap.html>
-   <http://judge.u-aizu.ac.jp/onlinejudge/description.jsp?id=2268>

## solution

DP。FFT。$O(N (\log N)^2)$。

要点は以下の3点。[editorial](http://www.utpc.jp/2011/slides/treap.pdf)を見て。

1.  treapの性質と乱数でパラメタを決めていることから、ただの二分探索木と見做せる
2.  平衡二分探索木の高さなので、すぐに要求精度$10^{-5}$より小さくなる
3.  DPを書いて式の形を良く見ると畳み込みなのでFFTで加速できる

注意としては、FFTを再帰で求めていると少し遅いので非再帰のものを使う。

## implementation

``` c++
#include <bits/stdc++.h>
#define REP(i, n) for (int i = 0; (i) < int(n); ++ (i))
#define REP3(i, m, n) for (int i = (m); (i) < int(n); ++ (i))
#define REP_R(i, n) for (int i = int(n) - 1; (i) >= 0; -- (i))
using namespace std;

template <typename R>
void fft_inplace(vector<complex<R> > & f, int dir) {
    int n = f.size();
    assert(n == pow(2, log2(n)));
    R theta = dir * 2 * M_PI / n;
    for (int m = n; m >= 2; m >>= 1) {
        REP (i, m / 2) {
            complex<R> w = polar<R>(1, i * theta);
            for (int j = i; j < n; j += m) {
                int k = j + m / 2;
                complex<R> x = f[j] - f[k];
                f[j] += f[k];
                f[k] = w * x;
            }
        }
        theta *= 2;
    }
    int i = 0;
    REP3 (j, 1, n - 1) {
        for (int k = n >> 1; k > (i ^= k); ) k >>= 1;
        if (j < i) {
            swap(f[i], f[j]);
        }
    }
}
template <typename T, typename R = double>
void convolution_self_inplace(vector<T> & a, int result_n) {
    int m = 2 * a.size() - 1;
    int n = pow(2, ceil(log2(m)));
    vector<complex<R> > x(n);
    copy(a.begin(), a.end(), x.begin());
    fft_inplace(x, +1);
    vector<complex<R> > z(n);
    REP (i, n) x[i] *= x[i];
    fft_inplace(x, -1);
    a.resize(result_n);
    REP (i, result_n) a[i] = x[i].real() / n;
}

int main() {
    // input
    int n; scanf("%d", &n);
    // solve
    const int height = min(n, 50);
    vector<double> dp(n + 1);
    dp[0] = 1;
    double last_dp_n = 0;
    REP3 (j, 1, height + 1) {
        convolution_self_inplace(dp, n + 1);
        REP_R (i, n) {
            dp[i + 1] = dp[i] / (i + 1);
        }
        dp[0] = 1;
        // output
        printf("%.10lf\n", double(dp[n] - last_dp_n));
        last_dp_n = dp[n];
    }
    REP3 (j, height + 1, n + 1) {
        printf("0\n");
    }
    return 0;
}
```
