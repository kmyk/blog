---
layout: post
alias: "/blog/2016/10/29/agc-006-c/"
date: "2016-10-29T23:35:15+09:00"
tags: [ "competitive", "writeup", "atcoder", "agc", "doubling", "difference" ]
"target_url": [ "https://beta.atcoder.jp/contests/agc006/tasks/agc006_c" ]
---

# AtCoder Grand Contest 006: C - Rabbit Exercise

C openして無提出 零完。
周期性(周期の上限が指数になりそう)や行列累乗($O(N^3(M + \log K))$)まで考えていたが、差分は予想外だった。

## solution

期待値の線形性から$E[x_i'] = E[x\_{i+1}] + E[x\_{i-1}] - E[x\_i]$。これは階差数列のswapと見れるのでdoubling。$O(M + N \log K)$。

うさぎ$i$が移動するとする。$x_i' = x_i + 2(x\_{i\pm 1} - x_i)$で符号はそれぞれ$\frac{1}{2}$の確率。
期待値で見て、$E[x_i'] = \frac{1}{2}(x_i + 2(x\_{i+1} - x_i)) + \frac{1}{2}(x_i + 2(x\_{i-1} - x_i)) = x\_{i+1} + x\_{i-1} - x_i$。

$b' = a - b + c$とする。$b' - a = c - b$かつ$c - b' = b - a$である。これは列$(a, b, c)$に関して階差数列のswapになっている。
このようにすればindexの列を持って$M$回のswapの$K$回の繰り返しとなり、doublingを使って高速に計算できる。

## implementation

``` c++
#include <iostream>
#include <vector>
#include <numeric>
#define repeat(i,n) for (int i = 0; (i) < (n); ++(i))
#define whole(f,x,...) ([&](decltype((x)) whole) { return (f)(begin(whole), end(whole), ## __VA_ARGS__); })(x)
typedef long long ll;
using namespace std;
template <typename T>
vector<T> apply(vector<T> const & a, vector<int> const & swp) {
    int n = swp.size();
    vector<T> b(n);
    repeat (i,n) b[i] = a[swp[i]];
    return b;
}
int main() {
    // input
    int n; cin >> n;
    vector<ll> x(n); repeat (i,n) cin >> x[i];
    int m; ll k; cin >> m >> k;
    vector<int> a(m); repeat (i,m) { cin >> a[i]; -- a[i]; }
    // differences, swap, doubling
    vector<ll> dx(n-1); repeat (i,n-1) dx[i] = x[i+1] - x[i];
    vector<int> swp(n-1); whole(iota, swp, 0);
    repeat (j,m) swap(swp[a[j]-1], swp[a[j]]);
    for (ll i = 1; i <= k; i <<= 1) {
        if (k & i) dx = apply(dx, swp);
        swp = apply(swp, swp);
    }
    // output
    vector<ll> y(n);
    y[0] = x[0]; repeat (i,n-1) y[i+1] = y[i] + dx[i];
    repeat (i,n) cout << y[i] << endl;
    return 0;
}
```
