---
layout: post
redirect_from:
  - /writeup/algo/yukicoder/196/
  - /blog/2017/01/11/yuki-196/
date: "2017-01-11T16:50:53+09:00"
tags: [ "competitive", "writeup", "yukicoder", "dp", "tree" ]
"target_url": [ "http://yukicoder.me/problems/no/196" ]
---

# Yukicoder No.196 典型DP (1)

$O(N^3)$を定数倍高速化してねじ込んだつもりだったのに、よく見たら$O(N^2)$になってしまっていた。これ好き。

## solution

木DP。$O(N^2)$。

部分木$T$について、その部分木内の頂点を黒に塗った個数$k$に対しその塗り方の個数$f_T(k)$とする。
これを合成していく。
合成は$(f_L \cdot f_R)(k) = \sum\_{i + j = k} f_L(i) f_R(j)$である。

部分木$x$の大きさ$\|x\|$より大きい$k \gt \|x\|$について$f_x(k) = 0$なので、合成の計算量は$O(\|x\| \cdot \|y\|)$。
全体では計算量の漸化式$T(N) \approx T(L + R) \approx T(L) + T(R) + LR \approx T(N) + T(N) + N^2$となり、$T(N) \succcurlyeq N^2$なら矛盾しない。
よって全体でも$O(N^2)$。

## implementation

``` c++
#include <iostream>
#include <vector>
#include <functional>
#define repeat(i,n) for (int i = 0; (i) < int(n); ++(i))
using ll = long long;
using namespace std;
template <typename X, typename T> auto vectors(X x, T a) { return vector<T>(x, a); }
template <typename X, typename Y, typename Z, typename... Zs> auto vectors(X x, Y y, Z z, Zs... zs) { auto cont = vectors(y, z, zs...); return vector<decltype(cont)>(x, cont); }
const int mod = 1e9+7;
vector<int> merge(vector<int> & a, vector<int> & b) {
    int n = a.size() + b.size() + 3;
    vector<int> c(n);
    repeat (i, a.size()) {
        repeat (j, b.size()) {
            c[i + j] += a[i] *(ll) b[j] % mod;
            c[i + j] %= mod;
        }
    }
    while (not c.empty() and c.back() == 0) c.pop_back();
    return c;
}
int main() {
    int n, k; cin >> n >> k;
    vector<vector<int> > g(n);
    repeat (i,n-1) {
        int a, b; cin >> a >> b;
        g[a].push_back(b);
        g[b].push_back(a);
    }
    vector<vector<int> > dp(n);
    vector<int> size(n);
    function<void (int, int)> go = [&](int i, int parent) {
        size[i] = 1;
        if (dp[i].size() <= 0) dp[i].resize(1);
        dp[i][0] = 1;
        for (int j : g[i]) if (j != parent) {
            go(j, i);
            dp[i] = merge(dp[i], dp[j]);
            size[i] += size[j];
        }
        if (dp[i].size() <= size[i]) dp[i].resize(size[i] + 1);
        dp[i][size[i]] = 1;
    };
    go(0, -1);
    cout << dp[0][k] << endl;
    return 0;
}
```
