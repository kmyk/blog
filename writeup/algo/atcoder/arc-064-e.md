---
layout: post
alias: "/blog/2016/12/05/arc-064-e/"
date: "2016-12-05T15:43:09+09:00"
title: "AtCoder Regular Contest 064: E - Cosmic Rays"
tags: [ "competitive", "writeup", "atcoder", "dijkstra" ]
"target_url": [ "https://beta.atcoder.jp/contests/arc064/tasks/arc064_c" ]
---

なんでこれが$3$問目なんだICPC国内予選か？という印象。ABCの方の$4$問目の調整のために$2$問目とswapしたのだろうか。

## solution

dijkstra。$O(V^2)$。

## implementation

$O(E \log V)$でなく$O(V^2)$のオリジナルDijkstraが言及されていたので書いてみた。$E = V^2$なケースではこちらが単純かつ高速。

``` c++
#include <cstdio>
#include <vector>
#include <algorithm>
#include <numeric>
#include <tuple>
#include <cmath>
#define repeat(i,n) for (int i = 0; (i) < (n); ++(i))
#define whole(f,x,...) ([&](decltype((x)) whole) { return (f)(begin(whole), end(whole), ## __VA_ARGS__); })(x)
using namespace std;
template <class T> void setmin(T & a, T const & b) { if (b < a) a = b; }
template <typename T>
vector<T> original_dijkstra(vector<vector<pair<int, T> > > const & g, int start, T inf) {
    int n = g.size();
    vector<double> dist(n, inf);
    vector<int> ixs(n); whole(iota, ixs, 0);
    dist[start] = 0;
    repeat (loop,n) {
        int i; {
            auto it = whole(min_element, ixs, [&](int i, int j) { return dist[i] < dist[j]; });
            i = *it;
            *it = ixs.back();
            ixs.pop_back();
        }
        for (auto it : g[i]) {
            int j; T cost; tie(j, cost) = it;
            setmin(dist[j], dist[i] + cost);
        }
    }
    return dist;
}
int main() {
    int sx, sy, gx, gy, n; scanf("%d%d%d%d%d", &sx, &sy, &gx, &gy, &n);
    vector<int> x(n), y(n), r(n); repeat (i,n) scanf("%d%d%d", &x[i], &y[i], &r[i]);
    x.push_back(sx); y.push_back(sy); r.push_back(0);
    x.push_back(gx); y.push_back(gy); r.push_back(0);
    vector<vector<pair<int, double> > > g(n+2);
    repeat (i,n+2) repeat (j,n+2) g[i].emplace_back(j, max(0.0, sqrt(pow(x[j] - x[i], 2) + pow(y[j] - y[i], 2)) - r[i] - r[j]));
    auto dist = original_dijkstra(g, n, double(INFINITY));
    printf("%.10lf\n", dist[n+1]);
    return 0;
}
```
