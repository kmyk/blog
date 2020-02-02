---
layout: post
alias: "/blog/2017/08/15/abc-070-d/"
date: "2017-08-15T13:15:50+09:00"
title: "AtCoder Beginner Contest 070: D - Transit Tree Path"
tags: [ "competitive", "writeup", "atcoder", "abc", "dp" ]
"target_url": [ "https://beta.atcoder.jp/contests/abc070/tasks/abc070_d" ]
---

LCAを貼りかけた。だめ。

## solution

答えは$d(x\_j, K) + d(K, y\_j)$。
頂点$K$からの最短経路長を全て求めておけばよい。Dijkstraでもよいが、木なのでDPでもできる。
$O(N + Q)$。

## implementation

``` c++
#include <cstdio>
#include <functional>
#include <vector>
#define repeat(i, n) for (int i = 0; (i) < int(n); ++(i))
using ll = long long;
using namespace std;

int main() {
    int n; scanf("%d", &n);
    vector<vector<pair<int, int> > > g(n);
    repeat (i, n - 1) {
        int a, b, c; scanf("%d%d%d", &a, &b, &c); -- a; -- b;
        g[a].emplace_back(b, c);
        g[b].emplace_back(a, c);
    }
    int q, k; scanf("%d%d", &q, &k); -- k;
    vector<ll> dist(n, -1);
    function<void (int)> go = [&](int i) {
        for (auto e : g[i]) {
            int j, cost; tie(j, cost) = e;
            if (dist[j] != -1) continue;
            dist[j] = dist[i] + cost;
            go(j);
        }
    };
    dist[k] = 0;
    go(k);
    while (q --) {
        int x, y; scanf("%d%d", &x, &y); -- x; -- y;
        printf("%lld\n", dist[x] + dist[y]);
    }
    return 0;
}
```
