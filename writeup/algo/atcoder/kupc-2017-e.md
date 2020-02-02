---
layout: post
alias: "/blog/2017/10/22/kupc-2017-e/"
date: "2017-10-22T13:33:27+09:00"
title: "Kyoto University Programming Contest 2017: E - Treasure Hunt"
tags: [ "competitive", "writeup", "kupc", "atcoder", "graph" ]
"target_url": [ "https://beta.atcoder.jp/contests/kupc2017/tasks/kupc2017_e" ]
---

これ好き。

## solution

宝箱を頂点 鍵を辺として無向グラフを作る。
各成分ごとに独立なので連結と仮定してよい。
このとき、頂点数より辺数のほうが大きければ全ての宝箱を開けられ、そうでない(つまり木)ならばどこか好きなひとつだけ開けられない。
$O(n + m)$。

初手で最小費用流や2-SATが思い付くだろうが、最小費用流のアルゴリズムをネットワークに沿って高速化することや、単に2-SATのアルゴリズムからの類推で解法が思いつける。

## implementation

``` c++
#include <climits>
#include <cstdio>
#include <functional>
#include <vector>
#define repeat(i, n) for (int i = 0; (i) < int(n); ++(i))
using ll = long long;
using namespace std;
template <class T> inline void setmin(T & a, T const & b) { a = min(a, b); }

int main() {
    // input
    int n, m; scanf("%d%d", &n, &m);
    vector<ll> v(n); repeat (i, n) scanf("%lld", &v[i]);
    vector<vector<int> > g(n);
    repeat (i, m) {
        int x, y; scanf("%d%d", &x, &y); -- x; -- y;
        g[x].push_back(y);
        g[y].push_back(x);
    }

    // solve
    vector<bool> used(n);
    ll acc, ignored; int vertex_count, degree_count;
    function<void (int)> go = [&](int i) {
        used[i] = true;
        acc += v[i];
        setmin(ignored, v[i]);
        vertex_count += 1;
        degree_count += g[i].size();
        for (int j : g[i]) if (not used[j]) {
            go(j);
        }
    };
    ll result = 0;
    repeat (i, n) if (not used[i]) {
        acc = 0;
        ignored = LLONG_MAX;
        vertex_count = 0;
        degree_count = 0;
        go(i);
        if (degree_count == 0) continue;
        result += acc;
        if (vertex_count > degree_count / 2) result -= ignored;
    }

    // output
    printf("%lld\n", result);
    return 0;
}
```
