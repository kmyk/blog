---
layout: post
alias: "/blog/2017/11/27/cf17-round1-d/"
date: "2017-11-27T11:46:20+09:00"
title: "CODE FESTIVAL 2017 Elimination Tournament Round 1: D - Ancient Tree Record"
tags: [ "competitive", "writeup", "atcoder", "codefestival", "asapro", "tree", "construction" ]
"target_url": [ "https://beta.atcoder.jp/contests/cf17-tournament-round1-open/tasks/asaporo2_d" ]
---

## solution

ほとんどの点で式を立てて解くだけ。$O(N)$。

辺$e = (u, v)$について考える。$u$側の部分木の頂点数を$N\_u$とし、$u$から$u$側の部分木の頂点への最短距離の和を$s\_u^u$とする。同様に$N\_v, s\_v^v$をおく。このとき辺$e$の重み$w$について次の式が立つ:

-   $s\_u = s\_u^u + N\_v w + s\_v^v$
-   $s\_v = s\_v^v + N\_u w + s\_u^u$

$N\_v \ne N\_u$と仮定して適当に消去し$w = \frac{s\_u - s\_v}{N\_v - N\_u}$が求まる。
入力の仮定より割り切れる。
これで$N\_v = N\_u$な辺以外の全てについて解けた。

残るは木の中央にある(かもしれない)$N\_v = N\_u$な辺。
しかしこれ以外の辺について長さは求まっているので、それらを使えば一意に計算できる。

## implementation

``` c++
#include <cassert>
#include <cstdio>
#include <functional>
#include <map>
#include <tuple>
#include <vector>
#define repeat(i, n) for (int i = 0; (i) < int(n); ++(i))
using ll = long long;
using namespace std;

int main() {
    // input
    int n; scanf("%d", &n);
    vector<pair<int, int> > edges(n - 1);
    vector<vector<int> > g(n);
    repeat (i, n - 1) {
        int a, b; scanf("%d%d", &a, &b); -- a; -- b;
        edges[i] = { a, b };
        g[a].push_back(b);
        g[b].push_back(a);
    }
    vector<ll> s(n); repeat (i, n) scanf("%lld", &s[i]);
    // solve
    map<pair<int, int>, ll> result;
    vector<int> parent(n, -1);
    vector<int> size(n);
    vector<ll> score(n);
    int center_j = -1;
    function<void (int)> go = [&](int i) {
        size[i] = 1;
        for (int j : g[i]) if (j != parent[i]) {
            parent[j] = i;
            go(j);
            size[i] += size[j];
            score[i] += score[j];
            int size_j_c = n - size[j];
            if (size_j_c == size[j]) {
                center_j = j;
                continue;
            }
            assert ((s[j] - s[i]) % (size_j_c - size[j]) == 0);
            ll w =  (s[j] - s[i]) / (size_j_c - size[j]);
            score[i] += w * size[j];
            result[make_pair(i, j)] = w;
            result[make_pair(j, i)] = w;
        }
    };
    go(0);
    if (center_j != -1) {
        assert ((s[0] - score[0]) % size[center_j] == 0);
        ll w = (s[0] - score[0]) / size[center_j];
        int center_i = parent[center_j];
        result[make_pair(center_i, center_j)] = w;
        result[make_pair(center_j, center_i)] = w;
    }
    // output
    for (auto edge : edges) {
        int a, b; tie(a, b) = edge;
        assert (result.count(make_pair(a, b)));
        printf("%lld\n", result[make_pair(a, b)]);
    }
    return 0;
}
```
