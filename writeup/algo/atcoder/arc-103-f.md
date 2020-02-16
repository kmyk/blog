---
layout: post
date: 2018-10-05T04:28:06+09:00
tags: [ "competitive", "writeup", "atcoder", "arc", "graph", "tree", "construction", "dp" ]
"target_url": [ "https://beta.atcoder.jp/contests/arc103/tasks/arc103_d" ]
---

# AtCoder Regular Contest 103: F - Distance Sums

## 解法

### 概要

$D_i$ の降順に見て葉から決めていく。
$O(N \log N)$。

### 詳細

木が構成できるための$D_i$の必要条件を考える。
木の辺$(u, v)$があるなら、その辺から見て$u, v$側の頂点の数をそれぞれ$a, b$とおくと、ある$D$があって $D_u = D + b$ かつ $D_v = D + a$ になる。
あるいは単に $D_u = D_v - b + a$ とおける。

これにより木の中央に行くほど$D_i$は小さくなることが分かる。
そのような中央は高々$2$点。
$D_i$のdistinct制約により(これは本質的ではないが)$D_i$が最小となる$i$は一意であるので、そのような頂点を根とする根付き木を考える。
中央に近付けば小さくなり遠ざかれば大きくなるので、この木は子にいくほど$D_i$が大きくなる。

さてこのような木を構築したい。
根から伸ばしていくか葉からまとめ上げるかのどちらか。
正解は後者。
各部分木を見たとき、部分木の根$i$の値$D_i$と部分木の大きさ$N_i$が分かれば、$i$の親になるべき頂点の値$D_j = D_i - N_i + (N - N_i)$は一意に定まる。
ここで$D_i$のdistinct制約が(本質的に)効いて、そのような$j$は存在すれば一意。
存在しなければ構築不能なので存在すると仮定してよく、これを再帰的にすれば木が構成される。
構成の過程では$D_i, D_j$間の差分しか見ていないため、構成された木がきちんと列$D_i$を生成するか確認すれば終わり。
この確認は単純な木DPでよい。

## メモ

地頭構築ゲーかなと思ったけど解法を見ると典型感があった。

## 実装

``` c++
#include <bits/stdc++.h>
#define REP(i, n) for (int i = 0; (i) < (int)(n); ++ (i))
using ll = long long;
using namespace std;

vector<pair<int, int> > solve(int n, vector<ll> const & d) {
    map<ll, int> index;
    REP (i, n) {
        index[d[i]] = i;
    }

    int root = index.begin()->second;
    vector<pair<int, int> > edges;
    vector<int> size(n, 1);
    vector<ll> d1(n, 0);
    for (auto it = index.rbegin(); ; ++ it) {
        ll d_i; int i; tie(d_i, i) = *it;
        if (i == root) break;
        ll d_parent = d_i - n + 2 * size[i];
        if (not index.count(d_parent)) {
            return vector<pair<int, int> >();
        }
        int parent = index[d_parent];
        edges.emplace_back(parent, i);
        size[parent] += size[i];
        d1[parent] += d1[i] + size[i];
    }

    if (d1[root] != d[root]) {
        return vector<pair<int, int> >();
    }
    return edges;
}

int main() {
    int n; cin >> n;
    vector<ll> d(n);
    REP (i, n) cin >> d[i];
    auto edges = solve(n, d);
    if (edges.empty()) {
        cout << -1 << endl;
    } else {
        for (auto edge : edges) {
            int i, j; tie(i, j) = edge;
            cout << i + 1 << ' ' << j + 1 << endl;
        }
    }
    return 0;
}
```
