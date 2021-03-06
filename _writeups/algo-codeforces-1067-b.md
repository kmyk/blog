---
redirect_from:
  - /writeup/algo/codeforces/1067-b/
layout: post
date: 2018-10-25T11:41:25+09:00
tags: [ "competitive", "writeup", "codeforces", "graph", "tree", "center-of-tree", "dp" ]
"target_url": [ "http://codeforces.com/contest/1067/problem/B" ]
---

# Codeforces Round #518 (Div. 1) [Thanks, Mail.Ru!]: B. Multihedgehog

## 問題

与えられた木$G$が、star graphの葉を再帰的に$k$回star graphで置き換えたようなものになっているか判定せよ。

## 解法

### 概要

目的のグラフは綺麗な根付き木になっている。
その根は木の唯一の中心でしかありえないので、これを求めて確認すればよい。
$O(N)$。

## メモ

-   同様のグラフに対する問題: [AtCoder Grand Contest 009: D - Uninity](https://beta.atcoder.jp/contests/agc009/tasks/agc009_d)

## 実装

``` c++
#include <bits/stdc++.h>
#define REP(i, n) for (int i = 0; (i) < (int)(n); ++ (i))
using namespace std;

vector<int> get_centers(vector<vector<int> > const & tree) {
    int n = tree.size();
    vector<bool> used(n);
    vector<int> cur, prv;
    REP (i, n) {
        if (tree[i].size() <= 1) {
            cur.push_back(i);
            used[i] = true;
        }
    }
    while (not cur.empty()) {
        cur.swap(prv);
        cur.clear();
        for (int i : prv) {
            for (int j : tree[i]) if (not used[j]) {
                cur.push_back(j);
                used[j] = true;
            }
        }
    }
    return prv;
}

bool solve(int n, int k, vector<vector<int> > const & g) {
    auto centers = get_centers(g);
    if (centers.size() != 1) return false;
    int center = centers[0];
    function<void (int, int, int)> go = [&](int i, int parent, int depth) {
        int children = (int)g[i].size() - (parent != -1);
        if (depth == 0) {
            if (children) throw false;
        } else {
            if (children < 3) throw false;
            for (int j : g[i]) if (j != parent) {
                go(j, i, depth - 1);
            }
        }
    };
    try {
        go(center, -1, k);
        return true;
    } catch (bool e) {
        assert (not e);
        return false;
    }
}

int main() {
    int n, k; cin >> n >> k;
    vector<vector<int> > g(n);
    REP (i, n - 1) {
        int u, v; cin >> u >> v;
        -- u; -- v;
        g[u].push_back(v);
        g[v].push_back(u);
    }
    cout << (solve(n, k, g) ? "Yes" : "No") << endl;
    return 0;
}
```
