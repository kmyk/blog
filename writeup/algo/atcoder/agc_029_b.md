---
layout: post
date: 2018-12-16T04:10:40+09:00
tags: [ "competitive", "writeup", "atcoder", "agc", "tree", "matching", "graph", "greedy" ]
"target_url": [ "https://beta.atcoder.jp/contests/agc029/tasks/agc029_b" ]
redirect_from:
  - /writeup/algo/atcoder/agc-029-b/
---

# AtCoder Grand Contest 029: B - Powers of two

## 解法

### 概要

$$A_i + A_j = 2^k$$ であるような $$(i, j)$$ に辺を張ると答えはその最大マッチングの大きさとなる。
このグラフは木であることを信じれば $$O(N \log N)$$ ぐらいで解ける。

### 詳細

自己ループと多重辺を無視したときにグラフ $$G$$ が木であることを証明しておく。
数列の最大値 $$b = \max_i A_i$$ の大きさで帰納法。
$$b = 1$$ のときは明らか。
$$b \ge 2$$ 未満での成立を仮定する。
グラフから $$b$$ を除いた部分は木であるので $$b$$ の次数が $$1$$ であることを言えばよい。
$$b$$ と辺が張られる数を考えると $$a \lt b$$ かつ $$a + b = 2^k$$ を満たす。
これを整理すると $$b \le 2^k \lt 2b$$ となるので $$a$$ は一意に定まる。
よってグラフ $$G$$ は木である。

## メモ

-   $$2^k$$ の $$k$$ の上限が足りずに1WAした
-   コンテスト中は雰囲気で通した
-   木であることの証明は解説放送を見た

## 実装

``` c++
#include <bits/stdc++.h>
#define REP(i, n) for (int i = 0; (i) < (int)(n); ++ (i))
using namespace std;

int solve(int n, vector<int> const & a) {
    unordered_map<int, int> f;
    for (int a_i : a) {
        f[a_i] += 1;
    }

    // construct the graph
    unordered_map<int, vector<int> > g;
    unordered_map<int, int> degree;
    queue<int> que;
    for (int a_i : a) if (not g.count(a_i)) {
        REP (k, 31) {
            int a_j = (1 << k) - a_i;
            if (f.count(a_j)) {
                g[a_i].push_back(a_j);
            }
        }
        degree[a_i] = g[a_i].size();
        if (degree[a_i] == 1) {
            que.push(a_i);
        }
    }

    // find the matching
    int ans = 0;
    while (not que.empty()) {
        int a_i = que.front();
        que.pop();
        for (int a_j : g[a_i]) {
            int delta = min(f[a_i], f[a_j]);
            if (a_i == a_j) {
                delta /= 2;
            } else {
                f[a_i] -= delta;
            }
            f[a_j] -= delta;
            ans += delta;
        }
        for (int a_j : g[a_i]) {
            degree[a_j] -= 1;
            if (degree[a_j] == 1) {
                que.push(a_j);
            }
        }
    }
    return ans;
}

int main() {
    int n; cin >> n;
    vector<int> a(n);
    REP (i, n) cin >> a[i];
    cout << solve(n, a) << endl;
    return 0;
}
```
