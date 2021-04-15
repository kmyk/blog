---
redirect_from:
layout: post
date: 2018-10-05T04:55:07+09:00
tags: [ "competitive", "writeup", "atcoder", "kupc", "graph", "game", "greedy" ]
"target_url": [ "https://beta.atcoder.jp/contests/kupc2018/tasks/kupc2018_f" ]
---

# Kyoto University Programming Contest 2018: F - カード集め

## 解法

### 概要

グラフにして貪欲。
終了時の状態を考えると、部分的な操作にも点数を付けることができる。
$O(N \log N + M)$。

### 詳細

制約の関係をとりあえずグラフにする。
すると次のような問題になる:

頂点数$N$で辺数$M$の単純無向グラフ$G$があり、頂点$i$には重み$s_i$、辺$j$には重み$c_j$が定まっている。
$2$人で交互に頂点に白黒の色を塗り、塗った頂点の重み、両端を塗った辺の重みが得点。
これが大きい方の勝ち。

一般のグラフで$N \le 10^5$なので貪欲や偶奇で解けてほしい。
さてここでこのゲームの終了時の状態を眺める。
両端が異なる色で塗られている辺はどちらにとっても$0$点であるが、これを両方に$c_i / 2$点としても変わらない。
すると頂点と頂点の間の依存関係が切れ、頂点を$s_i + \sum _ {(i, j) \in E} c_j / 2$の順で貪欲に取ればよいことになる。

## 実装

``` c++
#include <bits/stdc++.h>
#define REP(i, n) for (int i = 0; (i) < (int)(n); ++ (i))
#define ALL(x) begin(x), end(x)
using ll = long long;
using namespace std;

bool solve(int n, int m, vector<int> const & s, vector<vector<pair<int, int> > > const & g) {
    vector<ll> score(n);
    REP (i, n) {
        score[i] = 2 * s[i];
        for (auto edge : g[i]) {
            int j, cost; tie(j, cost) = edge;
            score[i] += cost;
        }
    }
    vector<int> order(n);
    iota(ALL(order), 0);
    sort(ALL(order), [&](int i, int j) { return score[i] > score[j]; });
    ll first = 0, second = 0;
    REP (i, n) {
        (i % 2 == 0 ? first : second) += score[order[i]];
    }
    return first > second;
}

int main() {
    int n, m; cin >> n >> m;
    vector<int> s(n);
    REP (i, n) cin >> s[i];
    vector<vector<pair<int, int> > > g(n);
    REP (j, m) {
        int a, b, c; cin >> a >> b >> c;
        -- a; -- b;
        g[a].emplace_back(b, c);
        g[b].emplace_back(a, c);
    }
    bool winner = solve(n, m, s, g);
    cout << (winner ? "First" : "Second") << endl;
    return 0;
}
```
