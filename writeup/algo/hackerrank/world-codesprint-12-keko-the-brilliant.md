---
layout: post
alias: "/blog/2017/12/31/hackerrank-world-codesprint-12-keko-the-brilliant/"
date: "2017-12-31T16:26:58+09:00"
tags: [ "competitive", "writeup", "hackerrank", "codesprint", "dp", "tree", "red-black-tree", "monotonicity", "weighted-union-heuristics" ]
"target_url": [ "https://www.hackerrank.com/contests/world-codesprint-12/challenges/keko-the-brilliant" ]
---

# HackerRank World CodeSprint 12: Keko the Brilliant

## problem

根付き木が与えられる。
各点に重みが付いている。
いくつかの点の重みを好きな非負整数に書き換えて「子は親よりも常に大きいか等しい」ようにしたい。
最小でいくつの点を書き換える必要があるか。

## solution

木DP。赤黒木とweighted union heuristicsで加速。$O(N (\log N)^2)$。

部分木$T$の根の重みを$a$にしたときのコストを$\mathrm{dp}\_T(a)$とする。
愚直にやると$O(N^2)$。
このとき$\mathrm{dp}\_T$は広義単調増加な整数値関数であり、値の増加の回数は部分木の大きさで抑えられる。
この関数を増加する点で表現して`map<int, int>`としweighted union heuristicsで合成することで$O(N (\log N)^2)$となる。

動的構築segment木でもなんとかなる気はするがかなり面倒そう。
少し似た問題として [東京大学プログラミングコンテスト2012 L - じょうしょうツリー](https://beta.atcoder.jp/contests/utpc2012/tasks/utpc2012_12) がある。

## implementation

stack上に`map<int, int>`を取るとSegmentation Faultした、のでheapに取った。
手元で`sizeof map<int, int>`は$48$とそう大きくはないし、代入文を適当にコメントアウトするだけで消えたりするのでよく分からない。
最適化や一時変数が影響するようなきわどい状況なのだろうか。
詳しくは調べていない。

``` c++
#include <bits/stdc++.h>
#define REP(i, n) for (int i = 0; (i) < int(n); ++ (i))
using namespace std;

int main() {
    // input
    int n; scanf("%d", &n);
    vector<int> r(n); REP (i, n) scanf("%d", &r[i]);
    vector<vector<int> > g(n);
    REP (i, n - 1) {
        int x, y; scanf("%d%d", &x, &y);
        -- x; -- y;
        g[x].push_back(y);
        g[y].push_back(x);
    }
    // solve
    function<map<int, int> *(int, int)> dp = [&](int x, int parent) {
        auto cur = new map<int, int>();
        for (int y : g[x]) if (y != parent) {
            auto prv = dp(y, x);
            if (cur->size() < prv->size()) cur->swap(*prv);
            for (auto it : *prv) {
                (*cur)[it.first] += it.second;
            }
            delete prv;
        }
        (*cur)[0] += 1;
        (*cur)[r[x] + 1] += 1;
        auto it = -- cur->upper_bound(r[x]);
        it->second -= 1;
        if (it->second == 0) {
            cur->erase(it);
        }
        return cur;
    };
    int result = (*dp(0, -1))[0];  // leak
    // output
    printf("%d\n", result);
    return 0;
}
```
