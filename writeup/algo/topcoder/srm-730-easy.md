---
layout: post
alias: "/blog/2018/02/21/srm-730-easy/"
title: "TopCoder SRM 730 Div 1 Easy. StonesOnATree"
date: "2018-02-21T13:52:56+09:00"
tags: [ "competitive", "writeup", "topcoder", "srm", "tree", "dp" ]
---

## problem

<https://beta.atcoder.jp/contests/dwacon2018-prelims/tasks/dwacon2018_prelims_d> にいくつか制約が増えたもの。

## solution

木DP。 <https://beta.atcoder.jp/contests/dwacon2018-prelims/tasks/dwacon2018_prelims_d> の想定誤解法 (`02_tayama_killer00` にやられる) を投げれば制約が修正されているため通る。$O(n)$。

重みの単調性(と木の与え方)により部分木を順番に作っていくことが許され、子が高々ふたつの制約により計算量が落ちる。

## implementation

``` c++
#include <bits/stdc++.h>
#define REP(i, n) for (int i = 0; (i) < int(n); ++ (i))
using namespace std;
class StonesOnATree { public: int minStones(vector<int> p, vector<int> w); };

int StonesOnATree::minStones(vector<int> p, vector<int> w) {
    int n = w.size();
    vector<vector<int> > children(n);
    REP (i, n - 1) {
        children[p[i]].push_back(i + 1);
    }

    function<int (int)> go = [&](int i) {
        if (children[i].empty()) {
            return w[i];
        } else if (children[i].size() == 1) {
            int j = children[i][0];
            int go_j = go(j);
            return max(go_j, w[i] + w[j]);
        } else if (children[i].size() == 2) {
            int j = children[i][0];
            int k = children[i][1];
            int go_j = go(j);
            int go_k = go(k);
            return max(w[i] + w[j] + w[k],
                    min(max(go_j, w[j] + go_k),
                        max(go_k, w[k] + go_j)));
        } else {
            assert (false);
        }
    };
    return go(0);
}
```
