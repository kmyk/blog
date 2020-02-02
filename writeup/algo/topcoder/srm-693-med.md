---
layout: post
alias: "/blog/2016/06/26/srm-693-med/"
title: "TopCoder SRM 693 Div1 Medium: BipartiteConstruction"
date: 2016-06-26T17:36:17+09:00
tags: [ "competitive", "writeup", "topcoder", "srm", "graph", "bipartite-graph", "construction" ]
---

解けず。$k = (a_0a_1a_2 + a_3a_4a_5 + a_6a_7a_8)(a_9 + a\_{10})(a\_{11}a\_{12} + a\_{13}a\_{14})\dots$といい感じに分解できれば解けるというところまでは分かったが、分解がだめ。

challenge phaseにPetr氏の提出を見てみたら頭のいい解答だったのでそれを理解したのがこれ。
正解は素因数分解ではなく$n$進数展開であった。

## problem

整数$k \le 10^9$が与えられる。整数$n \le 20, m \le 120$を好きに決めてよい。
$n + n$頂点$m$辺の二部グラフで、完全マッチングをちょうど$k$個持つものを構成せよ。
多重辺は使ってよい。

## solution

Use base $B$ number system, especially $B = 3$, like below. This figure is the graph for the case $k = 57 = 1 \cdot 3^3 + 2 \cdot 3^2 + 1 \cdot 3^1 + 0 \cdot 3^0$.

[![](/blog/2016/06/26/srm-693-med/a.png)](/blog/2016/06/26/srm-693-med/a.dot)

## implementation

``` c++
#include <bits/stdc++.h>
#define repeat(i,n) for (int i = 0; (i) < (n); ++(i))
using namespace std;
class BipartiteConstruction { public: vector<int> construct(int K); };

const int n = 20;
const int base = 3;
vector<int> BipartiteConstruction::construct(int k) {
    vector<int> ans { n };
    auto add_edge = [&](int i, int j) { ans.push_back(i * n + j); };
    repeat (i,n-1) {
        add_edge(i, i);
        repeat (j, base) add_edge(i, i+1);
    }
    for (int i = n-1; k; -- i) {
        assert (i >= 0);
        repeat (j, k % base) add_edge(n-1, i);
        k /= base;
    }
    return ans;
}
```
