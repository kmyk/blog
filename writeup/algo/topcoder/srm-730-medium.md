---
layout: post
alias: "/blog/2018/02/21/srm-730-medium/"
title: "TopCoder SRM 730 Div 1 Medium. Subgraphs"
date: "2018-02-21T13:53:03+09:00"
tags: [ "competitive", "writeup", "topcoder", "srm", "graph", "construction" ]
---

## problem

整数$k$が与えられる。頂点数が高々$2k$の単純無向グラフ$G = (V, E)$で次のようなものを出力せよ: 任意の$x \le {}\_kC\_2$について、ある集合$Y \subseteq V$で$\|Y\| = k$なものがあって、$Y$で誘導される部分グラフ$G'$の頂点数が$x$と等しい。

## solution

構築。$O(k^2)$。

完全グラフ$K\_k$と、その頂点へちょうど$i$本の辺を持つ頂点$i = 1, 2, \dots, k$を作る。
特に、頂点$i$と隣接する頂点の集合を$A(i)$としたとき、$A(1) \subseteq A(2) \subseteq \dots \subseteq A(k)$にする。
あとはいい感じに辺を張る。

## implementation

``` c++
#include <bits/stdc++.h>
#define REP(i, n) for (int i = 0; (i) < int(n); ++ (i))
using namespace std;
class Subgraphs { public: vector<string> findGroups(int k); };

vector<string> Subgraphs::findGroups(int k) {
    vector<string> result;
    // make the adj. matrix
    REP (i, 2 * k - 1) {
        string s(2 * k - 1, '0');
        result.push_back(s);
    }
    REP (i, k) REP (j, i) {
        result[i][j] = '1';
        result[j][i] = '1';  // the complete graph
    }
    REP (i, k - 1) REP (j, i + 1) {
        result[k + i][j] = '1';
        result[j][k + i] = '1';  // the remaining part
    }
    // make the sets
    REP (x, k * (k - 1) / 2 + 1) {
        string s(2 * k - 1, 'N');
        int y = 0;
        while ((y + 1) * y / 2 <= x) ++ y;
        REP (i, y) {
            s[k - i - 1] = 'Y';
        }
        REP (i, k - y - 1) {
            s[k + i] = 'Y';
        }
        int i = x - y * (y - 1) / 2;
        s[k + (k - y - 1) + i] = 'Y';
        result.push_back(s);
    }
    return result;
}
```
