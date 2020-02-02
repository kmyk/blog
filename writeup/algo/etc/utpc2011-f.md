---
layout: post
alias: "/blog/2017/12/25/utpc2011-f/"
title: "東京大学プログラミングコンテスト2011: F. 全域木"
date: "2017-12-25T19:10:49+09:00"
tags: [ "competitive", "writeup", "utpc", "aoj", "spanning-tree", "construction" ]
---

-   <http://www.utpc.jp/2011/problems/spanning.html>
-   <http://judge.u-aizu.ac.jp/onlinejudge/description.jsp?id=2264>

## solution

再帰的に作る。$O(NK)$。

まず辺の数の条件から$2K \le N$でなければ明らかに構成不能。
逆にそうでなければ構成できる。

-   $N$は奇数として$N-1$で$K$個の互いに素な全域木があったとする。
    明らかに$K \le N$なので、新しい点から各全域木の適当な点に対して辺を生やせば終わり。
    このとき$N - K$本の辺が使われずに残るが、これらは木を削って余ったものであるため閉路を成さない。
-   $N$は偶数として$N-1$で$K-1$個の互いに素な全域木があったとする。
    $N = 2K$としてよい。
    $N-1$で使われていない辺が${}\_{N-1}C\_2 - (K-1)(N-2) = K - 1$本あり、上で見たように閉路を持たない。
    新しく追加される頂点により$N-1$本の辺が増える。
    まず古い$K-1$本と新しく追加された辺の中から$(N-1)-(K-1)$本で新しい全域木を作る。
    古いのに閉路がないことと新しいのの追加のされ方から必ず木にできる。
    残った$K-1$本で$N$が奇数の場合と同様にすれば完成。

## implementation

``` c++
#include <bits/stdc++.h>
#define REP3(i, m, n) for (int i = (m); (i) < int(n); ++ (i))
using namespace std;

int main() {
    int n, k; scanf("%d%d", &n, &k);
    if (2 * k > n) {
        printf("-1\n");
    } else {
        vector<vector<pair<int, int> > > spaning_trees;
        vector<pair<int, int> > unused_edges;
        REP3 (i, 2, n + 1) {
            int j = 0;
            for (; j < spaning_trees.size(); ++ j) {
                int k = i & 1 ? j : (i - 1) - j - 1;
                spaning_trees[j].emplace_back(k, i - 1);
            }
            if (spaning_trees.size() >= k) continue;
            for (; j < i - 1; ++ j) {
                int k = i & 1 ? j : (i - 1) - j - 1;
                unused_edges.emplace_back(k, i - 1);
            }
            if (i % 2 == 0) {
                spaning_trees.push_back(unused_edges);
                unused_edges.clear();
            }
        }
        for (auto const & spaning_tree : spaning_trees) {
            for (auto edge : spaning_tree) {
                int i, j; tie(i, j) = edge;
                printf("%d %d\n", i + 1, j + 1);
            }
            printf("\n");
        }
    }
    return 0;
}
```
