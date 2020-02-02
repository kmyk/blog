---
layout: post
title: "CodeChef October Mega Cook-Off 2018 Division 2: Power Tree"
date: 2018-10-22T06:39:53+09:00
tags: [ "competitive", "writeup", "codechef", "cook-off", "ordinal", "construction" ]
"target_url": [ "https://www.codechef.com/COOK99B/problems/PWRTREE" ]
---

## 問題

[tournament](https://en.wikipedia.org/wiki/Tournament_(graph_theory)) が与えられるので、頂点を変えず辺のみを削除して順序数の$\epsilon$-relationのグラフにせよ

## 解法

### 概要

解けなかったのでプロのツイートを勝手に貼ります

<blockquote class="twitter-tweet" data-lang="ja"><p lang="ja" dir="ltr">PWRTREE<br>Sを頂点全体の集合として、要素数が1になるまで次を繰り返せばいい。<br>S内の頂点のペアを作る。これらのペアの間の辺は使うことにする。各ペアで辺が出てる側を集めてSとする。</p>&mdash; (nは自然数) (@n_vip) <a href="https://twitter.com/n_vip/status/1054078941705584641?ref_src=twsrc%5Etfw">2018年10月21日</a></blockquote>
<script async src="https://platform.twitter.com/widgets.js" charset="utf-8"></script>

<blockquote class="twitter-tweet" data-conversation="none" data-lang="ja"><p lang="ja" dir="ltr">これはループを生き残った回数がi回のものがPT(i)の根になっているんですが、PT(0),PT(1),...と根の数が半々になってくのを眺めてるとこれが思いつきます</p>&mdash; (nは自然数) (@n_vip) <a href="https://twitter.com/n_vip/status/1054081391913127936?ref_src=twsrc%5Etfw">2018年10月21日</a></blockquote>
<script async src="https://platform.twitter.com/widgets.js" charset="utf-8"></script>

## メモ

-   どうでもいいけど順序数になってる
-   さらについでにvon Neumann's definitionでないordinalの名前を思い出せた: [Zermelo ordinal](https://en.wikipedia.org/wiki/Natural_number#Zermelo_ordinals)
    -   過去に教えてもらったのにいつの間にか名前だけ忘れてしまったのが気持ち悪くて探していた

## 実装

``` c++
#include <bits/stdc++.h>
#define REP(i, n) for (int i = 0; (i) < (int)(n); ++ (i))
#define ALL(x) begin(x), end(x)
using namespace std;
template <typename X, typename T> auto vectors(X x, T a) { return vector<T>(x, a); }
template <typename X, typename Y, typename Z, typename... Zs> auto vectors(X x, Y y, Z z, Zs... zs) { auto cont = vectors(y, z, zs...); return vector<decltype(cont)>(x, cont); }

vector<int> solve(int n, vector<vector<int> > const & g) {
    assert (1 <= n and n <= 256);
    if (__builtin_popcount(n) != 1) return vector<int>(1, -1);
    vector<int> removed;
    vector<int> cur(n);
    iota(ALL(cur), 0);
    vector<vector<int> > children(n);
    REP (i, n) children[i].push_back(i);
    while (cur.size() >= 2) {
        vector<int> nxt;
        assert (cur.size() % 2 == 0);
        for (int k = 0; k < cur.size(); k += 2) {
            int i = cur[k];
            int j = cur[k + 1];
            if (g[i][j] == -1) swap(i, j);
            for (int i1 : children[i]) {
                for (int j1 : children[j]) {
                    if (i1 == i and j1 == j) continue;
                    if (g[i1][j1] != -1) removed.emplace_back(g[i1][j1]);
                    if (g[j1][i1] != -1) removed.emplace_back(g[j1][i1]);
                }
            }
            nxt.push_back(i);
            children[i].insert(children[i].end(), ALL(children[j]));
        }
        cur = nxt;
    }
    return removed;
}

int main() {
    int testcase; cin >> testcase;
    while (testcase --) {
        int n; cin >> n;
        auto g = vectors(n, n, -1);
        REP (i, n * (n - 1) / 2) {
            int u, v; cin >> u >> v;
            -- u; -- v;
            g[u][v] = i;
        }
        auto removed = solve(n, g);
        if (removed.size() == 1 and removed[0] == -1) {
            cout << -1 << endl;
        } else {
            cout << removed.size() << endl;
            REP (i, removed.size()) {
                if (i) cout << ' ';
                cout << removed[i] + 1;
            }
            cout << endl;
        }
    }
    return 0;
}
```
