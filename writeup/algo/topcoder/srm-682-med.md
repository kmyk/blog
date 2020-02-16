---
layout: post
alias: "/blog/2016/02/23/srm-682-med/"
date: 2016-02-23T12:24:11+09:00
tags: [ "competitive", "writeup", "topcoder", "srm", "graph", "tree", "cycle" ]
---

# TopCoder SRM 682 Div1 Medium: SuccessfulMerger

3分足りなかった。

## [Medium: SuccessfulMerger]()

### 問題

頂点数$N$辺数$N$でloopを持たない連結グラフ$G$が与えられる。
このグラフの隣接する頂点を併合する操作を繰り返し以下の条件を満たすようにするとき、必要な操作の最小回数を求めよ。

-   ある頂点$k$があって、任意の異なる2頂点$i,j$に対し、$i$から$j$への道は必ず$k$を含む。

### 解法

最終的なグラフは、次数$n$の頂点ひとつを除いて全て次数$1$なグラフ$K\_{1,n}$になる。
葉の数を数える。

多重辺を無視すると、木に橋が高々1本かかったグラフと考えてよい。
(長さ$3$以上の)閉路が存在すると明らかに条件を満たさないので、その閉路は2頂点を残して潰されねばならない。

葉の数を考えるとき、元々葉である頂点は変化しないので、考えるべきはこの閉路から発生する葉である。
閉路中に次数$2$の頂点があれば、それをそのまま残すように潰せば、葉がひとつ得られる。

中心となる頂点も次数が$1$となるとき、つまり$N = 2$のときが例外。

### 実装

``` c++
#include <bits/stdc++.h>
#include <functional>
#define repeat(i,n) for (int i = 0; (i) < (n); ++(i))
using namespace std;
class SuccessfulMerger { public: int minimumMergers(vector<int> road); };
int SuccessfulMerger::minimumMergers(vector<int> road) {
    int n = road.size();
    if (n == 2) return 0;
    vector<vector<int> > g(n);
    repeat (i,n) {
        if (count(g[i].begin(), g[i].end(), road[i])) continue; // skip double edges
        g[i].push_back(road[i]);
        g[road[i]].push_back(i);
    }
    vector<int> cycle; {
        vector<bool> used(n);
        vector<int> parent(n);
        function<bool (int, int)> dfs = [&](int i, int p) {
            used[i] = true;
            parent[i] = p;
            for (int j : g[i]) if (j != p) {
                if (used[j]) {
                    for (int k = i; k != parent[j]; k = parent[k]) {
                        cycle.push_back(k);
                    }
                    return true;
                } else {
                    if (dfs(j, i)) return true;
                }
            }
            return false;
        };
        dfs(0, -1);
    }
    auto degree = [&](int i) { return g[i].size(); };
    int leaf = 0;
    for (int i : cycle) {
        if (degree(i) == 2) {
            ++ leaf;
            break;
        }
    }
    set<int> scycle;
    for (int i : cycle) scycle.insert(i);
    repeat (i,n) if (not scycle.count(i)) {
        if (degree(i) == 1) {
            ++ leaf;
        }
    }
    return n - leaf - 1;
}
```
