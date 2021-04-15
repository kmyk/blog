---
layout: post
redirect_from:
  - /writeup/algo/codeforces/592-d/
  - /blog/2015/11/01/cf-592-d/
date: 2015-11-01T12:50:56+09:00
tags: [ "codeforces", "competitive", "writeup", "tree", "diameter" ]
---

# Codeforces Round #328 (Div. 2) D. Super M

本番中はひたすらdfsを書いていた。計算量的には通ると思ったが、実装量的な問題で通らなかった。
直径使うのも一度は考えたのだけど、dfsでいけると思ったので考えるのを止めてしまった。

<!-- more -->

## [D. Super M](http://codeforces.com/contest/592/problem/D)

### 問題

木と、その木の頂点で通るべきものの集合が与えられる。
適当な頂点から始めて、通るべき頂点を全て通るような歩道を考える。
その中でも最短のもの、長さが同じであれば始点のindexが最も小さいものの、始点と長さを答えよ。

### 解法

直径を使う。

まず、通る必要のない葉を削除して、目的の歩道が木の全ての頂点と辺を使うようにする。
すると、目的の歩道の長さは、そのような木の*長さ - 直径*で求められる。
始点のindexについては、最も遠い頂点を求めるという操作を、直径を求めるだけならば2回でよいが、これを3回行えば得られる。

### 実装

``` c++
#include <iostream>
#include <vector>
#include <set>
#include <tuple>
#define repeat_from(i,m,n) for (int i = (m); (i) < (n); ++(i))
#define repeat(i,n) repeat_from(i,0,n)
using namespace std;
constexpr int inf = 1000000007;
bool shrink_tree(int v, int p, vector<vector<int> > & g, set<int> const & vs) {
    bool can_drop = not vs.count(v);
    vector<int> es;
    for (int w : g[v]) if (w != p) {
        if (shrink_tree(w, v, g, vs)) {
            // when you can drop the edge to w, nop
        } else {
            es.push_back(w);
            can_drop = false;
        }
    }
    if (not can_drop and p != inf) es.push_back(p);
    g[v].swap(es);
    return can_drop;
}
int size(int v, int p, vector<vector<int> > & g) {
    int result = 1;
    for (int w : g[v]) if (w != p) {
        result += size(w, v, g);
    }
    return result;
}
// depth, - vertex
pair<int,int> farthest(int v, int p, vector<vector<int> > & g) {
    auto result = make_pair(0, - v);
    for (int w : g[v]) if (w != p) {
        result = max(result, farthest(w, v, g));
    }
    result.first += 1;
    return result;
}
int main() {
    int n, m; cin >> n >> m;
    vector<vector<int> > g(n);
    repeat (i,n-1) {
        int a, b; cin >> a >> b; -- a; -- b;
        g[a].push_back(b);
        g[b].push_back(a);
    }
    set<int> vs;
    repeat (i,m) {
        int v; cin >> v; -- v;
        vs.insert(v);
    }
    int v0 = *vs.begin();
    shrink_tree(v0, inf, g, vs);
    int sz = size(v0, inf, g);
    int v1 = - farthest(v0, inf, g).second;
    int v2, diameter; tie(diameter, v2) = farthest(v1, inf, g); v2 *= -1;
    int v3 = - farthest(v2, inf, g).second;
    cout << min(v2, v3) + 1 << endl;
    cout << 2*sz - diameter - 1 << endl;
    return 0;
}
```
