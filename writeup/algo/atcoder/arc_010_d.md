---
layout: post
redirect_from:
  - /writeup/algo/atcoder/arc-010-d/
  - /blog/2015/12/22/arc-010-d/
date: 2015-12-22T23:42:32+09:00
tags: [ "competitive", "writeup", "atcoder", "arc", "scc", "strongly-connected-components-decomposition", "dag", "directed-acyclic-graph", "graph" ]
---

# AtCoder Regular Contest 010 D - 情報伝播

ライブラリ貼るだけだったのに、貼るライブラリを間違えてWAをたくさん生やした。
具体的に言うと、長さ3以上の有向閉路を考えるのを漏らしていて、union find木で解こうとしていた。

<!-- more -->

## [D - 情報伝播](https://beta.atcoder.jp/contests/arc010/tasks/arc010_4) {#d}

### 問題

平面上に$N$人($N \le 5000$)の仲間と$M$人($M \le 10^5$)の敵がいる。
敵に知られずに、あなたが持っているある情報を仲間全員で共有したい。
ある仲間が情報を得ると、その仲間はスピーカーを用いて適当な半径$r$以内の全ての人間に情報を伝えることができる。
このことから、あなたが直接情報を伝えれば、連鎖的に情報を伝達させることができる。
直接情報を伝えなければいけないの最低で何人か。

### 解法

それぞれの仲間は敵に聞こえない最大の大きさで情報を拡散すればよい。
この情報の伝達関係の有向グラフを作る。
特にその推移閉包を考え、これの点被覆の大きさを答えればよい。

具体的に言うと、まず1回のスピーカーによる拡散に関する伝達関係の有向グラフを作る。
これは$O(nm)$で構成すれば間に合う。整数で取り扱えばよい。

次に情報を直接伝えるべき仲間を表す頂点を探す。
そのような頂点の集合は、その要素の頂点から到達できる頂点を全て集めると、頂点全体になっている。つまり推移閉包の点被覆である。
まず、入次数が$0$の頂点は、明らかに点被覆に入る。
そう考えたとき閉路が問題となるが、これは事前に強連結成分分解をすれば回避できる。
有向非巡回グラフ(DAG)になっていれば、入次数が$0$でない点は何らかの入次数が$0$の点から到達できるので、これだけを行えば答えが得られる。この部分は$O(N^2)$である。

### 実装

以前書いた強連結成分分解を投げたらMLEしたので、ちゃんと開放が走るように修正をした。

``` c++
#include <iostream>
#include <vector>
#include <algorithm>
#include <climits>
#include <tuple>
#define repeat(i,n) for (int i = 0; (i) < (n); ++(i))
typedef long long ll;
using namespace std;
struct strongly_connected_components {
    static pair<int,vector<int> > decompose(vector<vector<int> > const & g) {
        strongly_connected_components scc(g);
        return { scc.k, scc.c };
    }
private:
    int n;
    vector<vector<int> > to, from;
    explicit strongly_connected_components(vector<vector<int> > const & g) : n(g.size()), to(g), from(n) {
        repeat (i,n) for (int j : to[i]) from[j].push_back(i);
        decompose();
    }
    vector<bool> used;
    vector<int> vs;
    void dfs(int i) {
        used[i] = true;
        for (int j : to[i]) if (not used[j]) dfs(j);
        vs.push_back(i);
    }
    int k; // number of scc
    vector<int> c; // i-th vertex in g is in c_i-th vertex in scc-decomposed g
    void rdfs(int i) {
        used[i] = true;
        c[i] = k;
        for (int j : from[i]) if (not used[j]) rdfs(j);
    }
    void decompose() {
        used.clear(); used.resize(n, false);
        repeat (i,n) if (not used[i]) dfs(i);
        used.clear(); used.resize(n, false);
        k = 0;
        c.resize(n);
        reverse(vs.begin(), vs.end());
        for (int i : vs) if (not used[i]) {
            rdfs(i);
            k += 1;
        }
    }
};
vector<vector<int> > components_graph(int k, vector<int> const & c, vector<vector<int> > const & g) {
    vector<vector<int> > f(k);
    repeat (i,g.size()) {
        for (int j : g[i]) {
            f[c[i]].push_back(c[j]);
        }
    }
    repeat (i,k) {
        sort(f[i].begin(), f[i].end());
        auto it = unique(f[i].begin(), f[i].end());
        it = remove(f[i].begin(), it, i);
        f[i].erase(it, f[i].end());
    }
    return f;
}
struct point_t { int y, x; };
ll sq(ll x) { return x*x; }
ll sqdist(point_t p, point_t q) {
    return sq(p.y-q.y) + sq(p.x-q.x);
}
vector<vector<int> > make_digraph(int n, vector<point_t> const & ps, int m, vector<point_t> const & qs) {
    vector<ll> rs(n, LLONG_MAX);
    repeat (i,n) {
        for (auto q : qs) {
            rs[i] = min(rs[i], sqdist(ps[i], q));
        }
    }
    vector<vector<int> > g(n); // directed graph
    repeat (i,n) {
        repeat (j,n) if (i != j) {
            if (sqdist(ps[i], ps[j]) < rs[i]) {
                g[i].push_back(j);
            }
        }
    }
    return g;
}
int count_roots(int n, vector<vector<int> > const & g) {
    vector<int> indegree(n);
    repeat (i,n) {
        for (int j : g[i]) {
            indegree[j] += 1;
        }
    }
    int result = 0;
    repeat (i,n) {
        if (indegree[i] == 0) {
            result += 1;
        }
    }
    return result;
}
int main() {
    int n; cin >> n;
    vector<point_t> ps(n); for (auto & p : ps) cin >> p.x >> p.y;
    int m; cin >> m;
    vector<point_t> qs(m); for (auto & q : qs) cin >> q.x >> q.y;
    if (m == 0) {
        cout << 1 << endl;
    } else {
        auto g = make_digraph(n, ps, m, qs);
        int k; vector<int> c;
        tie(k,c) = strongly_connected_components::decompose(g);
        auto f = components_graph(k, c, g);
        cout << count_roots(k, f) << endl;
    }
    return 0;
}
```
