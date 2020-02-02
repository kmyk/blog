---
layout: post
alias: "/blog/2016/06/12/jag2016-domestic2-d/"
title: "JAG 模擬国内予選 2016: D - 夏合宿の朝は早い"
date: 2016-06-12T22:30:45+09:00
tags: [ "competitive", "writeup", "icpc", "jag", "strongly-connected-components-decomposition", "scc", "graph" ]
"target_url": [ "http://acm-icpc.aitea.net/index.php?2016%2FPractice%2F%E6%A8%A1%E6%93%AC%E5%9B%BD%E5%86%85%E4%BA%88%E9%81%B8B" ]
---

sccのライブラリを使える形で持ってたのが私だけだったので私が書いた。

## implementation

有向グラフが与えられる。
それぞれの頂点には確率$p$が定められていて、確率$1 - p$で活性化し、確率$p$で活性化しない。
その頂点から有向辺を辿って辿り着ける頂点は全て活性化する。
全ての頂点が活性化する確率を求めよ。

## solution

強連結成分分解して入次数が$0$な強連結成分を見る。強連結成分分解の方法に依存するが$O(V + E)$にできる。

活性化していない頂点が存在する確率を求めればよい。
ある頂点が活性化しないのは、その頂点とその頂点へと辿り付ける頂点全てが活性化していないときである。

ここで有向閉路が存在すると面倒なので、強連結成分分解をして、これを除去しておく。
それぞれの強連結成分だけで考えて、その成分が活性化しないのはその成分中の頂点すべてが活性化しないときである。その確率は$\Pi\_{v \in C} p_v$。
次に、他の成分との関連を考える。成分$A$への有向辺を持つ成分$B$があるとき、$B$が活性なら$A$は常に活性、$B$が活性でないとき$A$がどうであろうと影響しない。よって入次数が正の成分は無視してよい。

よって、入次数$0$な強連結成分$C_i$が全て活性化する確率を答えればよいので、$\operatorname{ans} = \Pi_i (1 - \Pi\_{v \in C_i} p_v)$。

## implementation

``` c++
#include <iostream>
#include <vector>
#include <algorithm>
#include <tuple>
#define repeat(i,n) for (int i = 0; (i) < (n); ++(i))
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
    vector<int> c; // i-th vertex
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

int main() {
    while (true) {
        // input
        int n; cin >> n;
        if (n == 0) break;
        vector<double> p(n);
        vector<vector<int> > g(n); // adj. list
        repeat (i,n) {
            cin >> p[i];
            int m; cin >> m;
            repeat (j,m) {
                int a; cin >> a; -- a;
                g[i].push_back(a);
            }
        }
        // scc
        int k; vector<int> c;
        tie(k, c) = strongly_connected_components::decompose(g);
        vector<bool> root(k, true); // the componet's indeg is 0 or not
        repeat (i,n) {
            for (int j : g[i]) {
                if (c[i] != c[j]) {
                    root[c[j]] = false;
                }
            }
        }
        // calc
        double ans = 1; // all group awake
        repeat (a,k) if (root[a]) {
            double q = 1; // all member sleep
            repeat (i,n) if (c[i] == a) {
                q *= p[i];
            }
            ans *= 1 - q;
        }
        // output
        printf("%.9lf\n", ans);
    }
    return 0;
}
```
