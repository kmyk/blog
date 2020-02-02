---
layout: post
alias: "/blog/2016/05/01/gcj-2016-round1b-c/"
title: "Google Code Jam 2016 Round 1B C. Technobabble"
date: 2016-05-01T04:24:19+09:00
tags: [ "competitive", "writeup", "google-code-jam", "gcj", "graph", "bipartite-graph", "flow", "ford-fulkerson", "maximum-flow", "maximum-matching", "minimum-edge-cover" ]
"target_url": [ "https://code.google.com/codejam/contest/11254486/dashboard#s=p2" ]
---

最小辺被覆でぐぐったら最大独立集合とでてきたので飛び付いた結果、通せなかった。
最大流で最小辺被覆を求めるのは途中で考えていたので、これをちゃんとやれていれば通っていたはずだった。
However, I could advance to the Round 2 :)

## problem

生徒らが紙に単語の順序対を順番に書いた。
まじめでない生徒は、既に紙に書かれた単語対からコピペして別な単語対を作りだして書く。
そのようにして書かれた単語対の集合が(書かれた順序とは無関係な順に)与えられる。
まじめでない生徒は何人居たと考えられるか、その最大値を答えよ。

## solution

Minimum edge cover, using Maximum flow. $O(E^2)$.

Given words consists a bipartite graph.
And, what you need to find can be seen as the minimum edge cover.
Minimum edge cover is easily calculated ($(\text{minimum edge cover}) = E - V + (\text{maximum matching})$)if you know the maximum matching of the bipartite graph, and the maximum matching is obtained using a maximum flow.
So, you should find a maximum flow.

## implementation

``` c++
#include <iostream>
#include <vector>
#include <map>
#include <functional>
#include <limits>
#define repeat(i,n) for (int i = 0; (i) < (n); ++(i))
using namespace std;

struct edge_t { int to, cap, rev; };
void add_edge(vector<vector<edge_t> > & g, int from, int to, int cap) {
    g[from].push_back((edge_t){ to, cap, int(g[to].size()) });
    g[to].push_back((edge_t){ from, 0, int(g[from].size())-1 });
}
int maximum_flow(int s, int t, vector<vector<edge_t> > g /* adjacency list */) { // ford fulkerson, O(FE)
    int n = g.size();
    vector<bool> used(n);
    function<int (int, int)> dfs = [&](int i, int f) {
        if (i == t) return f;
        used[i] = true;
        for (edge_t & e : g[i]) {
            if (used[e.to] or e.cap <= 0) continue;
            int nf = dfs(e.to, min(f, e.cap));
            if (nf > 0) {
                e.cap -= nf;
                g[e.to][e.rev].cap += nf;
                return nf;
            }
        }
        return 0;
    };
    int result = 0;
    while (true) {
        used.clear(); used.resize(n);
        int f = dfs(s, numeric_limits<int>::max());
        if (f == 0) break;
        result += f;
    }
    return result;
}

void solve() {
    int n; cin >> n;
    vector<int> l(n), r(n);
    int ln = 0, rn = 0; {
        map<string,int> dict_l, dict_r;
        repeat (i,n) {
            string s, t; cin >> s >> t;
            if (not dict_l.count(s)) dict_l[s] = ln ++;
            if (not dict_r.count(t)) dict_r[t] = rn ++;
            l[i] = dict_l[s];
            r[i] = dict_r[t];
        }
    }
    vector<vector<edge_t> > g(1 + ln + rn + 1);
    int src = 0;
    int left = 1;
    int right = 1 + ln;
    int dst = 1 + ln + rn;
    repeat (i,ln) add_edge(g, src, left + i, 1);
    repeat (i, n) add_edge(g, left + l[i], right + r[i], 1);
    repeat (i,rn) add_edge(g, right + i, dst, 1);
    int v = ln + rn;
    int e = n;
    int minimum_edge_cover = e - v + maximum_flow(src, dst, g);
    cout << minimum_edge_cover << endl;
}
int main() {
    int t; cin >> t;
    repeat (i,t) {
        cout << "Case #" << i+1 << ": ";
        solve();
    }
    return 0;
}
```
