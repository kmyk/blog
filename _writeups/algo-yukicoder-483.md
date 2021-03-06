---
layout: post
redirect_from:
  - /writeup/algo/yukicoder/483/
  - /blog/2017/04/18/yuki-483/
date: "2017-04-18T15:37:59+09:00"
tags: [ "competitive", "writeup", "yukicoder", "2-sat" ]
"target_url": [ "http://yukicoder.me/problems/no/483" ]
---

# Yukicoder No.483 マッチ並べ

非想定解だった。意外だ。

## solution

$2$-SAT。$O(N)$あるいは雑に辺を張って$O(N^2)$。

$v_i$を「$i$番目のマッチ棒の頭薬の位置が$(r\_{1i}, c\_{1i})$」として、$v\_0, \dots, v\_{n-1}$の制約をCNFとして列挙すればよい。

## implementation

``` c++
#include <cstdio>
#include <vector>
#include <algorithm>
#include <tuple>
#include <cassert>
#define repeat(i,n) for (int i = 0; (i) < int(n); ++(i))
#define repeat_from(i,m,n) for (int i = (m); (i) < int(n); ++(i))
using namespace std;

struct strongly_connected_components {
    static pair<int,vector<int> > decompose(vector<vector<int> > const & g) { // adjacent list
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

vector<bool> twosat(int n, vector<pair<int, int> > const & cnf) {
    // make digraph
    vector<vector<int> > g(2*n);
    auto i = [&](int x) { assert (x != 0 and abs(x) <= n); return x > 0 ? x-1 : n-x-1; };
    for (auto it : cnf) {
        int x, y; tie(x, y) = it; // x or y
        g[i(- x)].push_back(i(y)); // not x implies y
        g[i(- y)].push_back(i(x)); // not y implies x
    }
    // do SCC
    vector<int> component = strongly_connected_components::decompose(g).second;
    vector<bool> valuation(n);
    repeat_from (x,1,n+1) {
        if (component[i(x)] == component[i(- x)]) { // x iff not x
            return vector<bool>(); // unsat
        }
        valuation[x-1] = component[i(x)] > component[i(- x)]; // use components which indices are large
    }
    return valuation;
}

int main() {
    int n; scanf("%d", &n);
    vector<int> y[2] = { vector<int>(n), vector<int>(n) };
    vector<int> x[2] = { vector<int>(n), vector<int>(n) };
    repeat (i,n) scanf("%d%d%d%d", &y[0][i], &x[0][i], &y[1][i], &x[1][i]);
    vector<pair<int, int> > cnf;
    repeat (j,n) repeat (i,j) {
        repeat (p,2) repeat (q,2) {
            if (make_pair(y[p][i], x[p][i]) == make_pair(y[q][j], x[q][j])) {
                int vi = (i+1) * (p ? 1 : -1);
                int vj = (j+1) * (q ? 1 : -1);
                cnf.emplace_back(- vi, - vj);
                cnf.emplace_back(- vj, - vi);
            }
        }
    }
    bool is_sat = not twosat(n, cnf).empty();
    printf("%s\n", is_sat ? "YES" : "NO");
    return 0;
}
```
