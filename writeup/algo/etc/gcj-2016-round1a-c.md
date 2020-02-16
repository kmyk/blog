---
layout: post
redirect_from:
  - /blog/2016/04/16/gcj-2016-round1a-c/
date: 2016-04-16T15:23:58+09:00
tags: [ "competitive", "writeup", "gcj", "google-code-jam", "graph", "tree" ]
"target_url": [ "https://code.google.com/codejam/contest/4304486/dashboard#s=p2" ]
---

# Google Code Jam 2016 Round 1A C. BFFs

## problem

全ての頂点の出次数が$1$であるような、有向グラフ$G$が与えられる。
このグラフの頂点の列$a$で、以下の条件を満たすもので、長さが最大のものの長さを答えよ。

-   どの頂点$a_i$に関しても、列内の前後の頂点($a\_{i-1}, a\_{i+1}$, ただし$0,n-1$の前/後ろは$n-1,0$とする)のどちらかに対し$a_i$からの辺がある

## solution

$O(N^2)$.

The result path is one of them:

-   single directed cycle in $G$
-   list of special directed paths
    -   the special directed path is a path like $a \rightarrow b \rightarrow \dots \rightarrow p \leftrightarrow q \leftarrow r \leftarrow \dots \leftarrow z$.

To list directed cycles is easy.

About the special directed paths.
Each path can be obtained from each undirected component.
One component always has just one cycle (including one whose length is $2$), and directed rooted trees are connected to it.
If the cycle length is $3$ or more, the component cannot form any chains.
The cycle length is $2$, it can form one chain, with adding two directed paths.


## implementation

``` c++
#include <iostream>
#include <vector>
#include <algorithm>
#include <functional>
#define repeat(i,n) for (int i = 0; (i) < (n); ++(i))
template <class T> bool setmax(T & l, T const & r) { if (not (l < r)) return false; l = r; return true; }
using namespace std;
void solve() {
    int n; cin >> n;
    vector<int> g(n);
    vector<vector<int> > h(n);
    repeat (i,n) {
        cin >> g[i]; -- g[i];
        h[g[i]].push_back(i);
    }
    int ans = -1;
    function<int (int, int, int)> rec = [&](int i, int depth, int root) {
        if (i == root) {
            setmax(ans, depth); // cycle
            return depth - 1;
        } else {
            int result = depth;
            for (int j : h[i]) {
                setmax(result, rec(j, depth + 1, root));
            }
            return result;
        }
    };
    vector<int> component(n, -1);
    int components_num = 0; {
        function<void (int)> collect = [&](int i) {
            if (component[i] != -1) return;
            component[i] = components_num;
            collect(g[i]);
            for (int j : h[i]) collect(j);
        };
        repeat (i,n) if (component[i] == -1) {
            collect(i);
            ++ components_num;
        }
    }
    vector<int> chain(components_num);
    repeat (i,n) {
        vector<int> xs;
        for (int j : h[i]) {
            xs.push_back(rec(j,1,i));
        }
        if (not xs.empty()) {
            int x = 0;
            int j = -1;
            repeat (k,xs.size()) if (g[i] == h[i][k]) {
                if (setmax(x, xs[k])) {
                    j = k;
                }
            }
            if (j != -1) {
                int y = 0;
                repeat (k,xs.size()) if (k != j) {
                    setmax(y, xs[k]);
                }
                setmax(chain[component[i]], x + 1 + y);
            }
        }
    }
    setmax(ans, accumulate(chain.begin(), chain.end(), 0));
    cout << ans << endl;
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
