---
layout: post
redirect_from:
  - /blog/2016/12/20/world-codesprint-8-torque-and-development/
date: "2016-12-20T02:33:03+09:00"
tags: [ "competitive", "writeup", "hackerrank", "world-codesprint" ]
"target_url": [ "https://www.hackerrank.com/contests/world-codesprint-8/challenges/torque-and-development" ]
---

# HackerRank World CodeSprint 8: Roads and Libraries

## solution

Let $K$ be the number of components of given graph, then $\mathrm{ans} = \min \\{ k \cdot c\_{\mathrm{lib}} + (n-k) \cdot c\_{\mathrm{road}} \mid 1 \le k \le K \\}$. $O(n)$ for each query.

## implementation

``` c++
#include <iostream>
#include <vector>
#include <functional>
#define repeat(i,n) for (int i = 0; (i) < int(n); ++(i))
typedef long long ll;
using namespace std;
template <class T> void setmin(T & a, T const & b) { if (b < a) a = b; }
const ll inf = ll(1e18)+9;
int main() {
    int queries; cin >> queries;
    while (queries --) {
        int n, m, c_lib, c_road; cin >> n >> m >> c_lib >> c_road;
        vector<vector<int> > g(n);
        repeat (i,m) {
            int u, v; cin >> u >> v; -- u; -- v;
            g[u].push_back(v);
            g[v].push_back(u);
        }
        int components = 0; {
            vector<bool> used(n);
            function<void (int)> dfs = [&](int i) {
                used[i] = true;
                for (int j : g[i]) if (not used[j]) dfs(j);
            };
            repeat (i,n) if (not used[i]) {
                components += 1;
                dfs(i);
            }
        }
        ll ans = inf;
        for (int k = components; k <= n; ++ k) { // inefficient
            setmin(ans, k *(ll) c_lib + (n-k) *(ll) c_road);
        }
        cout << ans << endl;
    }
    return 0;
}
```
