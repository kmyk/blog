---
layout: post
redirect_from:
  - /writeup/algo/topcoder/srm-692-easy/
  - /blog/2016/06/10/srm-692-easy/
date: 2016-06-10T11:43:27+09:00
tags: [ "competitive", "writeup", "topcoder", "srm", "graph" ]
---

# TopCoder SRM 692 Div1 Easy: HardProof

I tried to use my SCC library, but it causes TLE.

## problem

重み付き有向グラフで、任意の異なる頂点間のそれぞれの方向に辺がちょうど$1$本あるものが与えられる。つまり$\|E\| = {\|V\|}^2$となっている。
このグラフから適当に辺を選んで$\|V\|$個の頂点全体が強連結になるようにするとき、選んだ辺の重みの最大値と最小値の差の最小値を答えよ。

$\operatorname{ans} = \min \\{ \max X - \min X \mid X \subseteq E, X \operatorname{strongly connects} V \\}$.

## solution

For each edge $e$, assume the edge $e$ is the lowest-weight one, and find the minimum cost $k$ to connect $V$ strongly.
Add edges greedily like Dijkstra, and check the connectivity using DFS with memoization.
This seems $O(N^5)$.

You must take care about the case $N = 1$.

## implementation

``` c++
#include <bits/stdc++.h>
#include <functional>
#include <tuple>
#define repeat(i,n) for (int i = 0; (i) < (n); ++(i))
using namespace std;
template <class T> bool setmax(T & l, T const & r) { if (not (l < r)) return false; l = r; return true; }
template <class T> bool setmin(T & l, T const & r) { if (not (r < l)) return false; l = r; return true; }
class HardProof { public: int minimumCost(vector<int> D); };

const int inf = 1e9+7;
int HardProof::minimumCost(vector<int> D) {
    int n = sqrt(D.size());
    if (n == 1) return 0;
    auto cost = [&](int x, int y) { return D[x * n + y]; };
    int ans = inf;
    repeat (fst,n) {
        repeat (snd,n) if (fst != snd) {
            vector<bool> used(n);
            int used_count = 0;
            vector<vector<int> > g(n);
            vector<bool> connected(n);
            connected[fst] = true;
            int connected_count = 1;
            function<bool (int, vector<bool> &)> connect = [&](int x, vector<bool> & visited) {
                if (connected[x]) return true;
                visited[x] = true;
                for (int y : g[x]) if (not visited[y]) {
                    if (connect(y, visited)) {
                        connected[x] = true;
                        connected_count += 1;
                        return true;
                    }
                }
                return false;
            };
            int non_connected_iter = 0;
            priority_queue<tuple<int,int,int> > que; // (- cost, u, v)
            que.emplace(- (-1), fst, fst);
            que.emplace(- (-1), snd, snd);
            int max_cost = -1;
            while (not que.empty()) {
                int cur_cost, x, y; tie(cur_cost, x, y) = que.top(); que.pop(); cur_cost *= -1;
                setmax(max_cost, cur_cost);
                if (x != y) {
                    g[x].push_back(y);
                }
                if (not used[y]) {
                    used[y] = true;
                    used_count += 1;
                    repeat (z,n) if (z != y and cost(fst, snd) <= cost(y, z)) {
                        que.emplace(- cost(y, z), y, z);
                    }
                }
                if (used_count == n) {
                    while (non_connected_iter < n) {
                        vector<bool> visited(n);
                        if (connect(non_connected_iter, visited)) {
                            non_connected_iter += 1;;
                        } else {
                            break;
                        }
                    }
                }
                if (connected_count == n) {
                    break;
                }
            }
            if (connected_count == n) {
                setmin(ans, max_cost - cost(fst, snd));
            }
        }
    }
    return ans;
}
```
