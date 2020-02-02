---
layout: post
title: "AtCoder Regular Contest 045: D - みんな仲良し高橋君"
date: 2018-10-05T15:01:37+09:00
tags: [ "competitive", "writeup", "atcoder", "arc", "graph", "2d-plane", "two-edge-connected-components", "articulation-point" ]
"target_url": [ "https://beta.atcoder.jp/contests/arc045/tasks/arc045_d" ]
---

## 解法

### 概要

ペアになれる頂点の間に辺を張る。
完全マッチング。
関節点。
$O(N)$。

### 詳細

ペアになれる頂点の間に辺を張りグラフ$G$を作る。
このグラフから$1$点を落としての完全マッチングの存在を見ればそれが答え `OK` / `NG` になる。
単純にやると辺数が爆発するので、行と列に対応する頂点を足し$(2N + 1) \cdot 3$頂点のグラフ$G'$で代用する。
ただし以下$G'$でなく$G$についての形で話す。

完全マッチングは連結成分ごとに見ればよい。
連結成分の頂点数が偶数であることが、完全マッチングの存在に必要十分になっている。
$2n$点のとき完全マッチング$M$があると仮定し、そこに$2$点足して$2n + 2$点を考えよう。
このときグラフ$G$の作り方により、足した$2$点間のpathであって$M$に含まれる辺と含まれない辺を交互に使うものがある。
このpath上の辺の$M$への所属を反転させれば$2n + 2$点での完全マッチングになる。

頂点数が奇数な連結成分がちょうどひとつ存在すると仮定してよい。
この連結成分中の頂点についてのみ考えればよい。
ある頂点を消しても成分が連結なままなら、その頂点は `OK`。
消したとき非連結になるような頂点 (つまり関節点のこと) が問題。
関節点が `OK` か `NG` かは分解後の頂点数の形を見ればよい。
これは二重辺連結成分分解をしその木の上のDPで求まる。
異なる二重辺連結成分を繋ぐ辺は橋であり、関節点なら橋に接続していることを思い出そう。
なおグラフ$G$の作り方により関節点を消した後の連結成分数は常に$2$である。

## 実装

``` c++
#include <functional>
#include <iostream>
#include <vector>
#define REP(i, n) for (int i = 0; (i) < (int)(n); ++ (i))
using namespace std;

/**
 * @brief 2-edge-connected components decomposition
 * @param g an adjacent list of the simple undirected graph
 * @note O(V + E)
 */
pair<int, vector<int> > decompose_to_two_edge_connected_components(vector<vector<int> > const & g) {
    int n = g.size();
    vector<int> imos(n); { // imos[i] == 0  iff  the edge i -> parent is a bridge
        vector<char> used(n); // 0: unused ; 1: exists on stack ; 2: removed from stack
        function<void (int, int)> go = [&](int i, int parent) {
            used[i] = 1;
            for (int j : g[i]) if (j != parent) {
                if (used[j] == 0) {
                    go(j, i);
                    imos[i] += imos[j];
                } else if (used[j] == 1) {
                    imos[i] += 1;
                    imos[j] -= 1;
                }
            }
            used[i] = 2;
        };
        REP (i, n) if (used[i] == 0) {
            go(i, -1);
        }
    }
    int size = 0;
    vector<int> component_of(n, -1); {
        function<void (int)> go = [&](int i) {
            for (int j : g[i]) if (component_of[j] == -1) {
                component_of[j] = imos[j] == 0 ? size ++ : component_of[i];
                go(j);
            }
        };
        REP (i, n) if (component_of[i] == -1) {
            component_of[i] = size ++;
            go(i);
        }
    }
    return { size, move(component_of) };
}

vector<bool> solve(int n, vector<int> const & x, vector<int> const & y) {
    // make the graph with row/col
    int k = 2 * n + 1;
    vector<vector<int> > g(3 * k);
    REP (i, k) {
        int col =     k + x[i] - 1;
        int row = 2 * k + y[i] - 1;
        g[i].push_back(row);
        g[i].push_back(col);
        g[row].push_back(i);
        g[col].push_back(i);
    }

    // find the unique connected component with an odd size
    vector<int> odd_component; {
        vector<bool> used(3 * k);
        vector<int> acc;
        function<void (int)> go = [&](int i) {
            used[i] = true;
            if (i < k) {
                acc.push_back(i);
            }
            for (int j : g[i]) if (not used[j]) {
                go(j);
            }
        };
        REP (i, k) if (not used[i]) {
            acc.clear();
            go(i);
            if (acc.size() % 2 == 1) {
                if (not odd_component.empty()) {
                    return vector<bool>(k);
                }
                odd_component.swap(acc);
            }
        }
        if (odd_component.empty()) {
            return vector<bool>(k);
        }
    }

    // make two-edge connected components
    int component_count; vector<int> component_of;
    tie(component_count, component_of) = decompose_to_two_edge_connected_components(g);
    vector<vector<int> > nodes(component_count);  // the number of given points
    vector<vector<tuple<int, int, int> > > h(component_count);  // the decomposed tree
    {
        vector<bool> used(3 * k);
        function<void (int)> go = [&](int i) {
            used[i] = true;
            if (i < k) {
                nodes[component_of[i]].push_back(i);
            }
            for (int j : g[i]) if (not used[j]) {
                int x = component_of[i];
                int y = component_of[j];
                if (x != y) {
                    h[x].emplace_back(y, i, j);
                    h[y].emplace_back(x, j, i);
                }
                go(j);
            }
        };
        REP (i, 3 * k) if (not used[i]) {
            go(i);
        }
    }

    // make the result
    vector<bool> answer(3 * k); {
        function<int (int, int)> go = [&](int x, int parent) {
            for (int i : nodes[x]) {
                answer[i] = true;
            }
            int cnt = 0;
            for (auto edge : h[x]) {
                int y, i, j; tie(y, i, j) = edge;
                if (y == parent) continue;
                int cnt_y = go(y, x);
                cnt += cnt_y;
                answer[cnt_y % 2 == 0 ? j : i] = false;
            }
            return cnt + nodes[x].size();
        };
        int root = odd_component.front();
        go(component_of[root], -1);
        answer.resize(k);
    }

    return answer;
}

int main() {
    int n; cin >> n;
    vector<int> x(2 * n + 1), y(2 * n + 1);
    REP (i, 2 * n + 1) {
        cin >> x[i] >> y[i];
    }
    auto p = solve(n, x, y);
    for (bool p_i : p) {
        cout << (p_i ? "OK" : "NG") << endl;
    }
    return 0;
}
```
