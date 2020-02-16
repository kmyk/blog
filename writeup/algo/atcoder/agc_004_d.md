---
layout: post
redirect_from:
  - /writeup/algo/atcoder/agc-004-d/
  - /blog/2017/10/03/agc-004-d/
date: "2017-10-03T05:33:31+09:00"
tags: [ "competitive", "writeup", "atcoder", "agc", "graph", "tree" ]
"target_url": [ "https://beta.atcoder.jp/contests/agc004/tasks/agc004_d" ]
---

# AtCoder Grand Contest 004: D - Teleporter

## solution

テレポーターの転移先がひとつであることと制約「どの町から出発しても、テレポーターを何回か使うことで首都へ辿り着ける。」により、グラフは首都を根とする有向木のような形になっている。
この木の葉で最も深いものを選んで$K-1$番目の親を首都へ繋ぎ直すことを繰り返すだけでよい。
これを愚直に実装すれば解ける。ただしDFSで整理すればおそらくもっと楽で、計算量は$O(N)$になるだろう。

## implementation

実装方針を間違えたため長くなった。

``` c++
#include <cassert>
#include <cstdio>
#include <functional>
#include <queue>
#include <set>
#include <vector>
#define repeat(i, n) for (int i = 0; (i) < int(n); ++(i))
using namespace std;

int main() {
    // input
    int n, k; scanf("%d%d", &n, &k);
    vector<int> a(n);
    repeat (i, n) {
        scanf("%d", &a[i]);
        -- a[i];
    }

    // solve

    // // make the graphs
    int result = 0;
    if (a[0] != 0) {
        a[0] = 0;  // make the graph a tree
        ++ result;
    }
    vector<set<int> > b(n);  // backward digraph
    repeat (i, n) {
        b[a[i]].insert(i);
    }

    // // define things
    vector<int> valid(n, -1);
    function<void (int, int)> mark_valid = [&](int i, int limit) {
        if (valid[i] >= limit) return;
        valid[i] = limit;
        if (limit) {
            for (int j : b[i]) if (j != i) {
                mark_valid(j, limit - 1);
            }
        }
    };
    vector<int> depth(n, -1); {
        function<void (int)> go = [&](int i) {
            for (int j : b[i]) if (j != i) {
                depth[j] = depth[i] + 1;
                go(j);
            }
        };
        depth[0] = 0;
        go(0);  // connectivity is assumed
    }
    vector<bool> is_leaf(n);
    priority_queue<pair<int, int> > leaves;
    function<void (int)> update_leaf = [&](int i) {
        if (i == 0) return;
        if (not b[i].empty()) return;
        if (is_leaf[i]) return;
        is_leaf[i] = true;
        leaves.emplace(depth[i], i);
    };
    auto relink = [&](int i) {
        if (a[i] == 0) return;
        int a_i = a[i];
        ++ result;
        b[a[i]].erase(i);
        a[i] = 0;
        b[0].insert(i);
        mark_valid(i, k - 1);
        update_leaf(a_i);
    };
    auto k1th_parent = [&](int i) {
        repeat (iteration, k - 1) {
            i = a[i];
            if (i == 0) break;
        }
        return i;
    };

    // // run
    mark_valid(0, k);
    repeat (i, n) {
        update_leaf(i);
    }
    while (not leaves.empty()) {
        int i = leaves.top().second;
        leaves.pop();
        if (valid[i] == -1) {
            int j = k1th_parent(i);
            relink(j);
        }
        assert (valid[i] != -1);
    }

    // output
    printf("%d\n", result);
    return 0;
}
```
