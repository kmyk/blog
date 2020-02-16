---
layout: post
redirect_from:
  - /blog/2015/12/20/arc-009-d/
date: 2015-12-20T00:15:33+09:00
tags: [ "competitive", "writeup", "atcoder", "arc", "spanning-tree", "dp", "combinatorics", "overflow" ]
---

# AtCoder Regular Contest 009 D - 覚醒ノ高橋君

解法はそう難しくないが、実装が少し多めで、丁寧さが必要。
問題文は難しい。

<!-- more -->

## [D - 覚醒ノ高橋君](https://beta.atcoder.jp/contests/arc009/tasks/arc009_4) {#d}

### 問題

重み付き単純グラフを木のように連結してできるグラフが与えられる。
具体的には以下のようにしてできるグラフである。
複数の単純グラフを用意し、そのグラフを頂点とする木を作る。
ふたつの単純グラフで木の辺で繋がれたものに関して、それぞれから頂点をひとつずつ選んできて、その頂点を同じ頂点としてひとつのグラフにまとめる。
元となる単純グラフは$A$個($A \le 77$)であり、それぞれの頂点数は高々$7$、重みは高々$77$である。

さらに整数$k \le 7777777$が与えられる。与えられた単純グラフの全域木で、その全域木を作るために削除する辺の重みの総和が$k$番目に小さいものの、その削除した辺の重みの総和を求めよ。

### 解法

元となる単純グラフのそれぞれに関して全域木を作れば、全体としても全域木となるので、分割して考えることができる。それぞれに関して全ての全域木を列挙し、それぞれの重みでできる全域木の数を数える。

すると、整数の列が$A$個あって、それぞれからひとつずつ選んできて足し合わせてできる整数で、$k$番目に小さいものを求める、という問題に帰着する。
これは、足し合わせてできる数が小さいことから、dpで計算することができる。
ただし、同じ数を生む組み合わせの数はかなり大きくなる。overflowに注意。

### 実装

長い。

``` c++
#include <iostream>
#include <vector>
#include <algorithm>
#include <map>
#include <queue>
#define repeat(i,n) for (int i = 0; (i) < (n); ++(i))
typedef long long ll;
using namespace std;
struct edge_t {
    int from, to, cost;
};
// modified prim's algorithm
void spaning_tree_costs(int cost, queue<edge_t> que, vector<bool> & used, int used_sum, map<int,int> const & ix, vector<vector<edge_t> > const & g, map<int,int> & result) {
    if (used_sum == ix.size() - 1) {
        result[cost] += 1;
        return;
    }
    if (que.empty()) {
        return;
    } else {
        edge_t e = que.front(); que.pop();
        spaning_tree_costs(cost, que, used, used_sum, ix, g, result);
        int v = ix.at(e.to);
        if (not used[v]) {
            used[v] = true;
            for (edge_t f : g[e.to]) if (ix.count(f.to)) {
                int w = ix.at(f.to);
                if (not used[w]) {
                    que.push(f);
                }
            }
            spaning_tree_costs(cost - e.cost, que, used, used_sum + 1, ix, g, result);
            used[v] = false;
        }
    }
}
map<int,int> spaning_tree_costs(vector<int> const & vs, vector<vector<edge_t> > const & g) {
    map<int,int> ix;
    for (int v : vs) {
        int i = ix.size(); // required
        ix[v] = i;
    }
    int cost = 0;
    for (int v : vs) {
        for (edge_t e : g[v]) if (ix.count(e.to) and e.from < e.to) {
            cost += e.cost;
        }
    }
    queue<edge_t> que;
    for (edge_t e : g[vs[0]]) if (ix.count(e.to)) {
        que.push(e);
    }
    vector<bool> used(ix.size());
    used[ix[vs[0]]] = true;
    map<int,int> result;
    spaning_tree_costs(cost, que, used, 0, ix, g, result);
    return result;
}
int kth_combination(vector<map<int,int> > const & ts, int k) {
    int lim = 2; // +1 to include \Sigma \max t, +1 to distinguish overflow or not
    for (auto t : ts) lim += t.rbegin()->first;
    vector<ll> cur(lim); // dp[cost] = number
    vector<ll> prv(lim);
    cur[0] = 1;
    int l = lim;
    for (auto t : ts) {
        cur.swap(prv);
        fill(cur.begin(), cur.end(), 0);
        for (auto it : t) {
            repeat (j,lim) {
                if (j + it.first >= lim) break;
                cur[j + it.first] += prv[j] * it.second;
            }
        }
        l = min(lim, l + t.begin()->first);
        repeat (j,l) {
            if (cur[j] > k) {
                l = min(l, j);
                break;
            }
        }
    }
    repeat (i,lim-1) {
        if (i == l) return i; // overflow
        k -= cur[i];
        if (k <= 0) return i;
    }
    return -1;
}
int main() {
    // input
    int a, t, k; cin >> a >> t >> k;
    vector<vector<int> > c(a);
    repeat (i,a) {
        int n; cin >> n;
        c[i].resize(n);
        repeat (j,n) {
            cin >> c[i][j];
            -- c[i][j];
        }
    }
    vector<vector<edge_t> > g(t);
    int m; cin >> m;
    repeat (i,m) {
        int v, w, cost;
        cin >> v >> w >> cost;
        -- v; -- w;
        g[v].push_back((edge_t){ v, w, cost });
        g[w].push_back((edge_t){ w, v, cost });
    }
    // spaning tree
    vector<map<int,int> > ts(a);
    repeat (i,a) ts[i] = spaning_tree_costs(c[i], g);
    // combinatorics
    cout << kth_combination(ts, k) << endl;
    return 0;
}
```
