---
layout: post
title: "SoundHound Programming Contest 2018 Masters Tournament 本戦: D - Propagating Edges"
date: 2018-08-02T07:41:14+09:00
tags: [ "competitive", "writeup", "atcoder", "graph", "union-find-tree" ]
"target_url": [ "https://beta.atcoder.jp/contests/soundhound2018-summer-final/tasks/soundhound2018_summer_final_d" ]
---

## solution

union-find木をやる。雑にやるとTLEるので多少は丁寧に均す。$O((N + Q) \alpha(N))$ぐらい。

completeクエリは頂点$u$を含む連結成分全体を完全グラフにする。
これは連結成分をひとつの頂点$u$で置き換えるような操作とかなり近い。
ただし完全には同一でないので文字通り潰すのはだめ。
しかしだとするとcompleteクエリが均しでも$O(N)$にまで遅くなるので、それぞれの完全グラフ(つまりunion-find木の根)を頂点とするような荒い無向グラフを貼る必要がある。

## note

completeクエリを以下のように読み替えた場合は解けるのでしょうか。私はこのように誤読し、分からないので解説を見て誤読に気付きました。

>   completeクエリ($type=2, u, v=0$): 全ての頂点対$(a, b)$について以下を行う, $(u, a), (u, b)$ の間にそれぞれ辺があり，かつ $(a, b)$ 間に辺がない場合，  $(a, b)$ の間に辺を貼る。


## implementation

``` c++
#include <bits/stdc++.h>
using namespace std;

struct union_find_tree {
    vector<int> data;
    union_find_tree() = default;
    explicit union_find_tree(size_t n) : data(n, -1) {}
    bool is_root(int i) { return data[i] < 0; }
    int find_root(int i) { return is_root(i) ? i : (data[i] = find_root(data[i])); }
    int tree_size(int i) { return - data[find_root(i)]; }
    int unite_trees(int i, int j) {
        i = find_root(i); j = find_root(j);
        if (i != j) {
            if (tree_size(i) < tree_size(j)) swap(i,j);
            data[i] += data[j];
            data[j] = i;
        }
        return i;
    }
    bool is_same(int i, int j) { return find_root(i) == find_root(j); }
};

int main() {
    int n, q; cin >> n >> q;
    vector<set<int> > g(n);
    vector<set<int> > h(n);
    union_find_tree uft(n);
    while (q --) {
        int type, u, v; cin >> type >> u >> v;
        -- u; -- v;
        if (type == 1) {
            g[u].insert(v);
            g[v].insert(u);
            u = uft.find_root(u);
            v = uft.find_root(v);
            h[u].insert(v);
            h[v].insert(u);
        } else if (type == 2) {
            u = uft.find_root(u);
            function<void (int)> go = [&](int a) {
                uft.unite_trees(u, a);
                for (int b : h[a]) if (not uft.is_same(u, b)) {
                    go(b);
                }
            };
            go(u);
            u = uft.find_root(u);
            h[u].clear();
        } else if (type == 3) {
            bool is_adjacent = uft.is_same(u, v) or g[u].count(v);
            cout << (is_adjacent ? "Yes" : "No") << endl;
        } else {
            assert (false);
        }
    }
    return 0;
}
```
