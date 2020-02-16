---
layout: post
alias: "/blog/2018/04/06/arc-065-b/"
date: "2018-04-06T19:51:00+09:00"
tags: [ "competitive", "writeup", "arc", "union-find-tree" ]
"target_url": [ "https://arc065.contest.atcoder.jp/tasks/arc065_b" ]
---

# AtCoder Regular Contest 065: D - 連結 / Connectivity

## solution

まず道路/鉄道のそれぞれで連結性を判定し、両方で同じ連結成分に含まれるものの数を数える。
$O(N + (K + L) \alpha(N))$。

## implementation

``` c++
#include <bits/stdc++.h>
#define REP(i, n) for (int i = 0; (i) < int(n); ++ (i))
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
    int n, k, l; cin >> n >> k >> l;
    union_find_tree uft1(n);
    REP (i, k) {
        int p, q; cin >> p >> q; -- p; -- q;
        uft1.unite_trees(p, q);
    }
    union_find_tree uft2(n);
    REP (i, l) {
        int r, s; cin >> r >> s; -- r; -- s;
        uft2.unite_trees(r, s);
    }
    map<pair<int, int>, int> cnt;
    REP (i, n) {
        cnt[make_pair(uft1.find_root(i), uft2.find_root(i))] += 1;
    }
    REP (i, n) {
        cout << cnt[make_pair(uft1.find_root(i), uft2.find_root(i))] << ' ';
    }
    cout << endl;
    return 0;
}
```
