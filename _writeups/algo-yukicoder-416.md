---
layout: post
redirect_from:
  - /writeup/algo/yukicoder/416/
  - /blog/2016/08/26/yuki-416/
date: "2016-08-26T23:45:06+09:00"
tags: [ "competitive", "writeup", "yukicoder", "graph", "union-find-tree" ]
"target_url": [ "http://yukicoder.me/problems/no/416" ]
---

# Yukicoder No.416 旅行会社

## solution

逆から辺を復元していけばよい。union-find木で結合していって、初めて根と繋がった時点が初めて根から切断された時刻。
ただし、各成分中の頂点番号も記憶しておく必要があるため、データ構造をマージする一般的なテクを使って計算しておく。
$O(N \log N + M + Q \alpha(N))$。

## implementation

union find木に一般的な付加情報という形で成分の要素を載せた。
成分の要素の逆引きに特化させてもよかったかもしれない。

``` c++
#include <iostream>
#include <vector>
#include <set>
#include <functional>
#include <cassert>
#define repeat(i,n) for (int i = 0; (i) < (n); ++(i))
#define repeat_from(i,m,n) for (int i = (m); (i) < (n); ++(i))
#define repeat_reverse(i,n) for (int i = (n)-1; (i) >= 0; --(i))
using namespace std;

template <typename T>
struct disjoint_sets { // with data
    vector<int> xs;
    vector<T> data;
    function<void (T &, T &)> append;
    template <typename F>
    disjoint_sets(size_t n, T initial, F a_append) : xs(n, -1), data(n, initial), append(a_append) {}
    bool is_root(int i) { return xs[i] < 0; }
    int find_root(int i) { return is_root(i) ? i : (xs[i] = find_root(xs[i])); }
    int set_size(int i) { return - xs[find_root(i)]; }
    int union_sets(int i, int j) {
        i = find_root(i); j = find_root(j);
        if (i != j) {
            if (set_size(i) < set_size(j)) swap(i,j);
            xs[i] += xs[j];
            xs[j] = i;
            append(data[i], data[j]);
        }
        return i;
    }
    bool is_same(int i, int j) { return find_root(i) == find_root(j); }
};

int main() {
    // input
    int n, m, q; cin >> n >> m >> q;
    vector<int> a(m), b(m);
    repeat (j,m) {
        cin >> a[j] >> b[j];
        -- a[j]; -- b[j];
    }
    vector<int> c(q), d(q);
    repeat (j,q) {
        cin >> c[j] >> d[j];
        -- c[j]; -- d[j];
    }
    // compute
    disjoint_sets<set<int> > g(n, set<int>(), [&](set<int> & a, set<int> & b) {
        a.insert(b.begin(), b.end());
        b = set<int>(); // free
    });
    repeat (i,n) {
        g.data[i].insert(i);
    }
    set<pair<int,int> > breaking;
    repeat (j,q) {
        breaking.emplace(c[j], d[j]);
    }
    repeat (j,m) {
        if (breaking.count(make_pair(a[j], b[j]))) continue;
        g.union_sets(a[j], b[j]);
    }
    const int root = 0;
    vector<int> ans(n);
    repeat (i,n) {
        if (g.is_same(root, i)) {
            ans[i] = -1;
        }
    }
    repeat_reverse (j,q) {
        if (g.is_same(c[j], d[j])) continue;
        set<int> connected;
        if (g.is_same(root, c[j])) connected.swap(g.data[g.find_root(d[j])]);
        if (g.is_same(root, d[j])) connected.swap(g.data[g.find_root(c[j])]);
        g.union_sets(c[j], d[j]);
        for (int i : connected) {
            assert (ans[i] == 0);
            ans[i] = j+1;
        }
    }
    // output
    assert (ans[root] == -1);
    repeat_from (i,1,n) {
        cout << ans[i] << endl;
    }
    return 0;
}
```
