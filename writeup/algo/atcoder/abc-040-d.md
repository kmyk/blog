---
layout: post
alias: "/blog/2016/06/20/abc-040-d/"
date: 2016-06-20T01:45:12+09:00
tags: [ "competitive", "writeup", "abc", "atcoder", "graph", "union-find-tree" ]
"target_url": [ "https://beta.atcoder.jp/contests/abc040/tasks/abc040_d" ]
---

# AtCoder Beginner Contest 040 D - 道路の老朽化対策について

## solution

時間でsortして順に処理。union-find木。$O(Q + M)$.

作られた時間が新しい順に、辺を追加していく。
ある人が到達できる頂点の数は、その人の家からその人の許容できる辺で繋がれた連結成分の大きさの数である。
追加する辺と質問である人を、まとめてそれらの時間でsortして、これをやればよい。

## implementation

本番はIPSCのため見送った。その際`union`って聞こえてきた覚えがあったから(直和構造の意味の)`union`を使ってみたが、よく考えたらunion-find木のことだったのかもしれない。

また、すごく遅くてTLEぎりぎりである。なぜなのか。

``` c++
#include <iostream>
#include <vector>
#include <algorithm>
#define repeat(i,n) for (int i = 0; (i) < (n); ++(i))
#define whole(f,x,...) ([&](decltype((x)) y) { return (f)(begin(y), end(y), ## __VA_ARGS__); })(x)
using namespace std;

struct union_find {
    vector<int> tree;
    explicit union_find(size_t n) : tree(n, -1) {}
    bool is_root(int a) { return tree[a] < 0; }
    int find_root(int a) { return is_root(a) ? a : (tree[a] = find_root(tree[a])); }
    int tree_size(int a) { return - tree[find_root(a)]; }
    void union_tree(int a, int b) {
        a = find_root(a); b = find_root(b);
        if (a != b) {
            if (not (tree_size(a) < tree_size(b))) swap(a,b);
            tree[b] += tree[a];
            tree[a] = b;
        }
    }
    bool is_connected(int a, int b) { return find_root(a) == find_root(b); }
};

const int edge_tag = 0;
const int query_tag = 1;
struct edge_t  { int tag; int y, a, b; };
struct query_t { int tag; int w, i, v; };
union event_t {
    int tag;
    struct { int tag; int time; } common;
    struct edge_t edge;
    struct query_t query;
};
bool operator < (event_t a, event_t b) {
    return make_pair(a.common.time, a.common.tag)
         > make_pair(b.common.time, b.common.tag);
}
int main() {
    // read edges
    int n, m; cin >> n >> m;
    vector<event_t> que(m);
    repeat (i,m) {
        que[i].tag = edge_tag;
        edge_t & e = que[i].edge;
        cin >> e.a >> e.b >> e.y;
        -- e.a; -- e.b;
    }
    // read queries
    int q; cin >> q;
    que.resize(m + q);
    repeat (i,q) {
        que[m+i].tag = query_tag;
        query_t & q = que[m+i].query;
        q.i = i;
        cin >> q.v >> q.w;
        -- q.v;
    }
    // compute
    whole(sort, que);
    vector<int> ans(q);
    union_find t(n);
    for (event_t e : que) {
        if (e.tag == edge_tag) {
            t.union_tree(e.edge.a, e.edge.b);
        } else if (e.tag == query_tag) {
            ans[e.query.i] = t.tree_size(e.query.v);
        }
    }
    // output
    repeat (i,q) cout << ans[i] << endl;
    return 0;
}
```
