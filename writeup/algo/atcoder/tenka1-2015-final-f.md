---
layout: post
redirect_from:
  - /blog/2015/11/12/tenka1-2015-final-f/
date: 2015-11-12T19:10:46+09:00
tags: [ "competitive", "writeup", "atcoder", "tenka1-programmer-contest", "tree", "lowest-common-ancestor", "euler-tour" ]
---

# 天下一プログラマーコンテスト2015本戦 F - 根付き木のみさわさん

heavy-light decompositionを使う問題と聞いて解き始めたのだけど、euler tour + lcaが想定解法ぽくて、euler tourも書いたことがなかったのでeuler tourで解いた。
euler tour解を思い付けと言われると厳しいが、解法を聞いて書くだけなら苦労しない。

<!-- more -->

## [F - 根付き木のみさわさん](https://beta.atcoder.jp/contests/tenka1-2015-final-open/tasks/tenka1_2015_final_f)

### 問題

頂点数$N$の根付き木($N \le 10^5$)が与えられる。以下のクエリが$Q$個($Q \le 10^5$)与えられるので処理せよ。

$M$個の頂点が指定される。指定された頂点を子孫(それ自身を含む)に$K$個以上含む頂点で、深さが最も深いものの深さを答えよ。($K \le M \le N$)

### 解法

euler tour + lowest common ancestor。
指定された頂点をdfsの通りがけ順に、つまりeuler tourしたときのindexの順に整列する。その列の$i$項目と$i+K-1$項目のlcaとして与えられる頂点で、最も深いものの深さが答え。

指定された頂点から$K$個取りだしてそれら全てのlcaでできる頂点で、最も深いものの深さは答えである。
近い頂点からなる組合せだけを見れば十分であることから、euler tourの順に並べて隣接する$K$項だけ見ればよい。
eular tourの順に並べているので、その端と端のlcaを取ればそれが$K$個の頂点全てのlcaと一致する。

### 実装

``` c++
#include <iostream>
#include <vector>
#include <algorithm>
#include <cassert>
#define repeat_from(i,m,n) for (int i = (m); (i) < (n); ++(i))
#define repeat(i,n) repeat_from(i,0,n)
#define repeat_from_reverse(i,m,n) for (int i = (n)-1; (i) >= (m); --(i))
#define repeat_reverse(i,n) repeat_from_reverse(i,0,n)
using namespace std;
void count_depths(int v, int p, vector<vector<int> > const & g, int d, vector<int> & depth) {
    depth[v] = d;
    for (int w : g[v]) if (w != p) {
        count_depths(w, v, g, d+1, depth);
    }
}
vector<int> count_depths(int p, vector<vector<int> > const & g) {
    vector<int> depth(g.size());
    count_depths(p, -1, g, 0, depth);
    return depth;
}
void make_ancestors(int v, int p, vector<vector<int> > const & g, vector<int> & anc) {
    anc[v] = p;
    for (int w : g[v]) if (w != p) {
        make_ancestors(w, v, g, anc);
    }
}
vector<int> make_ancestors(int p, vector<vector<int> > const & g) {
    vector<int> anc(g.size());
    make_ancestors(p, -1, g, anc);
    return anc;
}
struct lowest_common_ancestor_t {
    int p;
    vector<vector<int> > a;
    vector<int> depth;
    explicit lowest_common_ancestor_t(int a_p, vector<vector<int> > const & g) {
        p = a_p;
        int n = g.size();
        a.resize(1 + floor(log2(n)));
        int l = a.size();
        a[0] = make_ancestors(p, g);
        repeat_from (k,1,l) {
            a[k].resize(n);
            repeat (j,n) {
                if (a[k-1][j] == -1) {
                    a[k][j] = -1;
                } else {
                    a[k][j] = a[k-1][a[k-1][j]];
                }
            }
        }
        depth = count_depths(p, g);
    }
    int get(int v, int w) {
        int l = a.size();
        if (depth[v] != depth[w]) {
            if (depth[v] < depth[w]) swap(v, w);
            assert (depth[v] > depth[w]);
            repeat_reverse (k,l) {
                if (a[k][v] != -1 and depth[a[k][v]] >= depth[w]) {
                    v = a[k][v];
                }
            }
        }
        assert (depth[v] == depth[w]);
        if (v == w) return v;
        repeat_reverse (k,l) {
            if (a[k][v] != a[k][w]) {
                v = a[k][v];
                w = a[k][w];
            }
        }
        assert (v != w);
        assert (a[0][v] == a[0][w]);
        assert (a[0][v] != -1);
        return a[0][v];
    }
};
void make_euler_tour(int v, int p, vector<vector<int> > const & g, int & i, vector<int> & ix) {
    ix[v] = i ++;
    for (int w : g[v]) if (w != p) {
        make_euler_tour(w, v, g, i, ix);
    }
}
vector<int> make_euler_tour(int p, vector<vector<int> > const & g) {
    int i = 0;
    vector<int> ix(g.size());
    make_euler_tour(p, -1, g, i, ix);
    return ix;
}
int main() {
    int n; cin >> n;
    vector<vector<int> > g(n);
    repeat (i,n-1) {
        int a, b; cin >> a >> b;
        -- a; -- b;
        g[a].push_back(b);
        g[b].push_back(a);
    }
    vector<int> euler = make_euler_tour(0, g);
    vector<int> depth = count_depths(0, g);
    lowest_common_ancestor_t lca(0, g);
    int q; cin >> q;
    repeat (query,q) {
        int m, k; cin >> m >> k;
        vector<int> vs(m);
        for (int & v : vs) {
            cin >> v; -- v;
        }
        sort(vs.begin(), vs.end(), [&](int v, int w) -> bool {
            return euler[v] < euler[w];
        });
        int d = 0;
        for (int i = 0; i+k-1 < m; ++ i) {
            d = max(d, depth[lca.get(vs[i], vs[i+k-1])]);
        }
        cout << d << endl;
    }
    return 0;
}
```
