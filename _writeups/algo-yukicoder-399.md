---
layout: post
redirect_from:
  - /writeup/algo/yukicoder/399/
  - /blog/2016/07/16/yuki-399/
date: "2016-07-16T00:02:29+09:00"
tags: [ "competitive", "writeup", "yukicoder", "segment-tree", "heavy-light-decomposition", "range-add-query", "range-sum-query", "imos-method", "tree" ]
"target_url": [ "http://yukicoder.me/problems/no/399" ]
---

# Yukicoder No.399 動的な領主

[前回](https://kimiyuki.net/blog/2016/07/02/yuki-386/)不必要にも重軽分解してしまっていたのでsegment木部分を貼り直すだけであった。区間add/sumのsegment木が見あたらなかったので実装したらバグらせた。しかしeditorialによると今回もまだ重軽分解は不要だったらしい。

## solution

重軽分解を貼ることができればやるだけなので、writer想定解の木上でのimos法について書く。

道$a,b$へのクエリが走ったときに、頂点$a,b$に$+1$、頂点$\operatorname{lca}(a,b),\operatorname{parent}(\operatorname{lca}(a,b))$に$-1$を乗せる。
木の下から上へimos法をしたとき、これは道上の各点に$+1$することになる。
この処理を各クエリに関して行う。
その後、木の下から上へimos法を行う。各頂点はちょうど$1$回訪問されるようにする。
このとき、その頂点の重み(最終的なその頂点の訪問回数)を$a$とすると、$\frac{a(a+1)}{2}$はその頂点の村から得られる関税の値となっている。
これらを総和すれば答えとなる。

## implementation

``` c++
#include <cstdio>
#include <vector>
#include <map>
#include <functional>
#include <cmath>
#include <cassert>
#define repeat(i,n) for (int i = 0; (i) < (n); ++(i))
#define repeat_reverse(i,n) for (int i = (n)-1; (i) >= 0; --(i))
typedef long long ll;
using namespace std;

struct heavy_light_decomposition_t {
    int n; // |V'|
    vector<int> a; // V ->> V' epic
    vector<vector<int> > path; // V' -> V*, bottom to top order, disjoint union of codomain matchs V
    vector<map<int,int> > pfind; // V' * V -> int, find in path
    vector<int> parent; // V' -> V
    heavy_light_decomposition_t(int v, vector<vector<int> > const & g) {
        n = 0;
        a.resize(g.size());
        dfs(v, -1, g);
    }
    int dfs(int v, int p, vector<vector<int> > const & g) {
        int heavy_node = -1;
        int heavy_size = 0;
        int desc_size = 1;
        for (int w : g[v]) if (w != p) {
            int size = dfs(w, v, g);
            desc_size += size;
            if (heavy_size < size) {
                heavy_node = w;
                heavy_size = size;
            }
        }
        if (heavy_node == -1) {
            a[v] = n;
            n += 1;
            path.emplace_back();
            path.back().push_back(v);
            pfind.emplace_back();
            pfind.back()[v] = 0;
            parent.push_back(p);
        } else {
            int i = a[heavy_node];
            a[v] = i;
            pfind[i][v] = path[i].size();
            path[i].push_back(v);
            parent[i] = p;
        }
        return desc_size;
    }
};

struct lowest_common_ancestor_t {
    vector<vector<int> > a;
    vector<int> depth;
    lowest_common_ancestor_t(int v, vector<vector<int> > const & g) {
        int n = g.size();
        int l = 1 + floor(log2(n));
        a.resize(l);
        repeat (k,l) a[k].resize(n, -1);
        depth.resize(n);
        dfs(v, -1, 0, g, a[0], depth);
        repeat (k,l-1) {
            repeat (i,n) {
                if (a[k][i] != -1) {
                    a[k+1][i] = a[k][a[k][i]];
                }
            }
        }
    }
    static void dfs(int v, int p, int current_depth, vector<vector<int> > const & g, vector<int> & parent, vector<int> & depth) {
        parent[v] = p;
        depth[v] = current_depth;
        for (int w : g[v]) if (w != p) {
            dfs(w, v, current_depth + 1, g, parent, depth);
        }
    }
    // find lca of x, y
    int operator () (int x, int y) const { // O(log N)
        int l = a.size();
        if (depth[x] < depth[y]) swap(x,y);
        repeat_reverse (k,l) {
            if (a[k][x] != -1 and depth[a[k][x]] >= depth[y]) {
                x = a[k][x];
            }
        }
        assert (depth[x] == depth[y]);
        assert (x != -1);
        if (x == y) return x;
        repeat_reverse (k,l) {
            if (a[k][x] != a[k][y]) {
                x = a[k][x];
                y = a[k][y];
            }
        }
        assert (x != y);
        assert (a[0][x] == a[0][y]);
        return a[0][x];
    }
    // find the descendant of x for y
    int descendant (int x, int y) const {
        assert (depth[x] < depth[y]);
        int l = a.size();
        repeat_reverse (k,l) {
            if (a[k][y] != -1 and depth[a[k][y]] >= depth[x]+1) {
                y = a[k][y];
            }
        }
        assert (a[0][y] == x);
        return y;
    }
};

struct segment_tree {
    int n;
    vector<ll> a, b;
    explicit segment_tree(int a_n) {
        n = pow(2,ceil(log2(a_n)));
        a.resize(2*n-1); // fill 0, unit of add
        b.resize(2*n-1); // fill 0, unit of sum
    }
    void range_add(int l, int r, int z) {
        range_add(0, 0, n, l, r, z);
    }
    void range_add(int i, int il, int ir, int l, int r, int z) {
        if (l <= il and ir <= r) {
            a[i] += z;
            b[i] += z * (ir - il);
        } else if (ir <= l or r <= il) {
            // nop
        } else {
            range_add(2*i+1, il, (il+ir)/2, l, r, z);
            range_add(2*i+2, (il+ir)/2, ir, l, r, z);
            b[i] = a[i] * (ir - il) + b[2*i+1] + b[2*i+2];
        }
    }
    ll range_sum(int l, int r) {
        return range_sum(0, 0, n, l, r);
    }
    ll range_sum(int i, int il, int ir, int l, int r) {
        if (l <= il and ir <= r) {
            return b[i];
        } else if (ir <= l or r <= il) {
            return 0; // unit
        } else {
            return a[i] * (min(ir,r) - max(il,l))
                 + range_sum(2*i+1, il, (il+ir)/2, l, r)
                 + range_sum(2*i+2, (il+ir)/2, ir, l, r);
        }
    }
};

ll path_sum(heavy_light_decomposition_t & hl, vector<segment_tree> & sts, int v, int w) {
    ll acc = 0;
    int i = hl.a[v];
    if (hl.a[w] == i) {
        assert (hl.pfind[i][v] <= hl.pfind[i][w]); // v must be a descendant of w
        acc += sts[i].range_sum(hl.pfind[i][v], hl.pfind[i][w]+1);
    } else {
        acc += sts[i].range_sum(hl.pfind[i][v], hl.path[i].size());
        acc += path_sum(hl, sts, hl.parent[i], w);
    }
    return acc;
}

ll path_sum(heavy_light_decomposition_t & hl, lowest_common_ancestor_t & lca, vector<segment_tree> & sts, int x, int y) {
    int z = lca(x, y);
    ll acc = 0;
    if (x != z) acc += path_sum(hl, sts, x, lca.descendant(z, x));
    if (y != z) acc += path_sum(hl, sts, y, lca.descendant(z, y));
    acc += path_sum(hl, sts, z, z);
    return acc;
}

void path_add(heavy_light_decomposition_t & hl, vector<segment_tree> & sts, int v, int w, int delta) {
    int i = hl.a[v];
    if (hl.a[w] == i) {
        assert (hl.pfind[i][v] <= hl.pfind[i][w]); // v must be a descendant of w
        sts[i].range_add(hl.pfind[i][v], hl.pfind[i][w]+1, delta);
    } else {
        sts[i].range_add(hl.pfind[i][v], hl.path[i].size(), delta);
        path_add(hl, sts, hl.parent[i], w, delta);
    }
}

void path_add(heavy_light_decomposition_t & hl, lowest_common_ancestor_t & lca, vector<segment_tree> & sts, int x, int y, int delta) {
    int z = lca(x, y);
    if (x != z) path_add(hl, sts, x, lca.descendant(z, x), delta);
    if (y != z) path_add(hl, sts, y, lca.descendant(z, y), delta);
    path_add(hl, sts, z, z, delta);
}

int main() {
    // input
    int n; scanf("%d", &n);
    vector<vector<int> > g(n);
    repeat (i,n-1) {
        int a, b; scanf("%d%d", &a, &b);
        -- a; -- b;
        g[a].push_back(b);
        g[b].push_back(a);
    }
    // prepare
    const int root = 0;
    heavy_light_decomposition_t hl(root, g);
    vector<segment_tree> sts;
    repeat (i,hl.n) {
        sts.emplace_back(hl.path[i].size());
    }
    repeat (i,n) {
        int l = hl.a[i];
        sts[l].range_add(hl.pfind[l][i], hl.pfind[l][i]+1, 1);
    }
    lowest_common_ancestor_t lca(root, g);
    // run
    ll ans = 0;
    int q; scanf("%d", &q);
    repeat (i,q) {
        int a, b; scanf("%d%d", &a, &b);
        -- a; -- b;
        ans += path_sum(hl, lca, sts, a, b);
        path_add(hl, lca, sts, a, b, 1);
    }
    // output
    printf("%lld\n", ans);
    return 0;
}
```
