---
layout: post
redirect_from:
  - /writeup/algo/atcoder/arc_048_d/
  - /writeup/algo/atcoder/arc-048-d/
  - /blog/2016/05/18/arc-048-d/
date: 2016-05-18T01:19:19+09:00
tags: [ "competitive", "writeup", "atcoder", "arc", "heavy-light-decomposition", "lowest-common-ancestor", "segment-tree" ]
"target_url": [ "https://beta.atcoder.jp/contests/arc048/tasks/arc048_d" ]
---

# AtCoder Regular Contest 048 D - たこ焼き屋とQ人の高橋君

自力で解けたので気持ちよかった。
重軽分解や最小共通祖先等は全て貼っただけなので、実装もあまりつらくはなかった。

頂点間の距離を深さを用いて分解し、変数間の依存関係をほぐすのは便利っぽい。

## solution

heavy light decompositionで列のminに落とす。$O(N \log N + Q\log N)$ぐらい。

木の頂点$2$つが与えられて、その間の移動時間を答える。
最短距離となる唯一の道を移動するのではなくて、たこやき屋に向かって一度だけより道してから向かう場合がある。
しかし木であるので、頂点$x$で道から逸れた場合、必ず頂点$x$で道に復帰しなければならない。
図にすると以下のようになる。$x = s, t$の場合はあるが、$x$は必ずこの道$P\_{s,t}$上にある。

```
(start)        (goal)
   s ---> x ---> t
          |
          y (takoyaki)
```

図のようにより道した場合、所用時間は$2d\_{s,x} + 3l\_{x,y} + d\_{x,t}$である。$d\_{v,w}$は頂点$v,w$間の距離である。
$a_x$を、頂点$x$から最も近いたこやき屋への距離とする。
$x$は道$P\_{s,t}$上の頂点であるので、求めたい答えは $\rm{ans} = \min \\{ 2d\_{s,x} + 3a_x + d\_{x,t} \mid x \in P\_{s,t} \\}$ となる。

これを、もう少し計算しやすい形に直そう。
$e_x$を、頂点$x$の深さとする。すると、$d\_{x,y} = \|e_x - e_y\|$が成り立つ。
ここで$s,t$の位置関係で場合分けをする。
例えば$s$は$t$の子孫であるとすると、 $2d\_{s,x} + 3a_x + d\_{x,t} = 2(e_s - e_x) + 3a_x + (e_x - e_t) = (2e_s - e_t) + (3a_x - e_x)$ となる。
$2e_s - e_t$は頂点$x$に依存しない定数であり、$3a_x - e_x$は頂点$x$のみに依存する値である。
よって $\rm{ans} = (2e_s - e_t) + \min \\{ 3a_x - e_x \mid x \in P\_{s,t} \\}$ となる。
これは、木の道に関する単純な最小値queryである。

木の道に関するqueryは、heavy light decompositionにより列に関するqueryに変換できることが知られている。
単純なsegment木を用いて、minを対数時間で計算可能である。

$s$が$t$の子孫な場合以外も、同様の簡単な式変形により答えが求められる。

## implementation

``` c++
#include <iostream>
#include <vector>
#include <cmath>
#include <map>
#include <functional>
#include <cassert>
#define repeat(i,n) for (int i = 0; (i) < (n); ++(i))
#define repeat_reverse(i,n) for (int i = (n)-1; (i) >= 0; --(i))
typedef long long ll;
template <class T> bool setmin(T & l, T const & r) { if (not (r < l)) return false; l = r; return true; }
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
    int operator () (int x, int y) const {
        int l = a.size();
        if (depth[x] < depth[y]) swap(x,y);
        repeat_reverse (k,l) {
            if (a[k][x] != -1 and depth[a[k][x]] >= depth[y]) {
                x = a[k][x];
            }
        }
        assert (depth[x] == depth[y]);
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
};

template <typename T>
struct segment_tree { // on monoid
    int n;
    vector<T> a;
    function<T (T,T)> append; // associative
    T unit;
    template <typename F>
    segment_tree(int a_n, T a_unit, F a_append) {
        n = pow(2,ceil(log2(a_n)));
        a.resize(2*n-1, a_unit);
        unit = a_unit;
        append = a_append;
    }
    void point_update(int i, T z) {
        a[i+n-1] = z;
        for (i = (i+n)/2; i > 0; i /= 2) {
            a[i-1] = append(a[2*i-1], a[2*i]);
        }
    }
    T range_concat(int l, int r) {
        return range_concat(0, 0, n, l, r);
    }
    T range_concat(int i, int il, int ir, int l, int r) {
        if (l <= il and ir <= r) {
            return a[i];
        } else if (ir <= l or r <= il) {
            return unit;
        } else {
            return append(
                    range_concat(2*i+1, il, (il+ir)/2, l, r),
                    range_concat(2*i+2, (il+ir)/2, ir, l, r));
        }
    }
};

template <typename T>
T path_concat(heavy_light_decomposition_t & hl, vector<segment_tree<T> > & sts, int v, int w) {
    auto append = sts.front().append;
    auto unit   = sts.front().unit;
    T acc = unit;
    int i = hl.a[v];
    if (hl.a[w] == i) {
        assert (hl.pfind[i][v] <= hl.pfind[i][w]); // v must be a descendant of w
        acc = append(acc, sts[i].range_concat(hl.pfind[i][v], hl.pfind[i][w]+1));
    } else {
        acc = append(acc, sts[i].range_concat(hl.pfind[i][v], hl.path[i].size()));
        acc = append(acc, path_concat(hl, sts, hl.parent[i], w));
    }
    return acc;
}

const int inf = 1e9+7;
int main() {
    // input
    int n, query; cin >> n >> query;
    vector<vector<int> > g(n);
    repeat (i,n-1) {
        int a, b; cin >> a >> b; -- a; -- b;
        g[a].push_back(b);
        g[b].push_back(a);
    }
    vector<bool> has_takoyaki(n);
    repeat (i,n) {
        char c; cin >> c;
        has_takoyaki[i] = c == '1';
    }
    // prepare
    const int root = 0;
    vector<int> parent(n, -1);
    vector<vector<int> > children(n); {
        function<void (int)> dfs = [&](int i) {
            for (int j : g[i]) if (j != parent[i]) {
                children[i].push_back(j);
                parent[j] = i;
                dfs(j);
            }
        };
        dfs(root);
    }
    vector<int> depth(n); {
        function<void (int, int)> dfs = [&](int i, int d) {
            depth[i] = d;
            for (int j : children[i]) dfs(j, d+1);
        };
        dfs(root, 0);
    }
    vector<int> nearest_takoyaki(n); {
        vector<int> descendent_nearest_takoyaki(n); {
            function<int (int)> dfs = [&](int i) {
                int acc = has_takoyaki[i] ? 0 : inf;
                for (int j : children[i]) setmin(acc, dfs(j) + 1);
                return descendent_nearest_takoyaki[i] = acc;
            };
            dfs(root);
        }
        function<void (int)> dfs = [&](int i) {
            if (parent[i] == -1) {
                assert (i == root);
                nearest_takoyaki[root] = descendent_nearest_takoyaki[root];
            } else {
                nearest_takoyaki[i] = min(descendent_nearest_takoyaki[i], nearest_takoyaki[parent[i]] + 1);
            }
            for (int j : children[i]) dfs(j);
        };
        dfs(root);
    }
    // calculate
    heavy_light_decomposition_t hl(root, g);
    vector<segment_tree<ll> > sts_up;
    vector<segment_tree<ll> > sts_down; {
        repeat (i,hl.n) {
            sts_up  .emplace_back(hl.path[i].size(), inf, [](ll a, ll b) { return min(a, b); });
            sts_down.emplace_back(hl.path[i].size(), inf, [](ll a, ll b) { return min(a, b); });
        }
        repeat (i,n) {
            ll weight_up   = 3ll * nearest_takoyaki[i] - depth[i];
            ll weight_down = 3ll * nearest_takoyaki[i] + depth[i];
            int l = hl.a[i];
            sts_up  [l].point_update(hl.pfind[l][i], weight_up  );
            sts_down[l].point_update(hl.pfind[l][i], weight_down);
        }
    }
    lowest_common_ancestor_t lca(root, g);
    auto solve = [&](int start, int goal) {
        int middle = lca(start, goal);
        ll ans = inf;
        setmin<ll>(ans, 2 * (depth[start] + depth[goal] - 2 * depth[middle])); // no takoyaki
        if (middle == start) {
            ll k = depth[goal] - 2 * depth[start];
            ll x = path_concat(hl, sts_down, goal, start);
            setmin(ans, k + x);
        } else if (middle == goal) {
            ll k = 2 * depth[start] - depth[goal];
            ll x = path_concat(hl, sts_up, start, goal);
            setmin(ans, k + x);
        } else {
            // takoyaki in up
            ll ku = 2 * depth[start] + depth[goal] - 2 * depth[middle];
            ll xu = path_concat(hl, sts_up, start, middle);
            setmin(ans, ku + xu);
            // takoyaki in down
            ll kd = 2 * depth[start] + depth[goal] - 4 * depth[middle];
            ll xd = path_concat(hl, sts_down, goal, middle);
            setmin(ans, kd + xd);
        }
        return ans;
    };
    // output
    while (query --) {
        int s, t; cin >> s >> t; -- s; -- t;
        cout << solve(s, t) << endl;
    }
    return 0;
}
```
