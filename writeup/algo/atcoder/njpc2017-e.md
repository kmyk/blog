---
redirect_from:
layout: post
date: 2018-08-02T08:01:03+09:00
tags: [ "competitive", "writeup", "atcoder", "njpc", "rerooting", "tree-dp", "graph" ]
"target_url": [ "https://beta.atcoder.jp/contests/njpc2017/tasks/njpc2017_e" ]
---

# NJPC2017: E - 限界集落

<!-- {% raw %} -->

## solution

全方位木DPを$2$回やるだけ。ある頂点を根にしたときの根付き木の高さと辺の反転回数をそれぞれ独立に求めてやればよい。$O(N)$。

editorialでは木の直径を使ってもう少しad-hocにやってた。

## implementation

``` c++
#include <bits/stdc++.h>
#define REP(i, n) for (int i = 0; (i) < (int)(n); ++ (i))
using ll = long long;
using namespace std;
template <class T> inline void chmin(T & a, T const & b) { a = min(a, b); }

template <typename TreeOperation>
vector<typename TreeOperation::type> fold_rooted_tree(vector<vector<tuple<int, ll, bool> > > const & g, int root, TreeOperation op = TreeOperation()) {
    int n = g.size();
    vector<typename TreeOperation::type> data(n);
    stack<tuple<bool, int, int> > stk;
    stk.emplace(false, root, -1);
    while (not stk.empty()) {
        bool state; int x, parent; tie(state, x, parent) = stk.top(); stk.pop();
        if (not state) {
            stk.emplace(true, x, parent);
            for (auto edge : g[x]) {
                int y = get<0>(edge);
                if (y != parent) {
                    stk.emplace(false, y, x);
                }
            }
        } else {
            vector<tuple<int, ll, bool, typename TreeOperation::type> > args;
            for (auto edge : g[x]) {
                int y; ll dist; bool is_reversed; tie(y, dist, is_reversed) = edge;
                if (y != parent) {
                    args.emplace_back(y, dist, is_reversed, data[y]);
                }
            }
            data[x] = op(x, args);
        }
    };
    return data;
}

template <typename TreeOperation>
vector<typename TreeOperation::type> reroot_folded_rooted_tree(vector<typename TreeOperation::type> data, vector<vector<tuple<int, ll, bool> > > const & g, int root, TreeOperation op = TreeOperation()) {
    stack<tuple<int, int, ll, bool> > stk;
    stk.emplace(root, -1, LLONG_MIN, false);
    while (not stk.empty()) {
        int x, parent; ll dist; bool is_reversed; tie(x, parent, dist, is_reversed) = stk.top(); stk.pop();
        if (parent != -1) {
            auto subtracted = op.subtract(parent, data[parent], x, data[x], dist, is_reversed);
            data[x] = op.add(x, data[x], parent, subtracted, dist, not is_reversed);
        }
        for (auto edge : g[x]) {
            int y; tie(y, dist, is_reversed) = edge;
            if (y != parent) {
                stk.emplace(y, x, dist, is_reversed);
            }
        }
    }
    return data;
}

struct tree_operation {
    typedef tuple<ll, ll, int> type;
    type operator () (int i, vector<tuple<int, ll, bool, type> > const & args) {
        type y = make_tuple(0, LLONG_MIN, 0);
        for (auto arg : args) {
            int j; ll dist; bool is_reversed; type x; tie(j, dist, is_reversed, x) = arg;
            y = add(i, y, j, x, dist, is_reversed);
        }
        return y;
    }
    type add(int i, type data_i, int j, type data_j, ll dist, bool is_reversed) {
        array<ll, 3> height = {{ get<0>(data_i), get<1>(data_i), get<0>(data_j) + dist }};
        sort(height.rbegin(), height.rend());
        int reversed = get<2>(data_i) + get<2>(data_j) + not is_reversed;
        return make_tuple(height[0], height[1], reversed);
    }
    type subtract(int i, type data_i, int j, type data_j, ll dist, bool is_reversed) {
        ll fst = get<0>(data_i);
        ll snd = get<1>(data_i);
        if (fst == get<0>(data_j) + dist) {
            fst = snd;
            snd = LLONG_MIN;  // NOTE: this is OK
        }
        int reversed = get<2>(data_i) - get<2>(data_j) - not is_reversed;
        return make_tuple(fst, snd, reversed);
    }
};

int main() {
    // input
    int n; ll d; cin >> n >> d;
    vector<vector<tuple<int, ll, bool> > > g(n);
    REP (i, n - 1) {
        int a, b; ll c; cin >> a >> b >> c;
        -- a; -- b;
        g[a].emplace_back(b, c, false);
        g[b].emplace_back(a, c, true);
    }

    // solve
    constexpr int root = 0;
    auto dp1 = fold_rooted_tree<tree_operation>(g, root);
    auto dp2 = reroot_folded_rooted_tree<tree_operation>(dp1, g, root);
    int answer = INT_MAX;
    REP (i, n) {
        ll dist; int cnt; tie(dist, ignore, cnt) = dp2[i];
        if (dist <= d) {
            chmin(answer, cnt);
        }
    }

    // output
    cout << (answer == INT_MAX ? -1 : answer) << endl;
    return 0;
}
```

<!-- {% endraw %} -->
