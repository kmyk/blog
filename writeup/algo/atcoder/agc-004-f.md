---
layout: post
title: "AtCoder Grand Contest 004: F - Namori"
date: 2018-10-24T16:52:58+09:00
tags: [ "competitive", "writeup", "atcoder", "agc", "graph", "namori-graph", "binary-search", "parity", "bipartite-graph" ]
"target_url": [ "https://beta.atcoder.jp/contests/agc004/tasks/agc004_f" ]
---

## 解法

### 概要

木の場合は$2$部グラフを考えて整理し、木DPで$O(N)$。
ナモリグラフの場合は閉路だけに整理する。
閉路が偶数長なら、頂点対を結ぶのに右からか左からかの選択の余地があるため、ある辺の使われる回数を凸性による二分探索して$O(N \log N)$。
閉路が奇数長なら、頂点対の結び方が一意になるので直接に調整して$O(N)$。

### 詳細

まずは木の場合のみ考える。
規則「白白 $\to$ 黒黒」を拡張すれば「白白白白 $\to$ 黒白白黒」「白白白白白白 $\to$ 黒白白白白黒」「白白白白白白白白 $\to$ 黒白白白白白白黒」 $\dots$ も使ってよいことが分かる。
これを元に整理を進めると、$2$部グラフ$(V_1, V_2, E \subseteq V_1 \times V_2)$を考えたくなり、頂点が同数$|V_1| = |V_2|$なら塗れ、そうでなければ塗れないことが分かる。
これは単純な木DPでできる。

次にナモリの場合を考えよう。
まずナモリ閉路だけ取り出そう。
閉路の各点を根とする木は同様の木DPで潰してしまい、閉路の各点には「深さが偶数のまだ使われていない頂点の数」「深さが奇数のまだ使われていない頂点の数」を乗せる。
特にこれはひとつの整数で表現できる。

$2$部グラフかどうかが重要であるため、ナモリ閉路の大きさの偶奇で場合分け。
まず偶数の場合。
最初に余っている頂点の数の必要条件を確認し、だめなら$-1$。
木であれば線形で解けるので、ある辺に注目しその辺が何回使われるかを二分探索してしまえばよい。
表現の仕方によるが、この「使われる回数」は負になりうることに注意。

次に閉路長が奇数の場合。
偶数の場合と同様に辺を切ってしまいたい。
閉路長が奇数であることから、頂点対を選んだときの経路は一意に定まる。
最初に余っている頂点の数の必要条件をよく見れば、各辺の使われる回数は一意に定まる。
ひとつ選んで切って木DPをするか、すべて足し合わせれば答えになる。

## メモ

-   対への操作を$2$部グラフで整理する典型
-   部分点は$1500$点もなくて$700$点ぐらいに見えるし、全体も$1300$点と言われて驚かない
-   $N$頂点$M$辺のグラフは俗にナモリグラフと呼ばれます

## 実装

``` c++
#include <bits/stdc++.h>
#define REP(i, n) for (int i = 0; (i) < (int)(n); ++ (i))
using ll = long long;
using namespace std;

template <typename UnaryPredicate>
int64_t binsearch(int64_t l, int64_t r, UnaryPredicate p) {
    assert (l <= r);
    -- l;
    while (r - l > 1) {
        int64_t m = l + (r - l) / 2;
        (p(m) ? r : l) = m;
    }
    return r;
}

/**
 * @param g a simple connected undirected graph with |E| = |V|
 */
deque<int> get_namori_cycle(vector<vector<int> > const & g) {
    int n = g.size();
    { int m = 0; REP (i, n) m += g[i].size(); assert (m == 2 * n); }  // assume the namori-ty
    deque<int> stk;
    vector<bool> used(n);
    function<void (int, int)> go = [&](int i, int parent) {
        if (used[i]) throw i;
        stk.push_back(i);
        used[i] = true;
        for (int j : g[i]) if (j != parent) {
            go(j, i);
        }
        assert (stk.back() == i);
        stk.pop_back();
        used[i] = false;
    };
    try {
        go(0, -1);
        assert (false);  // fails if the graph is not simple
    } catch (int i) {
        while (stk.front() != i) {
            stk.pop_front();
        }
    }
    return stk;
}

pair<ll, int> solve_tree(int i, vector<vector<int> > const & g, vector<bool> & used) {
    assert (used[i]);
    ll acc = 0;
    int delta = 1;
    for (int j : g[i]) if (not used[j]) {
        used[j] = true;
        auto it = solve_tree(j, g, used);
        acc += it.first;
        acc += abs(it.second);
        delta -= it.second;
    }
    return make_pair(acc, delta);
}

ll solve_path(deque<int> const & xs) {
    ll acc = 0;
    int delta = 0;
    for (int x : xs) {
        acc += abs(delta);
        delta *= -1;
        delta += x;
    }
    assert (not delta);
    return acc;
}

ll solve_cycle(deque<int> xs) {
    int sum_x = 0;
    int sum_abs_x = 0;
    for (int x : xs) {
        sum_x *= -1;
        sum_x += x;
        sum_abs_x += abs(x);
    }
    auto func = [&](int k) {
        xs.front() += k;
        xs.back()  += k;
        ll value = solve_path(xs);
        xs.front() -= k;
        xs.back()  -= k;
        return value;
    };

    if (xs.size() % 2 == 0) {
        if (sum_x) return -1;
        int k = binsearch(- sum_abs_x, sum_abs_x + 1, [&](int k) {
            return func(k + 1) - func(k) >= 0;
        });
        return abs(k) + func(k);

    } else {
        if (sum_x % 2) return -1;
        int k = - sum_x / 2;
        return abs(k) + func(k);
    }
}

ll solve(int n, int m, vector<vector<int> > const & g) {
    vector<bool> used(n);
    if (m == n - 1) {
        constexpr int root = 0;
        used[root] = true;
        auto it = solve_tree(root, g, used);
        if (it.second) return -1;
        return it.first;

    } else if (m == n) {
        deque<int> namori = get_namori_cycle(g);
        for (int i : namori) {
            used[i] = true;
        }
        ll acc = 0;
        deque<int> delta;
        for (int root : namori) {
            auto it = solve_tree(root, g, used);
            acc += it.first;
            delta.push_back(it.second);
        }
        ll acc1 = solve_cycle(delta);
        if (acc1 == -1) return -1;
        return acc + acc1;

    } else {
        assert (false);
    }
}

int main() {
    int n, m; scanf("%d%d", &n, &m);
    vector<vector<int> > g(n);
    REP (i, m) {
        int a, b; scanf("%d%d", &a, &b);
        -- a; -- b;
        g[a].push_back(b);
        g[b].push_back(a);
    }
    ll answer = solve(n, m, g);
    printf("%lld\n", answer);
    return 0;
}
```
