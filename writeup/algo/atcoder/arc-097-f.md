---
layout: post
title: "AtCoder Regular Contest 097: F - Monochrome Cat"
date: 2018-08-21T18:02:47+09:00
tags: [ "competitive", "writeup", "atcoder", "arc", "tree-dp", "tree", "rerooting" ]
"target_url": [ "https://beta.atcoder.jp/contests/arc097/tasks/arc097_d" ]
---

## solution

丁寧に全方位木DPやるだけ。$O(N)$。

始点を頂点$1$と固定した場合の木DPを考えよう。
各部分木について次を持てばよさそう:

-   部分木中の白い頂点の数
-   白い頂点を含む直接の子孫の数
-   その部分木の根から始めてその部分木の中の頂点をすべて黒にするために必要な時間
-   (その部分木の根から始めてその部分木の中の頂点をすべて黒にするとき、根に対する(移動なしの)反転操作をするかどうか)
-   その部分木の根から始めてその部分木の中の頂点をすべて黒にしてかつ根にいるために必要な時間
-   (その部分木の根から始めてその部分木の中の頂点をすべて黒にしてかつ根にいる状態を達成するとき、根に対する(移動なしの)反転操作をするかどうか)

この根に対する反転操作の有無は一意に定まることに注意。
特に、白い頂点を含む子の数の関数になっている。

手間ではあるが演算そのものは単純であるので、max操作に対してtop 2を持つよう変化(典型)させさえすれば、ほぼそのまま(実質的な)逆関数が書ける。
よって$O(N)$で全方位木DPできて解ける。

## note

editorialはもっと頭のいい方法でやってた

## implementation

``` c++
#include <bits/stdc++.h>
#define REP(i, n) for (int i = 0; (i) < (int)(n); ++ (i))
using namespace std;
template <class T> inline void chmin(T & a, T const & b) { a = min(a, b); }

struct state_t {
    int index;
    int white, width;
    int in[2], inout;
    int in_index;
    char in_c, inout_c;
};

void apply_root_c(state_t & a, int dir) {
    REP (k, 2) if (a.in[k] != INT_MAX) {
        a.in[k] += dir * (a.in_c == 'W');
    }
    a.inout += dir * (a.inout_c == 'W');
}

state_t init(int i, char c) {
    state_t a;
    a.index = i;
    a.white = (c == 'W');
    a.width = 0;
    a.in[0] = 0;
    a.in[1] = INT_MAX;
    a.inout = 0;
    a.in_index = -1;
    a.in_c = c;
    a.inout_c = c;
    apply_root_c(a, +1);
    return a;
}

state_t add(state_t a, state_t b) {
    if (b.white == 0) return a;
    a.white += b.white;
    a.width += 1;
    apply_root_c(a, -1);

    // update a.in[i] at first
    a.in[0] += 2 + b.inout + (b.inout_c == 'W' ? -1 : +1);
    if (a.in[1] != INT_MAX) {
        a.in[1] += 2 + b.inout + (b.inout_c == 'W' ? -1 : +1);
    }
    int a_in = a.inout + 1 + b.in[0] + (b.in_c == 'W' ? -1 : +1);
    if (a_in < a.in[0]) {
        a.in[1] = a.in[0];
        a.in[0] = a_in;
        a.in_index = b.index;
    } else if (a_in < a.in[1]) {
        a.in[1] = a_in;
    }
    if (a.width >= 2) a.in_c ^= 'W' ^ 'B';

    // update a.inout
    a.inout += 2 + b.inout + (b.inout_c == 'W' ? -1 : +1);
    a.inout_c ^= 'W' ^ 'B';

    apply_root_c(a, +1);
    return a;
}

state_t remove(state_t a, state_t b) {
    if (b.white == 0) return a;
    apply_root_c(a, -1);

    // invert a.inout
    a.inout -= 2 + b.inout + (b.inout_c == 'W' ? -1 : +1);
    a.inout_c ^= 'W' ^ 'B';

    // invert a.in[i]
    if (a.in_index == b.index) {
        a.in[0] = a.in[1];
        a.in[1] = INT_MAX;
    }
    a.in[0] -= 2 + b.inout + (b.inout_c == 'W' ? -1 : +1);
    if (a.in[1] != INT_MAX) {
        a.in[1] -= 2 + b.inout + (b.inout_c == 'W' ? -1 : +1);
    }
    if (a.width >= 2) a.in_c ^= 'W' ^ 'B';

    apply_root_c(a, +1);
    a.white -= b.white;
    a.width -= 1;
    return a;
}

int solve(int n, vector<vector<int> > const & g, string const & c) {
    vector<state_t> state(n);

    function<void (int, int)> fold = [&](int i, int parent) {
        state[i] = init(i, c[i]);
        for (int j : g[i]) if (j != parent) {
            fold(j, i);
            state[i] = add(state[i], state[j]);
        }
    };

    function<void (int, int)> reroot = [&](int i, int parent) {
        if (parent != -1) {
            state[i] = add(state[i], remove(state[parent], state[i]));
        }
        for (int j : g[i]) if (j != parent) {
            reroot(j, i);
        }
    };

    constexpr int root = 0;
    fold(root, -1);
    reroot(root, -1);
    int acc = INT_MAX;
    REP (i, n) {
        chmin(acc, state[i].in[0]);
    }
    return acc;
}

int main() {
    // input
    int n; cin >> n;
    vector<vector<int> > g(n);
    REP (i, n - 1) {
        int x, y; cin >> x >> y;
        -- x; -- y;
        g[x].push_back(y);
        g[y].push_back(x);
    }
    string c; cin >> c;

    // solve
    int answer = solve(n, g, c);

    // output
    cout << answer << endl;
    return 0;
}
```
