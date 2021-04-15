---
redirect_from:
  - /writeup/algo/codeforces/1074-b/
layout: post
date: 2018-11-05T21:05:45+09:00
tags: [ "competitive", "writeup", "codeforces", "reactive", "graph" ]
"target_url": [ "https://codeforces.com/contest/1074/problem/B" ]
---

# Lyft Level 5 Challenge 2018 - Final Round (Open Div. 1): B. Intersecting Subtrees

## 問題概要

$$n$$ 頂点の木 $$T$$ が与えられる。
2通りの方法 $$l_1, l_2 : n \to n$$ で頂点番号が振られており、$$l_2$$ は秘密となっている。
部分木 $$T_1, T_2$$ が定まっており、それぞれ $$l_i$$ で見たときの $$T_i$$ の頂点番号の全体からなる集合が与えられる。
次のクエリを計$$5$$回まで使って、部分木 $$T_1, T_2$$ に共通部分があるか判定し、あるならその頂点をひとつ出力せよ。

-   $$l_1$$ で見たときの番号を $$l_2$$ で見たときの番号に変換する $$A : l_1(i) \mapsto l_2(i)$$
-   $$l_2$$ で見たときの番号を $$l_1$$ で見たときの番号に変換する $$B : l_2(i) \mapsto l_1(i)$$

## 解法

### 概要

「$$5$$回まで」が実質答え。
クエリの回数は$$2$$回で十分。
適当な$$y_i$$に対し$$z = B(y_i)$$とし、$$z$$から最も近い$$x_i$$に対し$$z' = A(x_i)$$を見ればよい。

## 実装

``` c++
#include <bits/stdc++.h>
#define REP(i, n) for (int i = 0; (i) < (int)(n); ++ (i))
#define ALL(x) begin(x), end(x)
using namespace std;

int ask(char c, int i) {
    assert (c == 'A' or c == 'B');
    printf("%c %d\n", c, i + 1);
    fflush(stdout);
    int j; scanf("%d", &j);
    return j - 1;
}

int solve(int n, vector<vector<int> > const & g, int k1, vector<int> const & xs, int k2, vector<int> const & ys) {
    set<int> xs_set(ALL(xs));
    auto get_nearest_point = [&](int y) {
        queue<int> que;
        vector<bool> used(n);
        que.push(y);
        used[y] = true;
        while (not que.empty()) {
            int z = que.front();
            que.pop();
            if (xs_set.count(z)) {
                return z;
            }
            for (int nz : g[z]) if (not used[nz]) {
                que.push(nz);
                used[nz] = true;
            }
        }
        assert (false);
    };

    int y = ys[0];
    int b_y = ask('B', y);
    if (count(ALL(xs), b_y)) return b_y;
    int x = get_nearest_point(b_y);
    int a_x = ask('A', x);
    if (count(ALL(ys), a_x)) return x;
    return -1;
}

int main() {
    int t; scanf("%d", &t);
    while (t --) {
        // input
        int n; scanf("%d", &n);
        vector<vector<int> > g(n);
        REP (i, n - 1) {
            int a, b; scanf("%d%d", &a, &b);
            -- a; -- b;
            g[a].push_back(b);
            g[b].push_back(a);
        }
        int k1; scanf("%d", &k1);
        vector<int> xs(k1);
        REP (i, k1) {
            scanf("%d", &xs[i]);
            -- xs[i];
        }
        int k2; scanf("%d", &k2);
        vector<int> ys(k2);
        REP (j, k2) {
            scanf("%d", &ys[j]);
            -- ys[j];
        }

        // solve
        int answer = solve(n, g, k1, xs, k2, ys);

        // output
        printf("C %d\n", answer == -1 ? -1 : answer + 1);
        fflush(stdout);
    }
    return 0;
}
```
