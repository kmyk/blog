---
layout: post
date: 2018-08-18T09:45:33+09:00
tags: [ "competitive", "writeup", "atcoder", "arc", "graph", "bipartite-graph", "clique" ]
"target_url": [ "https://beta.atcoder.jp/contests/arc099/tasks/arc099_c" ]
redirect_from:
  - /writeup/algo/atcoder/arc_099_e/
  - /writeup/algo/atcoder/arc-099-e/
---

# AtCoder Regular Contest 099: E - Independence

## solution

editorialを見て。$O(n^2)$。

## note

クリークは分かる。
補グラフ取ると完全二部グラフだよねというのも分かる。
でもその先が出なかった。
「辺を削除してふたつのクリークにする」あるいは「辺を追加して完全二部グラフにする」といった形の整理ができなかった。
なぜなのか。
補グラフ取る + 辺を追加 という深さ2まで見ないといけないのが難しかったというのは候補のひとつ。
単に調子が悪かっただけな気もするが、この程度の問題が「調子が悪いから解けない」というのは普段あまりにも何も考えず雰囲気で流れで解いているということであるように思う。
そもそもたいした才能はないのだからちゃんと再現性ある技術として解けるようになるべき。

## implementation

``` c++
#include <bits/stdc++.h>
#define REP(i, n) for (int i = 0; (i) < (int)(n); ++ (i))
#define REP_R(i, n) for (int i = int(n) - 1; (i) >= 0; -- (i))
using namespace std;
template <typename X, typename T> auto vectors(X x, T a) { return vector<T>(x, a); }
template <typename X, typename Y, typename Z, typename... Zs> auto vectors(X x, Y y, Z z, Zs... zs) { auto cont = vectors(y, z, zs...); return vector<decltype(cont)>(x, cont); }

int solve(int n, int m, vector<vector<bool> > g) {
    // check whether the complement graph is a bipartite graph or not
    vector<pair<int, int> > bipartite;
    vector<int> used(n);
    function<void (int)> go = [&](int i) {
        (used[i] == 1 ? bipartite.back().first : bipartite.back().second) += 1;
        REP (j, n) if (i != j and not g[i][j]) {
            if (used[j]) {
                if (used[j] != - used[i]) {
                    throw -1;  // not a bipartite graph
                }
            } else {
                used[j] = - used[i];
                go(j);
            }
        }
    };
    REP (i, n) if (not used[i]) {
        bipartite.emplace_back(0, 0);
        used[i] = 1;
        try {
            go(i);
        } catch (int) {
            return -1;
        }
    }

    // knapsack
    vector<bool> cur(n + 1), prv;
    cur[0] = true;
    for (auto it : bipartite) {
        int a, b; tie(a, b) = it;
        cur.swap(prv);
        cur.assign(n + 1, false);
        REP_R (i, n + 1) {
            if (i - a >= 0 and prv[i - a]) cur[i] = true;
            if (i - b >= 0 and prv[i - b]) cur[i] = true;
        }
    }
    int a = n / 2;
    while (not cur[a]) -- a;
    int b = n - a;
    return a * (a - 1) / 2 + b * (b - 1) / 2;
}

int main() {
    int n, m; cin >> n >> m;
    auto g = vectors(n, n, bool());
    REP (i, m) {
        int a, b; cin >> a >> b;
        -- a; -- b;
        g[a][b] = true;
        g[b][a] = true;
    }
    cout << solve(n, m, g) << endl;
    return 0;
}
```
