---
layout: post
redirect_from:
  - /blog/2017/12/31/utpc-2012-c/
date: "2017-12-31T17:55:51+09:00"
tags: [ "competitive", "writeup", "utpc", "atcoder", "graph", "complete-graph", "forest" ]
"target_url": [ "https://beta.atcoder.jp/contests/utpc2012/tasks/utpc2012_03" ]
---

# 東京大学プログラミングコンテスト2012: C - 森ですか？

## solution

完全グラフの辺の数は${}\_NC\_2$で森ならば$\le N - 1$。
${}\_NC\_2 - M \gt N - 1$なら全て`no`でよく、そうでなければおおよそ$N \approx \sqrt{M}$としてよいので愚直にやれる。連結性の判定を$O(N \log N)$で$M$回やるとして$O(M^{\frac{3}{2}} \log M)$。

## implementation

``` c++
#include <bits/stdc++.h>
#define REP(i, n) for (int i = 0; (i) < int(n); ++ (i))
using namespace std;

int main() {
    int n, m; scanf("%d%d", &n, &m);
    if (n * (n - 1ll) / 2 - m > n - 1) {
        while (m --) {
            printf("no\n");
        }
    } else {
        vector<set<int> > g(n);
        REP (i, n) REP (j, n) if (i != j) g[i].insert(j);
        int edge_size = n * (n - 1) / 2;
        while (m --) {
            int s, t; scanf("%d%d", &s, &t); -- s; -- t;
            if (g[s].count(t)) {
                g[s].erase(t);
                g[t].erase(s);
                edge_size -= 1;
            } else {
                g[s].insert(t);
                g[t].insert(s);
                edge_size += 1;
            }
            bool result = false;
            if (edge_size <= n - 1) {
                result = true;
                vector<char> used(n);
                function<bool (int, int)> go = [&](int i, int parent) {
                    if (used[i]) return false;
                    used[i] = true;
                    for (int j : g[i]) if (j != parent) {
                        if (not go(j, i)) return false;
                    }
                    return true;
                };
                REP (i, n) if (not used[i]) {
                    if (not go(i, -1)) {
                        result = false;
                        break;
                    }
                }
            }
            printf("%s\n", result ? "yes" : "no");
        }
    }
    return 0;
}
```
