---
layout: post
redirect_from:
  - /writeup/algo/csacademy/72-d/
  - /writeup/algo/cs-academy/72-d/
  - /blog/2018/03/08/csa-72-d/
date: "2018-03-08T12:04:35+09:00"
tags: [ "competitive", "writeup", "csa", "graph", "namori-graph", "cycle" ]
"target_url": [ "https://csacademy.com/contest/round-72/task/sprint-cleaning/" ]
---

# CS Academy Round #72. Spring Cleaning

## solution

入次数$0$の点から貪欲に処理する。
枝のない閉路のみ連結成分が残るのでこれも処理。$O(N)$。

なもりグラフになっているというのは後から言われて気付いた。

## implementation

本番中だったので実装が雑/曖昧。

``` c++
#include <bits/stdc++.h>
#define REP(i, n) for (int i = 0; (i) < int(n); ++ (i))
using namespace std;

int main() {
    // input
    int n; scanf("%d", &n);
    vector<int> g(n);
    REP (i, n) {
        scanf("%d", &g[i]);
        -- g[i];
    }

    // solve
    vector<vector<int> > rev(n);
    REP (i, n) {
        rev[g[i]].push_back(i);
    }
    vector<pair<int, int> > result;
    vector<bool> cleared(n);  // ???
    vector<bool> visited(n);  // ???
    function<void (int)> go = [&](int i) {
        int j = g[i];
        if (not cleared[i] and not visited[j]) {
            visited[i] = true;
            visited[j] = true;
            go(j);
            result.emplace_back(i, j);
            cleared[j] = true;
        }
    };
    REP (i, n) if (rev[i].empty()) {  // for trees which have cycles as their roots
        go(i);
    }
    REP (i, n) if (not cleared[i]) {  // for complete cycles
        go(i);
    }

    // output
    for (auto line : result) {
        int a, b; tie(a, b) = line;
        printf("%d %d\n", a + 1, b + 1);
    }
    return 0;
}
```
