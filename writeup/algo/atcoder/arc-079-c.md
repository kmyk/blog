---
layout: post
alias: "/blog/2017/07/29/arc-079-c/"
date: "2017-07-29T23:07:07+09:00"
title: "AtCoder Regular Contest 079: C - Cat Snuke and a Voyage"
tags: [ "competitive", "writeup", "atcoder", "arc", "graph" ]
"target_url": [ "https://beta.atcoder.jp/contests/arc079/tasks/arc079_a" ]
---

## solution

最短距離が$2$か判定すればよい。つまり島$1, N$の両方に隣接する島の存在を調べればよい。$O(N + M)$。

## implementation

``` c++
#include <cstdio>
#include <set>
#include <vector>
#define repeat(i, n) for (int i = 0; (i) < int(n); ++(i))
using namespace std;

int main() {
    int n, m; scanf("%d%d", &n, &m);
    vector<set<int> > g(n);
    repeat (i, m) {
        int a, b; scanf("%d%d", &a, &b); -- a; -- b;
        g[a].insert(b);
        g[b].insert(a);
    }
    bool result = false;
    for (int k : g[0]) {
        if (g[k].count(n - 1)) {
            result = true;
            break;
        }
    }
    printf("%s\n", result ? "POSSIBLE" : "IMPOSSIBLE");
    return 0;
}
```
