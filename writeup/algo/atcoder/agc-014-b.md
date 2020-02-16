---
layout: post
alias: "/blog/2017/05/07/agc-014-b/"
date: "2017-05-07T21:10:42+09:00"
tags: [ "competitive", "writeup", "atcoder", "agc", "eulerian-graph", "tree" ]
"target_url": [ "https://beta.atcoder.jp/contests/agc014/tasks/agc014_b" ]
---

# AtCoder Grand Contest 014: B - Unplanned Queries

未証明で投げてみたら通った。

## implementation

クエリ$(a\_i, b\_i)$ごとに直接$a\_i - b\_i$間に辺を張ってできるグラフについて、その各頂点の次数が偶数なら`YES`。$O(N + M)$。
各連結成分がオイラーグラフ、あるいは閉路の集合に分解できるとも言える。

-   木上の(辺を複数回使うことを許して)閉路は、その構成要素の辺を各$2$回ずつ使うのは明らか
-   逆は(上ほどには明らかではないが)、十分確信できる

## solution

``` c++
#include <cstdio>
#include <vector>
#define repeat(i,n) for (int i = 0; (i) < int(n); ++(i))
using namespace std;
int main() {
    int n, m; scanf("%d%d", &n, &m);
    vector<vector<int> > g(n);
    repeat (i,m) {
        int a, b; scanf("%d%d", &a, &b); -- a; -- b;
        g[a].push_back(b);
        g[b].push_back(a);
    }
    bool result = true;
    repeat (i,n) {
        if (g[i].size() % 2 == 1) {
            result = false;
        }
    }
    printf("%s\n", result ? "YES" : "NO");
    return 0;
}
```
