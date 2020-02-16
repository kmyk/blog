---
layout: post
redirect_from:
  - /blog/2017/10/03/arc-072-d/
date: "2017-10-03T04:22:38+09:00"
tags: [ "competitive", "writeup", "atcoder", "arc", "game", "experiment" ]
"target_url": [ "https://beta.atcoder.jp/contests/arc072/tasks/arc072_b" ]
---

# AtCoder Regular Contest 072: D - Alice&Brown

## solution

実験。$\|x - y\| \le 1$か否かで決まる。$O(1)$。

## implementation

``` python
#!/usr/bin/env python3
x, y = map(int, input().split())
x, y = sorted([ x, y ])
if x == y or x + 1 == y:
    print('Brown')
else:
    print('Alice')
```

### 実験用コード

``` c++
#include <cstdio>
#include <map>
#include <set>
#define repeat(i,n) for (int i = 0; (i) < int(n); ++(i))
using namespace std;

template <typename C>
int mex(C const & xs) {
    int y = 0;
    for (int x : xs) { // xs must be sorted (duplication is permitted)
        if (y <  x) break;
        if (y == x) ++ y;
    }
    return y;
}

int grundy(int x, int y) {
    static map<pair<int, int>, int> memo;
    if (x > y) swap(x, y);
    pair<int, int> key = { x, y };
    if (not memo.count(key)) {
        set<int> g;
        for (int i = 2; i <= x; i += 2) g.insert(grundy(x - i, y + i / 2));
        for (int i = 2; i <= y; i += 2) g.insert(grundy(x + i / 2, y - i));
        memo[key] = mex(g);
    }
    return memo[key];
}
int main() {
    // ll x, y; scanf("%lld%lld", &x, &y);
    repeat (z, 1000) {
        repeat (x, z + 1) {
            int y = z - x;
            if (y >= x)
            if (grundy(x, y) == 0) printf("%d %d\n", x, y);
        }
    }
    return 0;
}
```
