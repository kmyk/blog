---
layout: post
alias: "/blog/2017/10/22/kupc-2017-d/"
date: "2017-10-22T13:33:25+09:00"
tags: [ "competitive", "writeup", "kupc", "atcoder", "experience" ]
"target_url": [ "https://beta.atcoder.jp/contests/kupc2017/tasks/kupc2017_d" ]
---

# Kyoto University Programming Contest 2017: D - Sanmoku

この手のものは私が相対的に得意らしい。
ratingが私と同じか少し高い某氏はこれを落としていたのが印象的。

## solution

$N \ge 3$なら$K = 1$は明らか。
実験。$O(1)$。

## implementation

``` python
#!/usr/bin/env python3
n = int(input())
if n in ( 1, 2 ):
    print(1, 1)
elif n == 3:
    print(2, 32)
elif n == 4:
    print(2, 18)
else:
    print(2, 8)
```

### 実験用コード

``` c++
#include <cstdio>
#include <functional>
#include <vector>
using namespace std;
template <typename X, typename T> auto vectors(X x, T a) { return vector<T>(x, a); }
template <typename X, typename Y, typename Z, typename... Zs> auto vectors(X x, Y y, Z z, Zs... zs) { auto cont = vectors(y, z, zs...); return vector<decltype(cont)>(x, cont); }

constexpr int mod = 1e9+7;
pair<int, int> solve(int n) {
    if (n <= 2) return { 1, 1 };
    auto f = vectors(n, n, char());
    function<int (int, int)> go = [&](int y, int x) {
        if (x == n) { y += 1; x = 0; }
        if (y == n) { return 1; }
        int required[2] = {};
        if (y - 2 >= 0 and f[y - 2][x] == f[y - 1][x]) required[not f[y - 1][x]] += 1;
        if (x - 2 >= 0 and f[y][x - 2] == f[y][x - 1]) required[not f[y][x - 1]] += 1;
        if (y - 2 >= 0 and x - 2 >= 0 and f[y - 2][x - 2] == f[y - 1][x - 1]) required[not f[y - 1][x - 1]] += 1;
        if (y - 2 >= 0 and x + 2 <  n and f[y - 2][x + 2] == f[y - 1][x + 1]) required[not f[y - 1][x + 1]] += 1;
        if (required[0] and required[1]) {
            return 0;
        } else if (required[0]) {
            f[y][x] = false;
            return go(y, x + 1);
        } else if (required[1]) {
            f[y][x] = true;
            return go(y, x + 1);
        } else {
            f[y][x] = false;
            int acc = go(y, x + 1);
            f[y][x] = true;
            acc += go(y, x + 1);
            return acc % mod;
        }
    };
    int result = go(0, 0);
    return { 2, result };
}
int main() {
    int n; scanf("%d", &n);
    int k, cnt; tie(k, cnt) = solve(n);
    printf("%d %d\n", k, cnt);
    return 0;
}
```
