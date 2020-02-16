---
layout: post
date: 2018-08-05T00:48:41+09:00
tags: [ "competitive", "writeup", "atcoder", "mujin-pc", "dfs" ]
"target_url": [ "https://beta.atcoder.jp/contests/mujin-pc-2018/tasks/mujin_pc_2018_d" ]
---

# Mujin Programming Challenge 2018: D - うほょじご

## solution

実装。
$NM \le 10^6$と小さいので全部の状態について求める。
閉路検出付きのDFS。
$O(NM)$。

## note

順序が自明にill-definedなので純粋な再帰関数にはならないが、積まれたstackで副作用を上手くやればメモ化再帰のように書ける。
この関数が何であるかは$1$巡目に呼び出される関数と$2$回目以降に呼び出される関数が異なるのだとして理解すればよさそう。

## implementation

``` c++
#include <bits/stdc++.h>
#define REP(i, n) for (int i = 0; (i) < (int)(n); ++ (i))
using namespace std;
template <typename X, typename T> auto vectors(X x, T a) { return vector<T>(x, a); }
template <typename X, typename Y, typename Z, typename... Zs> auto vectors(X x, Y y, Z z, Zs... zs) { auto cont = vectors(y, z, zs...); return vector<decltype(cont)>(x, cont); }

int rev(int x) {
    while (x % 10 == 0) x /= 10;
    int y = 0;
    for (; x; x /= 10) y = y * 10 + x % 10;
    return y;
}

int solve(int n, int m) {
    auto memo = vectors(1000, 1000, -1);
    function<int (int, int)> dp = [&](int x, int y) {
        if (memo[x][y] != -1) {
            return memo[x][y];
        }
        if (x == 0 or y == 0) {
            return memo[x][y] = 0;
        }
        memo[x][y] = 1;
        int x1 = x, y1 = y;
        if (x1 < y1) {
            x1 = rev(x1);
        } else {
            y1 = rev(y1);
        }
        if (x1 < y1) {
            y1 -= x1;
        } else {
            x1 -= y1;
        }
        return memo[x][y] = dp(x1, y1);
    };
    int cnt = 0;
    REP (x, n + 1) REP (y, m + 1) {
        cnt += dp(x, y);
    }
    return cnt;
}

int main() {
    int n, m; cin >> n >> m;
    cout << solve(n, m) << endl;
    return 0;
}
```
