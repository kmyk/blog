---
layout: post
alias: "/blog/2016/07/31/agc-002-b/"
date: "2016-07-31T22:58:23+09:00"
title: "AtCoder Grand Contest 002: B - Box and Ball"
tags: [ "competitive", "writeup", "atcoder", "agc" ]
"target_url": [ "https://beta.atcoder.jp/contests/agc002/tasks/agc002_b" ]
---

## solution

移動後に玉が$0$個になる場合にだけ気を付けて、赤玉の存在可能性を伝播させていく。$O(N)$。

赤玉の入っている確率を考えて、それが非零なものを数えるのに等しい。
移動元に赤玉が入っている確率が非零な$p \gt 0$であれば、移動先のその確率も非零になる。
移動元に玉が$n$個あったとして移動後の確率$p' = \frac{n - 1}{n} p$であるので、$n = 1$なら$p' = 0$、そうでなければ$p' \gt 0$。

## implementation

``` c++
#include <iostream>
#include <vector>
#include <algorithm>
#define repeat(i,n) for (int i = 0; (i) < (n); ++(i))
#define whole(f,x,...) ([&](decltype((x)) y) { return (f)(begin(y), end(y), ## __VA_ARGS__); })(x)
using namespace std;
int main() {
    int n, m; cin >> n >> m;
    vector<bool> dp(n); dp[0] = true;
    vector<int> cnt(n, 1);
    repeat (i,m) {
        int x, y; cin >> x >> y;
        -- x; -- y;
        -- cnt[x]; ++ cnt[y];
        if (dp[x]) dp[y] = true;
        if (cnt[x] == 0) dp[x] = false;
    }
    cout << whole(count, dp, true) << endl;
    return 0;
}
```
