---
layout: post
title: "Mujin Programming Challenge 2018: C - 右折"
date: 2018-08-05T00:43:17+09:00
tags: [ "competitive", "writeup", "atcoder", "mujin-pc" ]
"target_url": [ "https://beta.atcoder.jp/contests/mujin-pc-2018/tasks/mujin_pc_2018_c" ]
---

## solution

累積和っぽく適当に。$O(NM)$。

## note

-   $90$度回転をすると実装が$1/4$になる。
-   回転のつもりで転置を書かないように注意したい。サンプルに救われたがやらかした。

## implementation

``` c++
#include <bits/stdc++.h>
#define REP(i, n) for (int i = 0; (i) < (int)(n); ++ (i))
#define REP_R(i, n) for (int i = int(n) - 1; (i) >= 0; -- (i))
using ll = long long;
using namespace std;

ll solve1(int h, int w, vector<string> const & f) {
    ll cnt = 0;
    vector<ll> acc1(w);
    REP_R (y, h) {
        ll acc2 = 0;
        REP (x, w) {
            if (f[y][x] == '#') {
                acc1[x] = 0;
                acc2 = 0;
            } else {
                cnt += acc2;
                acc2 += acc1[x];
                acc1[x] += 1;
            }
        }
    }
    return cnt;
}

vector<string> rotate_field(int h, int w, vector<string> const & f) {
    vector<string> g(w, string(h, char()));
    REP (x, w) REP (y, h) {
        g[x][y] = f[y][w - x - 1];
    }
    return g;
}

ll solve(int h, int w, vector<string> f) {
    ll cnt = 0;
    REP (rot, 4) {
        cnt += solve1(h, w, f);
        f = rotate_field(h, w, f);
        swap(h, w);
    }
    return cnt;
}

int main() {
    // input
    int h, w; cin >> h >> w;
    vector<string> f(h);
    REP (y, h) cin >> f[y];

    // solve
    ll cnt = solve(h, w, f);

    // output
    cout << cnt << endl;
    return 0;
}
```
