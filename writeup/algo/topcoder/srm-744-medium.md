---
redirect_from:
layout: post
date: 2018-12-15T05:00:00+09:00
tags: [ "competitive", "writeup", "topcoder", "srm", "lightsout" ]
---

# TCO19 Single Round Match 744: Medium - UniformingMatrix

## 問題概要

LightsOut系。
中央を除く十字に反転させられる。
任意回繰り返してすべて黒にできるか判定せよ。

## 解法

### 概要

操作は列反転 + 行反転に分解できる。
愚直にやっても $$O(HW)$$。

### 詳細

列反転 + 行反転に分解できることから、同じ回数の列反転と行反転ですべて黒にできることが必要十分条件である。
同じ列や行を複数回選んでもよいのでこれは回数の偶奇が同じであることに等しい。

さらにコーナーケースとして以下のような場合がある。
これは `possible` だが $$H \not\equiv W \pmod{2}$$ の場合はすべてこれと同様の状況が発生するので「同じ回数の」という制約が落ちる。

```
110
110
```

## メモ

落とした。
愚直解を書いて検証しなかったのが敗因。
$$O(2^{HW})$$ なら書けるので書くべきだった。

## 実装

``` c++
#include <bits/stdc++.h>
#define REP(i, n) for (int i = 0; (i) < int(n); ++ (i))
using namespace std;
class UniformingMatrix { public: string isPossible(vector<string> M); };

bool solve1(int h, int w, vector<vector<char> > f) {
    int hr = 0;
    REP (y, h) if (not f[y][0]) {
        ++ hr;
        REP (x, w) {
            f[y][x] ^= 1;
        }
    }
    int vr = 0;
    REP (x, w) if (not f[0][x]) {
        ++ vr;
        REP (y, h) {
            f[y][x] ^= 1;
        }
    }
    if (h % 2 == w % 2 and hr % 2 != vr % 2) {
        return false;
    }
    REP (y, h) {
        REP (x, w) {
            if (not f[y][x]) return false;
        }
    }
    return true;
}

bool solve(int h, int w, vector<vector<char> > const & f) {
    if (solve1(h, w, f)) return true;
    vector<vector<char> > g(w, vector<char>(h));
    REP (y, h) REP (x, w) g[x][y] = f[y][x];
    if (solve1(w, h, g)) return true;
    return false;
}

string UniformingMatrix::isPossible(vector<string> M) {
    int h = M.size();
    int w = M[0].size();
    vector<vector<char> > f(h, vector<char>(w));
    REP (y, h) REP (x, w) f[y][x] = M[y][x] - '0';
    return solve(h, w, f) ? "possible" : "impossible";
}
```
