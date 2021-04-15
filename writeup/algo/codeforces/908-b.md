---
layout: post
redirect_from:
  - /writeup/algo/codeforces/908-b/
  - /blog/2017/12/30/cf-908-b/
date: "2017-12-30T12:48:28+09:00"
tags: [ "competitive", "writeup", "codeforces" ]
"target_url": [ "http://codeforces.com/contest/908/problem/B" ]
---

# Codeforces Good Bye 2017: B. New Year and Buggy Bot

## problem

障害物の置かれた盤面と数列が与えられる。
数から方向への対応$\sigma \in \mathfrak{S}\_4$を固定し、数列から翻訳された方向に従ってロボットが動く。
ロボットがスタートからゴールまで移動できるような対応の数はいくつか。

## solution

全部試す。$4!$が定数に乗る$O(HW + \|s\|)$。

## implementation

``` c++
#include <bits/stdc++.h>
#define REP(i, n) for (int i = 0; (i) < int(n); ++ (i))
#define ALL(x) begin(x), end(x)
using namespace std;

const int dy[] = { -1, 1, 0, 0 };
const int dx[] = { 0, 0, 1, -1 };

int main() {
    // input
    int h, w; cin >> h >> w;
    vector<string> f(h);
    REP (y, h) cin >> f[y];
    string command; cin >> command;
    // solve
    int sy = -1;
    int sx = -1;
    REP (y, h) REP (x, w) {
        if (f[y][x] == 'S') {
            sy = y;
            sx = x;
        }
    }
    int cnt = 0;
    array<int, 4> mapping;
    iota(ALL(mapping), 0);
    do {
        int y = sy;
        int x = sx;
        for (char c : command) {
            int dir = mapping[c - '0'];
            int ny = y + dy[dir];
            int nx = x + dx[dir];
            if (ny < 0 or h <= ny or nx < 0 or w <= nx) break;
            if (f[ny][nx] == '#') break;
            y = ny;
            x = nx;
            if (f[y][x] == 'E') break;
        }
        cnt += f[y][x] == 'E';
    } while (next_permutation(ALL(mapping)));
    // output
    printf("%d\n", cnt);
    return 0;
}
```
