---
layout: post
alias: "/blog/2015/10/01/arc-006-d/"
title: "AtCoder Regular Contest 006 D - アルファベット探し"
date: 2015-10-01T19:52:59+09:00
tags: [ "atcoder", "arc", "competitive", "writeup" ]
---

今日は意識が低い。たぶん気圧が低いのが悪い。

<!-- more -->

## [D - アルファベット探し](https://beta.atcoder.jp/contests/arc006/tasks/arc006_4) {#d}

いまいちよく分からなかったしなんか面倒だなあと思ったので解法をぐぐったら案の上外していた。

### 解法

文字を構成する黒マスが別の文字のそれと繋がることがないので、8近傍の連結成分を取れば1文字切り出せる。
文字を構成するマスの数とbounding boxの幅から`A` `B` `C`は識別できる。

### 実装

いくつかの簡単に判明するバグを埋めた。(怠っていた)対策としては、

-   必ず割り切れると分かっているときはそう`assert`する。
-   追加のテストケースは面倒臭がらず書く。

``` c++
#include <iostream>
#include <vector>
#include <algorithm>
#include <cassert>
#define repeat_from(i,m,n) for (int i = (m); (i) < (n); ++(i))
#define repeat(i,n) repeat_from(i,0,n)
using namespace std;
int dy[8] = { -1, -1, -1, 0, 0, 1, 1, 1 };
int dx[8] = { -1, 0, 1, -1, 1, -1, 0, 1 };
int main() {
    int h, w; cin >> h >> w;
    vector<vector<char> > c(h, vector<char>(w));
    repeat (y,h) repeat (x,w) cin >> c[y][x];
    int result[3] = {};
    repeat (y,h) repeat (x,w) if (c[y][x] == 'o') {
        c[y][x] = '.';
        vector<int> ys { y };
        vector<int> xs { x };
        int i = 0;
        while (i < ys.size()) {
            repeat (j,8) {
                int ny = ys[i] + dy[j];
                int nx = xs[i] + dx[j];
                assert (0 <= ny and ny < h and 0 <= nx and nx < w);
                if (c[ny][nx] == '.') continue;
                c[ny][nx] = '.';
                ys.push_back(ny);
                xs.push_back(nx);
            }
            ++ i;
        }
        assert (    (*max_element(ys.begin(), ys.end()) - *min_element(ys.begin(), ys.end()) + 1) % 5 == 0);
        int scale = (*max_element(ys.begin(), ys.end()) - *min_element(ys.begin(), ys.end()) + 1) / 5;
        assert (i % (scale * scale) == 0);
        int n = i / (scale * scale);
        assert (n == 12 or n == 16 or n == 11);
        result[n == 12 ? 0 : n == 16 ? 1 : 2] += 1;
    }
    cout << result[0] << ' ' << result[1] << ' ' << result[2] << endl;
    return 0;
}
```
