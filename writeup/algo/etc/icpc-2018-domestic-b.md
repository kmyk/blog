---
layout: post
date: 2018-07-10T13:02:00+09:00
tags: [ "competitive", "writeup", "icpc" ]
"target_url": [ "http://icpc.iisf.or.jp/past-icpc/domestic2018/contest/all_ja.html", "http://icpc.iisf.or.jp/past-icpc/domestic2018/judgedata/B/" ]
---

# ACM-ICPC 2018 国内予選: B. 折り紙

## solution

最初に$m \times n = H \times W$の$2$次元配列を用意し、各位置にいくつ重なりがあるかを保持しながらこれを折り畳んでいく。
$O(HW \cdot t + p)$。

$2$次元配列の転置を使って操作$d_i = 1$のみと仮定するなどすると実装が楽。

## note

本番はチームメンバーに書いてもらいその間にCやDを読んでいた。
しばらくバグらせてたが(急かしつつも)放っておいたら通してくれた。
コンテスト中は冷静を保ちにくいのでよくない。

後からゆっくりやったら一発で書けたが、本番だと何故かバグるんだろうなあという気持ち。

## implementation

``` c++
#include <bits/stdc++.h>
#define REP(i, n) for (int i = 0; (i) < int(n); ++ (i))
using namespace std;

void update_transpose(int & h, int & w, vector<vector<int> > & a) {
    vector<vector<int> > b(w, vector<int>(h));
    REP (y, h) REP (x, w) {
        b[x][y] = a[y][x];
    }
    a.swap(b);
    swap(h, w);
}

int main() {
    while (true) {
        // input
        int w, h, t, p; cin >> w >> h >> t >> p;
        if (w == 0 and h == 0 and t == 0 and p == 0) break;

        // fold the paper
        vector<vector<int> > a(h, vector<int>(w, 1));
        while (t --) {
            int d, c; cin >> d >> c;
            if (d == 2) update_transpose(h, w, a);

            // with vertical line
            int w1 = max(c, w - c);
            vector<vector<int> > b(h, vector<int>(w1));
            REP (y, h) {
                REP (x, w) {
                    int x1 = x < c ? c - x - 1 : x - c;
                    b[y][x1] += a[y][x];
                }
            }
            a.swap(b);
            w = w1;

            if (d == 2) update_transpose(h, w, a);
        }

        // make holes
        while (p --) {
            int x, y; cin >> x >> y;

            // output
            cout << a[y][x] << endl;
        }
    }
    return 0;
}
```
