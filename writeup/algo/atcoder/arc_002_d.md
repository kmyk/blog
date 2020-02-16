---
layout: post
redirect_from:
  - /writeup/algo/atcoder/arc-002-d/
  - /blog/2015/09/27/arc-002-d/
date: 2015-09-27T15:06:41+09:00
tags: [ "arc", "atcoder", "competitive", "writeup" ]
---

# AtCoder Regular Contest 002 D - ボードゲーム

少し難しめの問題を、と思ってD問題。もちろん簡単ではないが、とても難しいとも感じなかった。
バグが取れなかったのでヒントとして他人の解説記事を覗いてしまったが、それ以外は全て自力で解けた。

<!-- more -->

## [D - ボードゲーム](https://beta.atcoder.jp/contests/arc002/tasks/arc002_4) {#d}

## 問題

たくさんの歩が将棋盤の上に置いてある。
歩を交互に動かして、相手の歩をすべて取るか一番奥まで進ませれば勝ち。
盤面が与えられるので必勝手番を求める。

## 過程

落ち着いて丁寧に見ていけば、自動的に解法が得られる。 <small> <del> しかし私は落ち着きも丁寧さも足りなかったのでバグらせた </del> </small>

1.  grundy数による分割は、不偏ゲーム(impartial game)でないのでできない
2.  1番目のサンプルから、歩同士が1マス空けて睨み合っている場合に先に動かすことを相手に強制できれば勝ち
3.  2番目のサンプルから、睨み合う相手がいない歩がいる場合は単に走らせればよく、以降無視できる
4.  全ての睨み合いの間のマスが1マスの場合、後ろで遊んでいる歩を見れば結果が分かり、相手との干渉はない
5.  睨み合いの間のマスを詰める時は、後ろで遊んでいる歩の数だけ余裕ができる
6.  詰める時、同時に相手が得られるはずだった余裕を得られないようにしていることから、双方の遊んでいる歩の数の和が多い順に詰めていくべきである
7.  これを実装する

## 解答

``` c++
#include <iostream>
#include <vector>
#include <algorithm>
#include <cassert>
#define repeat_from(i,m,n) for (int i = (m); (i) < (n); ++(i))
#define repeat(i,n) repeat_from(i,0,n)
typedef long long ll;
using namespace std;
struct conflict_t { vector<int> o, x; };
struct buffer_t { int diff, o, x; };
bool operator < (buffer_t const & a, buffer_t const & b) { return a.diff < b.diff; }
bool solve(int h, int w, vector<vector<char> > const & c) {
    vector<conflict_t> cnfs;
    repeat (y,h) {
        vector<int> os, xs;
        repeat (x,w) {
            if (c[y][x] == 'x') {
                xs.push_back(x);
            } else if (c[y][x] == 'o') {
                if (not xs.empty()) {
                    cnfs.push_back({ os, xs });
                    os.clear();
                    xs.clear();
                }
                os.push_back(x);
            }
        }
        if (not (os.empty() and xs.empty())) {
            cnfs.push_back({ os, xs });
        }
    }
    int ao = w, ax = w;
    ll bo = 0, bx = 0;
    vector<buffer_t> bs;
    for (auto const & cnf : cnfs) {
        vector<int> const & o = cnf.o;
        vector<int> const & x = cnf.x;
        assert (not (o.empty() and x.empty()));
        if (cnf.x.empty()) {
            ao = min(ao, w - o.back() - 1);
        } else if (cnf.o.empty()) {
            ax = min(ax, x.front());
        } else {
            int on = o.size();
            int xn = x.size();
            repeat (i, on) bo += o.back()  - o[i] - i;
            repeat (i, xn) bx += x[i] - x.front() - i;
            repeat (i, (x.front() - o.back() - 2)) {
                bs.push_back({ on + xn, on, xn });
            }
        }
    }
    sort(bs.rbegin(), bs.rend());
    repeat (i, bs.size()) {
        if (i % 2 == 0) {
            bo += bs[i].o;
        } else {
            bx += bs[i].x;
        }
    }
    if (ao <= ax and ao != w) {
        return true;
    } else if (ao > ax) {
        return false;
    } else {
        return bo > bx;
    }
}
int main() {
    int h, w; cin >> h >> w;
    vector<vector<char> > c(h, vector<char>(w));
    repeat (y,h) repeat (x,w) cin >> c[y][x];
    cout << (solve(h,w,c) ? 'o' : 'x') << endl;
    return 0;
}
```
