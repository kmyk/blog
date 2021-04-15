---
layout: post
redirect_from:
  - /writeup/algo/atcoder/agc_004_e/
  - /writeup/algo/atcoder/agc-004-e/
  - /blog/2017/04/28/agc-004-e/
date: "2017-04-28T08:06:38+09:00"
tags: [ "competitive", "writeup", "atcoder", "agc", "dp" ]
"target_url": [ "https://beta.atcoder.jp/contests/agc004/tasks/agc004_e" ]
---

# AtCoder Grand Contest 004: E - Salvage Robots

$O(H^2W^2)$でbounding boxを尽くせば求まりそうだとは思ったが、細部を詰めるのも実装するのも面倒だなあと思ってしまったので解説を見てしまった。方向は合ってた。

## solution

壁の外に出てないロボットの範囲、あるいは出口を動かすと考えて出口が(ロボットを追加で爆発させることなしに)動ける範囲は、上下左右$(u,d,l,r)$という$4$つ組で表わせる。
そのような場合の救出したロボットの数の最大値を返す関数$\mathrm{dp} : H \times H \times W \times W \to \mathbb{N}$で計算する。$O(H^2W^2)$。

$dp(u,d,l,r)$から$dp(u+1,d,l,r), dp(u,d+1,l,r), dp(u,d,l+1,r), dp(u,d,l,r+1)$が求まるので丁寧にやる。
例えば$dp(u+1,d,l,r)$を求めるとき、$d \le E\_y-(u+1)$である必要があって$(E\_y-(u+1), x)$で$\max(E\_x-l, r) \le x \lt \min(E\_x+r+1, W-l)$の範囲のロボットが追加で救出できる。

## implementation

``` c++
#include <cstdio>
#include <cstdint>
#include <algorithm>
#define repeat(i,n) for (int i = 0; (i) < int(n); ++(i))
using namespace std;
template <class T> inline void setmax(T & a, T const & b) { a = max(a, b); }

constexpr int max_h = 100;
constexpr int max_w = 100;
int16_t dp[max_h][max_w][max_h][max_w];
bool f[max_h][max_w];
int row_acc[max_h][max_w+1];
int col_acc[max_w][max_h+1];
int main() {
    int h, w; scanf("%d%d", &h, &w);
    int ey = -1, ex = -1;
    repeat (y,h) repeat (x,w) {
        char c; scanf(" %c", &c);
        if (c == 'o') f[y][x] = true;
        if (c == 'E') { ey = y; ex = x; }
    }
    repeat (y,h) repeat (x,w) row_acc[y][x+1] = row_acc[y][x] + f[y][x];
    repeat (y,h) repeat (x,w) col_acc[x][y+1] = col_acc[x][y] + f[y][x];
    repeat (ly,ey+1) {
        repeat (lx,ex+1) {
            repeat (ry,h-ey) {
                repeat (rx,w-ex) {
                    auto col = [&](int x) { return rx <= x and x < w-lx ? col_acc[x][min(ey+ry+1,h-ly)] - col_acc[x][max(ey-ly,ry)] : 0; };
                    auto row = [&](int y) { return ry <= y and y < h-ly ? row_acc[y][min(ex+rx+1,w-lx)] - row_acc[y][max(ex-lx,rx)] : 0; };
                    if (ey-(ly+1) >= 0) setmax<int16_t>(dp[ly+1][lx][ry][rx], dp[ly][lx][ry][rx] + row(ey-(ly+1)));
                    if (ex-(lx+1) >= 0) setmax<int16_t>(dp[ly][lx+1][ry][rx], dp[ly][lx][ry][rx] + col(ex-(lx+1)));
                    if (ey+(ry+1) <  h) setmax<int16_t>(dp[ly][lx][ry+1][rx], dp[ly][lx][ry][rx] + row(ey+(ry+1)));
                    if (ex+(rx+1) <  w) setmax<int16_t>(dp[ly][lx][ry][rx+1], dp[ly][lx][ry][rx] + col(ex+(rx+1)));
                }
            }
        }
    }
    printf("%d\n", dp[ey][ex][h-ey-1][w-ex-1]);
    return 0;
}
```
