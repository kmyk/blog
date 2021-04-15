---
layout: post
redirect_from:
  - /writeup/algo/atcoder/kupc-2015-b/
  - /blog/2015/10/24/kupc-2015-b/
date: 2015-10-24T23:55:09+09:00
tags: [ "kupc", "competitive", "writeup", "exhaustive-search", "local-execution" ]
---

# 京都大学プログラミングコンテスト2015 B - GUARDIANS

手で解けそう、ってのが先行したせいで、手元で探索させればいいってのに気付くのがとても遅れた。

こういうの好き

<!-- more -->

## [B - GUARDIANS](https://beta.atcoder.jp/contests/kupc2015/tasks/kupc2015_b) {#b}

### 問題

$10 \times 10$の盤面がある。
侵入者が、最左列の適当な位置から、右上、右、右下への移動を繰り返し、最右列を目指す。
鎖頭を適当に配置して、侵入者の取り得る経路がただ1種類のみになるようにする。
鎖頭を`C`の位置に配置すると、侵入者は以下の`X`で示した位置へ移動できなくなる。

```
.......
.X.X.X.
..XXX..
.XXCXX.
..XXX..
.X.X.X.
.......
```

鎖頭の配置を構成し提出せよ。
鎖頭の数は少ないほうが良く、$N = 4$の解が存在する。

### 解法

-   思い付く
-   手元で全探索
    -   $N = 4$の解が存在する、というのがヒント
    -   解の総数を$X$とし$({}\_{100}C\_4 \times 10) / X$ぐらいなので十分間に合う

### 実装

全探索

``` c++
#include <iostream>
#include <array>
#include <cassert>
#define repeat_from(i,m,n) for (int i = (m); (i) < (n); ++(i))
#define repeat(i,n) repeat_from(i,0,n)
using namespace std;
int dy[17] = { -2, -2, -2, -1, -1, -1, 0, 0, 0, 0, 0, 1, 1, 1, 2, 2, 2 };
int dx[17] = { -2, 0, 2, -1, 0, 1, -2, -1, 0, 1, 2, -1, 0, 1, -2, 0, 2 };
void update(array<array<int,10>,10> & a, int cy, int cx, int v) {
    repeat (j,17) {
        int y = cy + dy[j];
        int x = cx + dx[j];
        if (0 <= y and y < 10 and 0 <= x and x < 10) {
            a[y][x] += v;
        }
    }
}
int dfs(array<array<int,10>,10> const & a, int y, int x) {
    if (x == 9) return 1;
    int acc = 0;
    for (int dy : { -1, 0, 1 }) {
        int ny = y + dy;
        if (0 <= ny and ny < 10) {
            if (not a[ny][x+1]) {
                acc += dfs(a, ny, x+1);
                if (acc >= 2) return acc;
            }
        }
    }
    return acc;
}
bool pred(array<array<int,10>,10> const & a) {
    int acc = 0;
    repeat (y, 10) {
        if (not a[y][0]) {
            acc += dfs(a, y, 0);
            if (acc >= 2) return false;
        }
    }
    cerr << acc << endl;
    return acc == 1;
}
void output(array<int,4> const & ys, array<int,4> const & xs) {
    repeat (y, 10) {
        repeat (x, 10) {
            char c = '.';
            repeat (i,4) {
                if (ys[i] == y and xs[i] == x) {
                    c = 'C';
                }
            }
            cout << c;
        }
        cout << endl;
    }
}
int main() {
    array<array<int,10>,10> a = {};
    array<int,4> xs;
    array<int,4> ys;
    repeat (i,100) {
cerr << i << endl;
        ys[0] = i / 10;
        xs[0] = i % 10;
        update(a, ys[0], xs[0], 1);
        repeat_from (j,i+1,100) {
            ys[1] = j / 10;
            xs[1] = j % 10;
            update(a, ys[1], xs[1], 1);
            repeat_from (k,j+1,100) {
                ys[2] = k / 10;
                xs[2] = k % 10;
                update(a, ys[2], xs[2], 1);
                repeat_from (l,k+1,100) {
                    ys[3] = l / 10;
                    xs[3] = l % 10;
                    update(a, ys[3], xs[3], 1);
                    if (pred(a)) {
repeat (y,10) {
repeat (x,10) {
cerr << a[y][x];
}
cerr << endl;
}
cerr << endl;
                        output(ys,xs);
                        return 0;
                    }
                    update(a, ys[3], xs[3], -1);
                }
                update(a, ys[2], xs[2], -1);
            }
            update(a, ys[1], xs[1], -1);
        }
        update(a, ys[0], xs[0], -1);
    }
    return 1;
}
```
