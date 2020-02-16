---
layout: post
alias: "/blog/2016/07/13/code-festival-2015-okinawa-open-c/"
date: "2016-07-13T02:52:42+09:00"
tags: [ "competitive", "writeup", "codefestival", "atcoder", "game", "nim", "grundy" ]
"target_url": [ "https://beta.atcoder.jp/contests/code-festival-2015-okinawa-open/tasks/code_festival_2015_okinawa_c" ]
---

# CODE FESTIVAL 2015 OKINAWA OPEN C - Cat versus Wolf

ジェンガのparseの部分で、対角だけ見ればいいというの気付きたかった。

<!-- more -->

## problem

ジェンガの途中の状態が与えられる。
参加プレイヤーは$2$人とし、これ以降両者は最適に動くとしてその勝者を答えよ。

## solution

Use the grundy numbers, for each layer. $O(N)$.

Layers are mutually mutually independent, so the entire game is the sum of games for layers. In each layer, the grundy number is easily computable. Simply sum them up with xor.

## implementation

``` c++
#include <cstdio>
#include <vector>
#include <array>
#define repeat(i,n) for (int i = 0; (i) < (n); ++(i))
using namespace std;
int main() {
    // input
    int n; scanf("%d", &n);
    vector<array<bool,3> > f(n);
    repeat (i,n) {
        char s[3][3];
        repeat (y,3) repeat (x,3) scanf(" %c", &s[y][x]);
        repeat (j,3) {
            if (i % 2 == 0) {
                f[i][j] = s[0][j] == '#';
            } else {
                f[i][j] = s[j][0] == '#';
            }
        }
    }
    // compute
    array<array<array<int,2>,2>,2> grundy;
    grundy[0][0][0] = -1;
    grundy[1][0][0] = -1;
    grundy[0][1][0] =  0;
    grundy[0][0][1] = -1;
    grundy[0][1][1] =  1;
    grundy[1][0][1] =  0;
    grundy[1][1][0] =  1;
    grundy[1][1][1] =  2;
    int acc = 0;
    int removed = 0;
    for (auto g : f) {
        acc ^= grundy[g[0]][g[1]][g[2]];
        removed += (not g[0]) + (not g[1]) + (not g[2]);
    }
    int ans = bool(acc) == bool(removed % 2 == 0);
    // output
    printf("%s\n", ans ? "Snuke" : "Sothe");
    return 0;
}
```
