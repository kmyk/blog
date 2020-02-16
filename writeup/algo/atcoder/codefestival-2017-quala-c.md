---
layout: post
alias: "/blog/2017/10/03/codefestival-2017-quala-c/"
date: "2017-10-03T06:36:51+09:00"
tags: [ "competitive", "writeup", "atcoder", "codefestival", "palindrome" ]
"target_url": [ "https://beta.atcoder.jp/contests/code-festival-2017-quala/tasks/code_festival_2017_quala_c" ]
---

# CODE FESTIVAL 2017 qual A: C - Palindromic Matrix

## solution

$H, W$が奇数のときちょうど中央はまったく自由。
上を除いて、$H$が奇数のとき中央の行は$1$個決めたらもう$1$個も決まる。
それ以外は$1$個決めたらもう$3$個決まる。
つまり$4, 2, 1$刻みで文字種を消費していくことになる。そのようにすれば構成までできる。
$O(HW)$。

## implementation

``` c++
#include <array>
#include <cassert>
#include <cstdio>
#define repeat(i, n) for (int i = 0; (i) < int(n); ++(i))
using namespace std;

bool solve(int h, int w, array<int, 26> cnt) {
    int r1 = (h % 2) * (w % 2);
    int r2 = (h % 2) * (w / 2) + (w % 2) * (h / 2);
    assert  ((h * w - 2 * r2 - r1) % 4 == 0);
    int r4 = (h * w - 2 * r2 - r1) / 4;
    for (int c = 0; r4 --; ) {
        while (c < 26 and cnt[c] < 4) ++ c;
        if (c == 26) return false;
        cnt[c] -= 4;
    }
    for (int c = 0; r2 --; ) {
        while (c < 26 and cnt[c] < 2) ++ c;
        if (c == 26) return false;
        cnt[c] -= 2;
    }
    return true;
}

int main() {
    // input
    int h, w; scanf("%d%d", &h, &w);
    array<int, 26> cnt = {};
    repeat (y, h) repeat (x, w) {
        char c; scanf(" %c", &c);
        cnt[c - 'a'] += 1;
    }
    // solve
    bool result = solve(h, w, cnt);
    // output
    printf("%s\n", result ? "Yes" : "No");
    return 0;
}
```
