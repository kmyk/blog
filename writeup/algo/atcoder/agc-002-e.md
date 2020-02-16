---
layout: post
alias: "/blog/2017/04/28/agc-002-e/"
date: "2017-04-28T03:51:52+09:00"
tags: [ "competitive", "writeup", "atcoder", "agc", "game" ]
"target_url": [ "https://beta.atcoder.jp/contests/agc002/tasks/agc002_e" ]
---

# AtCoder Grand Contest 002: E - Candy Piles

山のキャンディを全て食べる操作を任意の山に対して行えると誤読し、解説を読んで気付いた。

## solution

ad-hocに。$O(N)$。
図が載ってて分かりやすいので、[editorial](https://beta.atcoder.jp/contests/agc002/data/agc/002/editorial.pdf)を見て。

---

# AtCoder Grand Contest 002: E - Candy Piles

解法はeditorialに譲ったので、感じたことを書く。

まず問題文より、行なえる操作は以下のふたつ。

1.  キャンディが最も多く残っている山をひとつ選び、その山のキャンディをすべて食べる。
2.  キャンディが残っているすべての山から、1 個ずつキャンディを食べる。

始めに山を降順に整列しておけば、(1.)は最も左の山を削除するという操作になる。
(2.)の操作は順序を保存する。
また、これらの操作(1.), (2.)は可換である。
ということで、それぞれの操作回数を$a, b$として、ゲームの状態は座標$(a, b)$のようにして表せる。

このような感じに座標に落とすのは多分他の問題でも出てきそうという気がする。

## implementation

``` c++
#include <cstdio>
#include <vector>
#include <algorithm>
#include <cassert>
#define repeat(i,n) for (int i = 0; (i) < int(n); ++(i))
#define whole(f,x,...) ([&](decltype((x)) whole) { return (f)(begin(whole), end(whole), ## __VA_ARGS__); })(x)
using namespace std;
int main() {
    // input
    int n; scanf("%d", &n);
    vector<int> a(n); repeat (i,n) scanf("%d", &a[i]);
    whole(sort, a);
    whole(reverse, a);
    // compute
    int z = 0;
    assert (z < n and z < a[z]);
    while (z+1 < n and z+1 < a[z+1]) ++ z;
    int dy = a[z] - z - 1;
    int dx = 0;
    while (z + dx+1 < n and z < a[z + dx+1]) ++ dx;
    bool result = (dy % 2 == 1) or (dx % 2 == 1);
    // output
    printf("%s\n", result ? "First" : "Second");
    return 0;
}
```
