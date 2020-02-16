---
layout: post
redirect_from:
  - /writeup/algo/atcoder/agc-008-c/
  - /blog/2016/12/25/agc-008-c/
date: "2016-12-25T23:01:24+09:00"
tags: [ "competitive", "writeup", "atcoder", "agc" ]
"target_url": [ "https://beta.atcoder.jp/contests/agc008/tasks/agc008_c" ]
---

# AtCoder Grand Contest 008: C - Tetromino Tiling

## 反省

使える組の形を勘違いしてて$1$時間も溶かした。
謎のR型テトロミノが入力取る部分に混入してた事件もあった。
冷静になるのも兼ねて、途中でDを見に行ってもよかった。

## solution

よく見て計算。$O(1)$。

T, S, Z型のテトロミノは無視してよい。
$1$マス分の欠けを埋められるテトロミノは存在しない。
O型のテトロミノは自明な利用しかできないので忘れてよい。

I, J, L型のテトロミノについて。
これらは以下のように組合せられる。

-   I-I
-   J-J, J-I-I-J, J-I-I-I-I-J, $\dots$
-   L-L, L-I-I-L, L-I-I-I-I-L, $\dots$
-   J-I-L, J-I-I-I-L, J-I-I-I-I-I-L, $\dots$

この中で考慮すべきは I-I, J-J, L-L, J-I-L の組合せだけ。
J-I-L の組$2$つ以上使う場合はこれを J-J, I-I, L-L の$3$組へ分解してよいので、 J-I-L の組は高々$1$回しか使わない。これで場合分けすればよい。

## implementation

この手のやつを`enum foo_t { A, B, C, size };`と`array<int, size>`でいい感じにするのは便利。

``` c++
#include <iostream>
#include <array>
#define repeat(i,n) for (int i = 0; (i) < int(n); ++(i))
typedef long long ll;
using namespace std;
template <class T> void setmax(T & a, T const & b) { if (a < b) a = b; }
/*
 *  OO  IIII  Jjjj  lllL
 *  OO  iiii  JJJj  lLLL
 *
 *  L IIII LLL
 *  LLL iiii L
 *
 *  L IIII J
 *  LLL  JJJ
 */
enum tile_t { I, O, T, J, L, S, Z };
ll f(array<ll, 7> a, int jil) {
    a[I] -= jil;
    a[J] -= jil;
    a[L] -= jil;
    if (a[I] < 0 or a[J] < 0 or a[L] < 0) return -1;
    ll k = 0;
    k += jil * 3;
    k += a[I] / 2 * 2; a[I] %= 2;
    k += a[J] / 2 * 2; a[J] %= 2;
    k += a[L] / 2 * 2; a[L] %= 2;
    k += a[O]; a[O] = 0;
    return k;
}
int main() {
    array<ll, 7> a; repeat (i,7) cin >> a[i];
    ll k = 0;
    repeat (jil,3) setmax(k, f(a, jil));
    cout << k << endl;
    return 0;
}
```
