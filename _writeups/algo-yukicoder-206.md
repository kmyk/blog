---
layout: post
redirect_from:
  - /writeup/algo/yukicoder/206/
  - /blog/2016/08/16/yuki-206/
date: "2016-08-16T22:25:40+09:00"
tags: [ "competitive", "writeup", "yukicoder", "bitset" ]
"target_url": [ "http://yukicoder.me/problems/no/206" ]
---

# Yukicoder No.206 数の積集合を求めるクエリ

解けず。`bitset`は未だに思い付けない。
`bitset`の高速化はよく分からないのだけど、$k = 64$倍速いと思えばよいのかな。

## solution

`bitset`による定数倍高速化。bit数$k$に対し$O(NQ/k)$。$k = 64$ [要出典]。

長さ$N$の大きな`bitset`で、$A$と$B$を表すものをそれぞれ用意する。
これを$i$-bit shiftしたもののbit積のpopcountを$0 \le i \lt Q$に関して出力すればよい。

## implementation

``` c++
#include <iostream>
#include <bitset>
#define repeat(i,n) for (int i = 0; (i) < (n); ++(i))
using namespace std;
const int MAX_N = 100000;
int main() {
    int l, m, n; cin >> l >> m >> n;
    bitset<MAX_N> a; repeat (i,l) { int j; cin >> j; a[j-1] = true; }
    bitset<MAX_N> b; repeat (i,m) { int j; cin >> j; b[j-1] = true; }
    int q; cin >> q;
    repeat (i,q) cout << (a & (b << i)).count() << endl;
    return 0;
}
```
