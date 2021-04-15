---
layout: post
redirect_from:
  - /writeup/algo/topcoder/srm-677-easy/
  - /blog/2015/12/27/srm-677-easy/
date: 2015-12-27T04:08:43+09:00
tags: [ "competitive", "writeup", "srm" ]
---

# TopCoder SRM 676 Div1 Easy: DoubleOrOneEasy

零完しました。$x' = f(x) = x \ll i + j$の$i$を総当たればよいのは気付いていたが、その先をDPだと思い込んでしまっていた。

## [Easy: DoubleOrOneEasy]() {#easy}

### 問題

正整数の対$(a,b)$が与えられる。
以下の変換を用いて$(a',b')$を作るとき、必要な変換の操作の回数の最小値はいくらか。

-   $(x,y)$を$(x+1,y+1)$に変換する。
-   $(x,y)$を$(2x,2y)$に変換する。

### 解法

一連の変換操作は、$(x,y)$から$(f(x),f(y))$への変換で、$f(x) = x \ll i + j$と表せる。
この$i$、つまり答えとなる変換の中の2倍する回数について総当たりする。

$i$を固定すると$j$が定まる。これは$a,b$で一致しなければならない。
ここで答えは$i+j$ではない。$i$回のshift演算を使って$j$を効率的に作れるからである。
下位$i$-bitはshiftにより$1$回のincrementで作れ、それより上のbitの部分$j \gg i$はincrementをそれ自身の回数$j \gg i$回用いなければならない。

### 実装

``` c++
#include <bits/stdc++.h>
#define repeat(i,n) for (int i = 0; (i) < (n); ++(i))
typedef long long ll;
using namespace std;
class DoubleOrOneEasy {
public:
    int minimalSteps(ll a, ll b, ll newA, ll newB);
};

int DoubleOrOneEasy::minimalSteps(ll a, ll b, ll newA, ll newB) {
    ll result = INT_MAX;
    repeat (i,32) {
        if (newA - (a<<i) == newB - (b<<i)) {
            ll j = newA - (a<<i);
            if (j < 0) continue;
            result = min(result, i + (j >> i) + __builtin_popcount(j & ((1ll<<i) - 1)));
        }
    }
    return result == INT_MAX ? -1 : result;
}
```
