---
layout: post
redirect_from:
  - /writeup/algo/atcoder/code-festival-2015-final-c/
  - /blog/2015/11/21/code-festival-2015-final-c/
date: 2015-11-21T17:18:56+09:00
tags: [ "competitive", "writeup", "codefestival", "atcoder", "greedy" ]
---

# CODE FESTIVAL 2015 決勝 C - 寿司タワー

寿司を積む。
本番は貪欲をc++で書いたが、1行で書ける問題だったようだ。

<!-- more -->

## [C - 寿司タワー](https://beta.atcoder.jp/contests/code-festival-2015-final-open/tasks/codefestival_2015_final_c) {#c}

### 問題

`0`と`1`の列が与えられる。
空列から始めて以下の操作を繰り返し、与えられた列を作る。

1. 列の後ろに`01`あるいは`10`を追加する。
2. 列の後ろに`0`あるいは`1`を追加する。後程好きなタイミングで、`0`と`1`の追加しなかった方を、列に加えてよい。

与えられた列を作るのに、後者の操作は最小で何回必要か。
与えられた列を作れることは保証されている。

### 解法

貪欲。

`01`あるいは`10`と連続する部分を全て削除して長さを2で割ってもよい。
やってることは同じ。

### 実装

``` sh
read;bc<<<`sed 's/01\|10//g'|wc -c`/2
```

``` perl
<>;$_=<>;s/01|10//g;print int y///c/2,$/
```

``` c++
#include <iostream>
using namespace std;
#define SHARI '0'
#define NETA  '1'
int main() {
int n; cin >> n;
string s; cin >> s;
int split = 0;
int i = 0;
int neta = 0, shari = 0;
while (i < 2*n) {
    if (i+1 == 2*n) {
        (s[i] == NETA ? neta : shari) -= 1;
        i += 1;
    } else {
        if (s[i] != s[i+1]) {
            i += 2;
        } else {
            if (s[i] == NETA ? neta : shari) {
                (s[i] == NETA ? neta : shari) -= 1;
            } else {
                (s[i] == NETA ? shari : neta) += 1;
                split += 1;
            }
            i += 1;
        }
    }
}
cout << split << endl;
return 0;
}
```
