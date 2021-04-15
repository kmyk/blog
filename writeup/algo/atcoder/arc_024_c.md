---
layout: post
redirect_from:
  - /writeup/algo/atcoder/arc_024_c/
  - /writeup/algo/atcoder/arc-024-c/
  - /blog/2015/11/03/arc-024-c/
date: 2015-11-03T17:02:11+09:00
tags: [ "competitive", "writeup", "arc", "atcoder", "string-search" ]
---

# AtCoder Regular Contest 024 C - だれじゃ

arcのc埋め、残り3問に。

<!-- more -->

## [C - だれじゃ](https://beta.atcoder.jp/contests/arc024/tasks/arc024_3) {#c}

### 問題

長さ$n$の文字列$s$が与えられる。$s$の部分文字列の対で、互いに交差せず、それぞれ長さkで、互いにアナグラム、であるようなものが存在するかどうか調べよ。

### 解法

$O(n \log n)$。

文字列$s$の長さ$k$の部分文字列は$n-k+1$個存在する。
部分文字列どうしがアナグラムであるかどうかは、元の文字列中の位置によらない。
よって、部分文字列を前から見ていき、それより前に存在する交差しない部分文字列のいづれかとアナグラムであるかどうかを調べればよい。
ある文字列より前の部分文字列のいづれかとアナグラムであるかどうかは、部分文字列を舐める際に、`map`に格納しながら舐めていけば、$O(\log n)$で判定できる。

### 実装

あまりちゃんと考えず、まあ通りそうだし、と思って書いたら通った。

``` c++
#include <iostream>
#include <array>
#include <vector>
#include <map>
#define repeat_from(i,m,n) for (int i = (m); (i) < (n); ++(i))
#define repeat(i,n) repeat_from(i,0,n)
using namespace std;
int main() {
    int n, k; cin >> n >> k;
    string s; cin >> s;
    vector<array<int,26> > chrs(n - k + 1);
    repeat (i, k) {
        chrs[0][s[i] - 'a'] += 1;
    }
    repeat_from (i, 1, n-k+1) {
        chrs[i] = chrs[i-1];
        chrs[i][s[i+k-1] - 'a'] += 1;
        chrs[i][s[i-1]   - 'a'] -= 1;
    }
    map<array<int,26>,int> cnts;
    bool result = false;
    repeat (i, n-k+1) {
        if (0 <= i-k) cnts[chrs[i-k]] += 1;
        if (cnts[chrs[i]]) {
            result = true;
            break;
        }
    }
    cout << (result ? "YES" : "NO") << endl;
    return 0;
}
```
