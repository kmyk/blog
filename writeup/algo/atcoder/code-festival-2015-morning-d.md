---
layout: post
alias: "/blog/2015/11/20/code-festival-2015-morning-d/"
title: "CODE FESTIVAL 2015 朝プロ D - ヘイホー君と削除"
date: 2015-11-20T00:06:47+09:00
tags: [ "competitive", "writeup", "codefestival", "atcoder", "dp" ]
---

そこそこの速度でAC。でもDPの周りで実装ミスして1WA。

<!-- more -->

## [D - ヘイホー君と削除](https://beta.atcoder.jp/contests/code-festival-2015-morning-easy/tasks/cf_2015_morning_easy_d) {#d}

### 問題

長さ$N$の文字列$S$が与えられる。文字列$S$中の文字をひとつ選んで削除するという操作を行うことができる。
この$S$から、なんらかの文字列$T$の2回の繰り返しで表現されるような文字列$T \oplus T$を作りたい。必要な最小の操作の回数を答えよ。

### 解法

文字列$S$を文字列$T_1$と$T_2$に分割し、それぞれの部分列で一致するものを探す、という手順を取る。$T_2$の開始位置に関して総当たりする。$T_1$と$T_2$それぞれからいくつ文字を使ったかをindexに、一致する部分列で最長のものの長さを値とするDPを行う。$O(N^3)$。

### 実装

DP tableの更新の向きを間違えてWA。tableをひとつしか持たない場合、indexの大きい側から更新していく必要がある。最近よくやるミスなので気を付けたい。

``` c++
#include <iostream>
#include <vector>
#define repeat_from(i,m,n) for (int i = (m); (i) < (n); ++(i))
using namespace std;
int main() {
    int n; string s; cin >> n >> s;
    int usable = 0;
    repeat_from (l, 1, n) {
        vector<vector<int> > dp(l+1, vector<int>(n-l+1));
        repeat_from (i, 1, l+1) {
            repeat_from (j, 1, n-l+1) {
                dp[i][j] = max(dp[i-1][j], dp[i][j-1]);
                if (s[i-1] == s[l+j-1]) dp[i][j] = max(dp[i][j], dp[i-1][j-1]+1);
            }
        }
        usable = max(usable, dp[l][n-l]);
    }
    cout << n - 2*usable << endl;
    return 0;
}
```
