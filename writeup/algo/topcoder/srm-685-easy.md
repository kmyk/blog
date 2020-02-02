---
layout: post
alias: "/blog/2016/03/20/srm-685-easy/"
title: "TopCoder SRM 685 Div1 Easy: MultiplicationTable2"
date: 2016-03-20T03:16:56+09:00
tags: [ "competitive", "writeup", "topcoder", "srm", "greedy" ]
---

## Easy: MultiplicationTable2

### 問題

集合$S$とその上の2項演算$\\$ \subseteq (S \times S) \times S$が与えられる。
$S$の部分集合$T \subseteq S$で$\\$$について閉じたものの大きさ$|T|$で、最小のものを答えよ。

### 解法

なんかよく見る感じなやつ。$O(N^3)$。

全ての$i \in S$に関して$\\{ i \\}$から生成される$T$を見る。
$T' \gets T \cup \\{ i \\$ j | i \in T, j \in T \\}$と高々$N$回更新すればよい。ある種の貪欲。

### 実装

stackでもよいやつ。
queueにpushする前に使用済みflag立てたほうが良いのに頻繁に忘れる。

``` c++
#include <bits/stdc++.h>
#define repeat(i,n) for (int i = 0; (i) < (n); ++(i))
template <class T> bool setmin(T & l, T const & r) { if (not (r < l)) return false; l = r; return true; }
using namespace std;
class MultiplicationTable2 { public: int minimalGoodSet(vector<int> table); };

int MultiplicationTable2::minimalGoodSet(vector<int> table) {
    int n = 0; while (n*n != table.size()) ++ n;
    auto op = [&](int i, int j) { return table[i*n+j]; };
    int ans = n;
    repeat (init,n) {
        vector<bool> used(n);
        queue<int> q; q.push(init);
        while (not q.empty()) {
            int i = q.front(); q.pop();
            if (used[i]) continue;
            used[i] = true;
            repeat (j,n) if (used[j]) {
                int k = op(i,j); if (not used[k]) q.push(k);
                ;   k = op(j,i); if (not used[k]) q.push(k);
            }
        }
        setmin<int>(ans, count(used.begin(), used.end(), true));
    }
    return ans;
}
```
