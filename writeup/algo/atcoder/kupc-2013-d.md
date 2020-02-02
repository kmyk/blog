---
layout: post
alias: "/blog/2017/05/12/kupc-2013-d/"
date: "2017-05-12T20:28:51+09:00"
title: "京都大学プログラミングコンテスト2013: D - カーペット"
tags: [ "competitive", "writeup", "atcoder", "kupc", "stack" ]
"target_url": [ "https://beta.atcoder.jp/contests/kupc2013/tasks/kupc2013_d" ]
---

これはノーミス。

## solution

1.  まず各列について横幅$1$のカーペットを敷く
2.  可能な限り併合する

これはstackを上手く使えば$O(N)$。
左から順に見ていき、その時点で(谷によってかくされていなくて)見えるカーペットの縦幅の集合を持っておくようにし、各列でこれを更新していく。

## implementation

``` c++
#include <cstdio>
#include <vector>
#include <stack>
#define repeat(i,n) for (int i = 0; (i) < int(n); ++(i))
using namespace std;
int main() {
    int n; scanf("%d", &n);
    vector<int> a(n); repeat (i,n) scanf("%d", &a[i]);
    stack<int> stk;
    int cnt = 0;
    repeat (i,n) {
        while (not stk.empty() and a[i] < stk.top()) {
            stk.pop();
        }
        if (stk.empty() or stk.top() != a[i]) {
            stk.push(a[i]);
            cnt += 1;
        }
    }
    printf("%d\n", cnt);
    return 0;
}
```
