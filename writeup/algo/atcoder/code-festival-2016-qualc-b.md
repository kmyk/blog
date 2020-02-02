---
layout: post
alias: "/blog/2016/10/23/code-festival-2016-qualc-b/"
date: "2016-10-23T23:00:12+09:00"
title: "CODE FESTIVAL 2016 qual C: B - K個のケーキ / K Cakes"
tags: [ "competitive", "writeup", "atcoder", "codefestival", "greedy" ]
"target_url": [ "https://beta.atcoder.jp/contests/code-festival-2016-qualc/tasks/codefestival_2016_qualC_b" ]
---

## solution

貪欲。$O(K \log T)$。

$a_1 + a_2 + \dots + a_r = K \le 10000$の制約があるので、ケーキをひとつずつ食べれば間に合う。
直前に食べた種類を除いてケーキを区別するのはその残数だけであり、たくさん残ってるものから食べるのが妥当なので、そのような貪欲にしてよい。

## implementation

``` c++
#include <iostream>
#include <queue>
#include <tuple>
#define repeat(i,n) for (int i = 0; (i) < (n); ++(i))
using namespace std;
int main() {
    int k, t; cin >> k >> t;
    priority_queue<pair<int,int> > que;
    repeat (i, t) {
        int a; cin >> a;
        que.emplace(a, i);
    }
    int ans = 0;
    int last = -1;
    while (not que.empty()) {
        int a, i; tie(a, i) = que.top(); que.pop();
        if (i != last) {
            last = i;
            a -= 1;
            if (a) que.emplace(a, i);
        } else {
            if (que.empty()) { ans += a; break; }
            int b, j; tie(b, j) = que.top(); que.pop();
            last = j;
            b -= 1;
            que.emplace(a, i);
            if (b) que.emplace(b, j);
        }
    }
    cout << ans << endl;
    return 0;
}
```
