---
layout: post
alias: "/blog/2017/08/15/srm-719-easy/"
date: "2017-08-15T11:50:48+09:00"
tags: [ "competitive", "writeup", "topcoder", "srm" ]
---

# TopCoder SRM 719 Div1 Easy: LongMansionDiv1

問題文がこどふぉのように難しい。
どうでもいいストーリーを付けるな。
$x$-th rowと$y$-th columnなのをやめろ。

## solution

あるrowを選んで$y$方向の移動はすべてそこで行うようにする。選ぶrowについて総当たり。$O(N)$。

## implementation

``` c++
#include <bits/stdc++.h>
#define repeat(i,n) for (int i = 0; (i) < (n); ++(i))
#define whole(x) begin(x), end(x)
typedef long long ll;
using namespace std;
template <class T> inline void setmin(T & a, T const & b) { a = min(a, b); }
class LongMansionDiv1 { public: long long minimalTime(vector<int> t, int sX, int sY, int eX, int eY); };

constexpr ll inf = ll(1e18)+9;
ll LongMansionDiv1::minimalTime(vector<int> t, int sX, int sY, int eX, int eY) {
    int w = t.size();
    vector<int> acc(w + 1);
    partial_sum(whole(t), acc.begin() + 1);
    ll result = inf;
    repeat (x, w) {
        ll it = 0;
        it += acc[max(x, sX) + 1] - acc[min(x, sX)];
        it += acc[max(x, eX) + 1] - acc[min(x, eX)];
        it += t[x] *(ll) (abs(eY - sY) - 1);
        setmin(result, it);
    }
    return result;
}
```
