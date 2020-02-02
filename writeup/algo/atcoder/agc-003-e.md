---
layout: post
alias: "/blog/2017/04/28/agc-003-e/"
date: "2017-04-28T05:44:25+09:00"
title: "AtCoder Grand Contest 003: E - Sequential operations on Sequence"
tags: [ "competitive", "writeup", "atcoder", "agc" ]
"target_url": [ "https://beta.atcoder.jp/contests/agc003/tasks/agc003_e" ]
---

途中で詰まったのでeditorialを読んだが、分かりにくかったので後半は読んでない。

## solution

操作列を逆順に見て畳んでいく。
計算量の解析はよく分からないが、保守的に見て$O(Q^2 \log Q + N)$ではある。

まず、操作列$A$は狭義単調増加としてよい。
$A\_i \ge A\_{i+1}$であれば、$A\_i$による操作は無視してよいため。
不要な操作を除去するのはstackを使うのが楽。

操作$A\_{i+1} = qA\_i + r$は、現在の数列(長さは$A\_i$)の複製を$q-1$回末尾に追加しさらに先頭から$r$項を末尾に追加するような操作となる。
例えば$A = (5, 8, 11, 29)$なら以下。

```
 5: 12345
 8: 12345 123
11: 12345 123 123
29: 12345 123 123 12345 123 123 12345 12
```

これを逆順に行う。その項がどこから来たかを考えその出処に足し込む。
操作$A\_{i+1} = qA\_i + r$は、操作後の数列の$j$項目は現在の数列(長さは$A\_{i+1}$)の$k$項目($k \equiv j \pmod{A\_i}$)の和とする。
これは同じ例に対し以下のようになり、最後の行は問題全体の答えになる。

```
29: 11111 111 111 11111 111 111 11111 11
11: 33333 332 222
 8: 55533 332
 5: 88733
```

これを愚直に行うと$O(\sum\_{i \lt Q} A_i)$であり間に合わない。
そこで、最終的な列の始切片で長さ$l$のものが$k$個あるという情報を`std::map`等で管理し、各操作$A\_i$でこれを切り分けていくようにする。
計算量の解析は上手くできなかったが、十分な速度で動作する。
同じ例に対し以下。

```
29: 29*1
11: 11*2 7*1
 8: 8*2 7 3*2
 5: 5*3 3*4 2*1
-> 12345 12345 12345 123 123 123 123 12 12
```

## implementation

``` c++
#include <cstdio>
#include <vector>
#include <algorithm>
#include <map>
#include <queue>
#include <tuple>
#include <cassert>
#define repeat(i,n) for (int i = 0; (i) < int(n); ++(i))
#define repeat_reverse(i,n) for (int i = (n)-1; (i) >= 0; --(i))
#define whole(f,x,...) ([&](decltype((x)) whole) { return (f)(begin(whole), end(whole), ## __VA_ARGS__); })(x)
using ll = long long;
using namespace std;

int main() {
    // input
    int n, q; scanf("%d%d", &n, &q);
    vector<ll> a(q); repeat (i,q) scanf("%lld", &a[i]);
    { // remove unnecessary queries
        vector<ll> b;
        b.push_back(n);
        repeat (i,q) {
            while (not b.empty() and a[i] <= b.back()) {
                b.pop_back();
            }
            b.push_back(a[i]);
        }
        a = b;
        q = b.size();
    }
    assert (whole(is_sorted, a));
    // compute in reverse order
    vector<ll> cnt(n);
    map<ll, ll> que;
    que[a.back()] += 1;
    repeat_reverse (i,q-1) {
        ll t = 0;
        while (not que.empty() and que.rbegin()->first >= a[i]) {
            ll delta, k; tie(delta, k) = *que.rbegin(); que.erase(delta);
            ll q = delta / a[i];
            t += k*q;
            ll r = delta % a[i];
            if (r == 0) {
                // nop
            } else if (r <= a[0]) {
                cnt[r-1] += k;
            } else {
                que[r] += k;
            }
        }
        que[a[i]] += t;
    }
    assert (que.size() == 1 and que.begin()->first == a[0]);
    cnt[a[0]-1] += que.begin()->second;
    repeat_reverse (i,n-1) {
        cnt[i] += cnt[i+1];
    }
    // output
    repeat (i,n) {
        printf("%lld\n", cnt[i]);
    }
    return 0;
}
```
