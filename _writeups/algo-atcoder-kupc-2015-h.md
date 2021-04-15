---
layout: post
redirect_from:
  - /writeup/algo/atcoder/kupc-2015-h/
  - /blog/2015/10/24/kupc-2015-h/
date: 2015-10-24T23:55:47+09:00
tags: [ "kupc", "competitive", "writeup" ]
---

# 京都大学プログラミングコンテスト2015 H - Bit Count

kupc楽しかったです。京都オンサイトで解きました。7完できて34位だったのかなり嬉しいです。ありがとうございました。


<hr>


残り1分切ってから通した。ぎりぎり。

<!-- more -->

## [H - Bit Count](https://beta.atcoder.jp/contests/kupc2015/tasks/kupc2015_h) {#h}

### 問題

正整数Nが与えられる。XとX+Nの2進表記中の1の数が等しくなるような正整数Xで最小のものを求めよ。

### 解法

最下位桁から再帰的にXを決めていく。
Xを決めたことにより変化したNと、決定済みのX及び確定済みのN+Xの中の1の数の差でメモ化する。
Nの最下位桁が0である場合は適当にshiftしてよい。

### 解答

``` c++
#include <iostream>
#include <map>
#include <utility>
#define repeat_from(i,m,n) for (int i = (m); (i) < (n); ++(i))
#define repeat(i,n) repeat_from(i,0,n)
typedef long long ll;
using namespace std;
constexpr ll inf = 10000000000000000ll;
ll solve(ll n, int used, int limit, map<pair<ll,int>,ll> & memo) {
    auto key = make_pair(n, used);
    if (memo.count(key)) return memo[key];
    if (limit < used) return inf;
    if (used == __builtin_popcountll(n)) return 0;
    if (n == 0) return inf;
    int shift = 0;
    while (not (n & 1)) { n >>= 1; shift += 1; }
    ll x = inf;
    x = min(x, solve(n >> 1, used - 1, limit, memo) << 1);
    x = min(x, (solve((n + 1) >> 1, used + 1, limit, memo) << 1) + 1);
    if (x != inf) x <<= shift;
    return memo[key] = x;
}
int main() {
    int datasets; cin >> datasets;
    repeat (dataset, datasets) {
        ll n; cin >> n;
        map<pair<ll,int>,ll> memo;
        cout << solve(n, 0, __builtin_popcountll(n), memo) << endl;
    }
    return 0;
}
```
