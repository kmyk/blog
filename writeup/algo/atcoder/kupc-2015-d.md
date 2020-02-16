---
layout: post
redirect_from:
  - /blog/2015/10/24/kupc-2015-d/
date: 2015-10-24T23:55:30+09:00
tags: [ "kupc", "competitive", "writeup" ]
---

# 京都大学プログラミングコンテスト2015 D - 高橋君の旅行

この手の、とりあえず先に進んでから、手前で操作していたことにする、ってのはよく見るしいい感じの名前が欲しい。

<!-- more -->

## [D - 高橋君の旅行](https://beta.atcoder.jp/contests/kupc2015/tasks/kupc2015_d) {#d}

### 問題

n個の町があり、それぞれに滞在時、出発時の所持金の変動が設定されている。
n日間あって、毎日、滞在か次の町に行くかを選べる。
終了時の金額の最大値を求めよ。

### 解法

町iまで最短の日数で移動するときの必要日数と結果の所持金を求める。余った日数は町iまでで最も滞在時の効用が大きい町に滞在していたことにする。$O(n)$

### 実装

``` c++
#include <iostream>
#include <vector>
#include <cassert>
#define repeat_from(i,m,n) for (int i = (m); (i) < (n); ++(i))
#define repeat(i,n) repeat_from(i,0,n)
typedef long long ll;
using namespace std;
int main() {
    int n; cin >> n;
    vector<ll> a(n+1); repeat (i,n) cin >> a[i];
    vector<ll> b(n+1); repeat (i,n) cin >> b[i];
    ll result = 0;
    ll acc = 0;
    ll best = b[0];
    int k = 0;
    int t = n;
    while (0 <= t) {
        result = max(result, acc + t * best);
        acc += a[k];
        k += 1;
        t -= 1;
        if (t < 0) break;
        if (acc < 0) {
            if (best == 0) break;
            ll dt = (-acc + best-1) / best;
            acc += dt * best;
            assert (0 <= acc and acc < best);
            t -= dt;
        }
        assert (0 <= b[k]);
        best = max(best, b[k]);
    }
    cout << result << endl;
    return 0;
}
```
