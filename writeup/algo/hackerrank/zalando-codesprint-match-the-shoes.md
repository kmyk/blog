---
layout: post
redirect_from:
  - /blog/2016/06/05/hackerrank-zalando-codesprint-match-the-shoes/
date: 2016-06-05T19:16:33+09:00
tags: [ "competitive", "writeup", "hackerrank" ]
"target_url": [ "https://www.hackerrank.com/contests/zalando-codesprint/challenges/match-the-shoes" ]
---

# HackerRank Zalando CodeSprint: Match the Shoes

## problem

$N$種類の靴の購買の履歴が与えられる。
被購入回数の多い種類に並べ、上から$K$種類を出力せよ。
ただし、購入回数が同じならIDの順に並べる。

## solution

Sort with $(- A_i, i)$. $O(N \log N)$.

## implementation

``` c++
#include <iostream>
#include <vector>
#include <algorithm>
#define repeat(i,n) for (int i = 0; (i) < (n); ++(i))
using namespace std;
int main() {
    int k, m, n; cin >> k >> m >> n;
    vector<int> cnt(m);
    repeat (i,n) {
        int a; cin >> a;
        cnt[a] += 1;
    }
    vector<int> xs(m); repeat (i,m) xs[i] = i;
    sort(xs.begin(), xs.end(), [&](int x, int y) {
        return make_pair(- cnt[x], x) < make_pair(- cnt[y], y);
    });
    repeat (i,k) cout << xs[i] << endl;
    return 0;
}
```
