---
layout: post
redirect_from:
  - /writeup/algo/hackerrank/university-codesprint-2-game-of-two-stacks/
  - /blog/2017/02/22/hackerrank-university-codesprint-2-game-of-two-stacks/
date: "2017-02-22T23:44:07+09:00"
tags: [ "competitive", "writeup", "hackerrank", "codesprint", "university-codesprint" ]
"target_url": [ "https://www.hackerrank.com/contests/university-codesprint-2/challenges/game-of-two-stacks" ]
---

# HackerRank University CodeSprint 2: Game of Two Stacks

## solution

自然数のstackがふたつと整数$x$が与えられる。
取り出した数の合計が$x$以上になるまで、ふたつのstackから好きに数を取り出してよい。
取り出す数の個数を最大化したとき、それはいくつか。

## solution

しゃくとり法。$O(N + M)$ for each game。

## implementation

``` c++
#include <iostream>
#include <vector>
#define repeat(i,n) for (int i = 0; (i) < int(n); ++(i))
using ll = long long;
using namespace std;
template <class T> void setmax(T & a, T const & b) { if (a < b) a = b; }
int main() {
    int games; cin >> games;
    while (games --) {
        int na, nb, x; cin >> na >> nb >> x;
        vector<int> a(na); repeat (i,na) cin >> a[i];
        vector<int> b(nb); repeat (j,nb) cin >> b[j];
        int result = 0;
        int i = 0;
        ll acc = 0;
        while (i < na and acc + a[i] <= x) {
            acc += a[i];
            ++ i;
        }
        int j = 0;
        while (true) {
            while (j < nb and acc + b[j] <= x) {
                acc += b[j];
                ++ j;
            }
            setmax(result, i + j);
            if (i == 0) {
                break;
            } else {
                -- i;
                acc -= a[i];
            }
        }
        cout << result << endl;
    }
    return 0;
}
```
