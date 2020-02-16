---
layout: post
redirect_from:
  - /blog/2016/05/01/hackerrank-world-codesprint-april-gena/
date: 2016-05-01T12:20:46+09:00
tags: [ "competitive", "writeup", "hackerrank", "world-codesprint" ]
"target_url": [ "https://www.hackerrank.com/contests/world-codesprint-april/challenges/gena" ]
---

# HackerRank World Codesprint April: Gena Playing Hanoi

## problem

棒の数を$4$本に増やしたハノイの塔の、円盤がいくらか動かされた状態が与えられる。
その状態から完成させるには最短で何手かかるか。

## solution

Simply search with $O(4^N)$.

The size of the possible space $|V| = 4^N \le 4^{10} \approx 10^6$.
So it will be done in time.

## implementation

``` c++
#include <iostream>
#include <vector>
#include <array>
#include <queue>
#include <cmath>
#define repeat(i,n) for (int i = 0; (i) < (n); ++(i))
#define repeat_reverse(i,n) for (int i = (n)-1; (i) >= 0; --(i))
using namespace std;
int pack(vector<int> const & xs) {
    int y = 0;
    for (int x : xs) y = 4 * y + x;
    return y;
}
vector<int> unpack(int y, int n) {
    vector<int> xs(n);
    repeat_reverse (i,n) {
        xs[i] = y % 4;
        y /= 4;
    }
    return xs;
}
int main() {
    // input only n
    int n; cin >> n;
    // bfs
    vector<int> dp(pow(4, n), -1);
    queue<int> que;
    que.push(pack(vector<int>(n, 0)));
    dp[      pack(vector<int>(n, 0))] = 0;
    while (not que.empty()) {
        int px = que.front(); que.pop();
        vector<int> x = unpack(px, n);
        array<bool,4> used = {};
        repeat (i,n) if (not used[x[i]]) {
            int t = x[i];
            used[x[i]] = true;
            repeat (j,4) if (not used[j]) {
                x[i] = j;
                int py = pack(x);
                if (dp[py] == -1) {
                    dp[py] = dp[px] + 1;
                    que.push(py);
                }
            }
            x[i] = t;
        }
    }
    // input
    vector<int> a(n); repeat (i,n) { cin >> a[i]; -- a[i]; }
    // output
    cout << dp[pack(a)] << endl;
    return 0;
}
```
