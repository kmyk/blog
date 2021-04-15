---
layout: post
redirect_from:
  - /writeup/algo/yukicoder/519/
  - /blog/2017/05/28/yuki-519/
date: "2017-05-28T23:58:57+09:00"
tags: [ "competitive", "writeup", "yukicoder", "branch-and-bound" ]
"target_url": [ "http://yukicoder.me/problems/no/519" ]
---

# Yukicoder No.519 アイドルユニット

一定の余裕を持って通った。
その後撃墜されたが簡単に回復できた。

## solution

分枝限定法。非想定解法。計算量分からず。

端から順に決定していく。
上界は、残っている中でまだ使われてない人同士を使用回数の制限を無視して使う。
つまり$\frac{1}{2} \cdot \sum \\{ \max \\{ f\_{i,j} \mid j \; \text{is unused} \\} \mid i \; \text{is unused} \\}$。

## implementation

``` c++
#include <algorithm>
#include <array>
#include <cassert>
#include <cstdio>
#include <numeric>
#include <vector>
#define repeat(i,n) for (int i = 0; (i) < int(n); ++(i))
#define repeat_from(i,m,n) for (int i = (m); (i) < int(n); ++(i))
#define all(x) begin(x), end(x)
using namespace std;
template <class T> inline void setmax(T & a, T const & b) { a = max(a, b); }

constexpr int max_n = 24;
int n;
array<array<int, max_n>, max_n> f;
array<bool, max_n> used;
int result = 0;
int upper_bound(int i, int score) {
    repeat_from (j, i, n) if (not used[j]) {
        int acc = 0;
        repeat_from (k, i, n) if (not used[k]) {
            setmax(acc, f[j][k]);
        }
        score += (acc + 1) / 2;
    }
    return score;
}
void go(int i, int score) {
    if (i == n) {
        setmax(result, score);
        return;
    }
    if (used[i]) {
        go(i+1, score);
        return;
    }
    if (upper_bound(i, score) <= result) {
        return;
    }
    repeat_from (j, i+1, n) if (not used[j]) {
        used[j] = true;
        go(i+1, score + f[i][j]);
        used[j] = false;
    }
}
int main() {
    scanf("%d", &n);
    assert (n <= max_n);
    repeat (y, n) repeat (x, n) scanf("%d", &f[y][x]);
    { // workaround for the challenge case
        vector<int> tr(n);
        iota(all(tr), 0);
        sort(all(tr), [&](int i, int j) { return accumulate(all(f[i]), 0) > accumulate(all(f[j]), 0); });
        auto prv = f;
        repeat (y, n) repeat (x, n) f[tr[y]][tr[x]] = prv[y][x];
    }
    go(0, 0);
    printf("%d\n", result);
    return 0;
}
```

<hr>

-   2017年  6月 27日 火曜日 14:37:45 JST
    -   撃墜されたので対応
