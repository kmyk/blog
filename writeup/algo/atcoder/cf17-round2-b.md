---
layout: post
redirect_from:
  - /blog/2017/11/27/cf17-round2-b/
date: "2017-11-27T11:46:26+09:00"
tags: [ "competitive", "writeup", "atcoder", "codefestival", "asapro", "sort", "swap" ]
"target_url": [ "https://beta.atcoder.jp/contests/cf17-tournament-round2-open/tasks/asaporo2_b" ]
---

# CODE FESTIVAL 2017 Elimination Tournament Round 2: B - Many Swaps Sorting

## solution

ちゃんと解析してないが、操作回数$O(N^2)$で時間計算量は$O(N^3)$のはず。

次に気付けばよい:

-   $k = 1$の操作をすれば、列のrotateができる
-   $k = N-1$の操作をすれば、(列のrotateと併せて)隣接項のswapができる

swap操作を関数として書いてbubble sortをすれば操作回数が$O(N^3)$になって$700$点の部分点。
連続するswap操作の間のrotateを潰せばよく、そのように上手くすると$O(N^2)$になって満点。

## implementation

``` c++
#include <algorithm>
#include <cassert>
#include <cstdio>
#include <vector>
#define repeat(i, n) for (int i = 0; (i) < int(n); ++(i))
#define repeat_from(i, m, n) for (int i = (m); (i) < int(n); ++(i))
#define whole(x) begin(x), end(x)
using namespace std;

int main() {
    // input
    int n; scanf("%d", &n);
    vector<int> p(n); repeat (i, n) scanf("%d", &p[i]);
    // solve
    vector<int> history;
    auto operate = [&](int k) {
        repeat_from (i, k, n) {
            swap(p[i], p[i - k]);
        }
        history.push_back(k);
    };
    while (p[0] != 0 or not is_sorted(whole(p))) {
        if (p[0] < p[n - 1] and p[0] != 0) {
            operate(n - 1);
        } else {
            operate(1);
        }
    }
    // output
    assert (is_sorted(whole(p)));
    assert (history.size() <= 100000);
    printf("%d\n", int(history.size()));
    for (int result_i : history) {
        printf("%d\n", result_i);
    }
    return 0;
}
```
