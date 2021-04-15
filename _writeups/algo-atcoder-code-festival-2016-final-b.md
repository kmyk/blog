---
layout: post
redirect_from:
  - /writeup/algo/atcoder/code-festival-2016-final-b/
  - /blog/2016/11/28/code-festival-2016-final-b/
date: "2016-11-28T02:15:08+09:00"
tags: [ "competitive", "writeup", "atcoder", "codefestival", "greedy" ]
"target_url": [ "https://beta.atcoder.jp/contests/cf16-final-open/tasks/codefestival_2016_final_b" ]
---

# CODE FESTIVAL 2016 Final: B - Exactly N points

分からなくて焦ったのだが、なんとなく書いてみたら通った。

## solution

上限を決め打ちして大きいものから貪欲に採用する。上限を二分探索すれば$O(\sqrt{N} \log{N})$だが、小さい方から順に試しても$O(N)$。

## implementation

``` c++
#include <iostream>
#include <vector>
#define repeat(i,n) for (int i = 0; (i) < (n); ++(i))
using namespace std;
vector<int> func(int n, int k) {
    vector<int> result;
    for (; k >= 1 and n != 0; k = min(k-1, n)) {
        if (n >= k) {
            n -= k;
            result.push_back(k);
        }
    }
    if (n) result.clear();
    return result;
}
int main() {
    int n; cin >> n;
    repeat (k,n+1) {
        vector<int> xs = func(n, k);
        if (not xs.empty()) {
            for (int x : xs) cout << x << endl;
            break;
        }
    }
    return 0;
}
```
