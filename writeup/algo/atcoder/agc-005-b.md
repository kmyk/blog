---
layout: post
alias: "/blog/2017/12/31/agc-005-b/"
date: "2017-12-31T18:42:40+09:00"
tags: [ "competitive", "writeup", "atcoder", "agc", "divide-and-conquer" ]
"target_url": [ "https://beta.atcoder.jp/contests/agc005/tasks/agc005_b" ]
---

# AtCoder Grand Contest 005: B - Minimum Sum

`std::map`に持ちながら端から舐めていってもいける気がする。

## solution

分割統治。数列の区間中で一番小さい数を含むか含まないかで分け、含まないなら小さくなった区間について再帰。区間への分割点の集合を持つようにすれば非再帰になり実装も楽。$O(N \log N)$。

## implementation

``` c++
#include <cstdio>
#include <queue>
#include <set>
#include <tuple>
#include <vector>
#define repeat(i, n) for (int i = 0; (i) < int(n); ++(i))
using ll = long long;
using namespace std;
template <class T> using reversed_priority_queue = priority_queue<T, vector<T>, greater<T> >;

int main() {
    // input
    int n; scanf("%d", &n);
    vector<int> a(n); repeat (i, n) scanf("%d", &a[i]);
    // solve
    reversed_priority_queue<pair<int, int> > que;
    repeat (i, n) {
        que.emplace(a[i], i);
    }
    set<int> sep;
    sep.insert(-1);
    sep.insert(n);
    ll result = 0;
    while (not que.empty()) {
        int a_i, i; tie(a_i, i) = que.top(); que.pop();
        auto it = sep.upper_bound(i);
        int r = *it;
        int l = *(-- it) + 1;
        result += (i - l + 1) * (ll) (r - i) * a_i;
        sep.insert(i);
    }
    // output
    printf("%lld\n", result);
    return 0;
}
```
