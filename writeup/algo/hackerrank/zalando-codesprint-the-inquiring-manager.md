---
layout: post
redirect_from:
  - /writeup/algo/hackerrank/zalando-codesprint-the-inquiring-manager/
  - /blog/2016/06/05/hackerrank-zalando-codesprint-the-inquiring-manager/
date: 2016-06-05T19:17:02+09:00
tags: [ "competitive", "writeup", "hackerrank", "priority-queue" ]
"target_url": [ "https://www.hackerrank.com/contests/zalando-codesprint/challenges/the-inquiring-manager" ]
---

# HackerRank Zalando CodeSprint: The Inquiring Manager

## problem

以下の$2$種類のクエリを処理せよ。

-   時刻$T$に、値段$P$の注文が発生したことが知らされる
-   時刻$(T-60, T]$で発生する注文の中で最も大きい値段を答える

## solution

Use priority queue. $O(N \log N)$.

Sort queries with the time and the type, and add the hypothesis: the type-$1$ queries precedes type-$2$ queries if they has the same time $t$.
Then for a type-$1$ query, add the order the priority queue.
For a type-$2$ query. See the order whose price is highest in the queue.
If the order is expired, then pop and ignore it and see the next one, else answer it.

## implementation

``` c++
#include <iostream>
#include <vector>
#include <algorithm>
#include <queue>
#include <functional>
#define repeat(i,n) for (int i = 0; (i) < (n); ++(i))
typedef long long ll;
using namespace std;
struct query_t { int type; ll p, t; };
int main() {
    int n; cin >> n;
    vector<query_t> qs(n);
    for (query_t & q : qs) {
        cin >> q.type;
        if (q.type == 1) {
            cin >> q.p >> q.t;
        } else if (q.type == 2) {
            cin >> q.t;
        }
    }
    sort(qs.begin(), qs.end(), [](query_t a, query_t b) {
        return make_pair(a.t, a.type) < make_pair(b.t, b.type);
    });
    auto cmp = [](query_t a, query_t b) {
        return a.p < b.p;
    };
    priority_queue<query_t, priority_queue<query_t>::container_type, decltype(cmp)> que(cmp);
    for (query_t q : qs) {
        if (q.type == 1) {
            que.push(q);
        } else if (q.type == 2) {
            while (not que.empty() and que.top().t <= q.t - 60) que.pop();
            int ans = -1;
            if (not que.empty()) ans = que.top().p;
            cout << ans << endl;
        }
    }
    return 0;
}
```
