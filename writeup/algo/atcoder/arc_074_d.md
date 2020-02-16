---
layout: post
redirect_from:
  - /writeup/algo/atcoder/arc-074-d/
  - /blog/2017/05/20/arc-074-d/
date: "2017-05-20T22:32:37+09:00"
tags: [ "competitive", "writeup", "atcoder", "arc" ]
"target_url": [ "https://beta.atcoder.jp/contests/arc074/tasks/arc074_b" ]
---

# AtCoder Regular Contest 074: D - 3N Numbers

## solution

$[0, r)$から$N$個選んだときの最大値と$[l, 3N)$から$N$個選んだときの最小値をそれぞれ$O(N \log N)$で計算しておいてまとめる。$O(N \log N)$。

$N$個選んだときの最大値最小値には、要素数が$N$という不変条件を持たせて`priority_queue`とかを使う。

## implementation

``` c++
#include <cstdio>
#include <vector>
#include <queue>
#define repeat(i,n) for (int i = 0; (i) < int(n); ++(i))
#define repeat_from(i,m,n) for (int i = (m); (i) < int(n); ++(i))
#define repeat_reverse(i,n) for (int i = (n)-1; (i) >= 0; --(i))
using ll = long long;
using namespace std;
template <class T> inline void setmax(T & a, T const & b) { a = max(a, b); }
template <class T> using reversed_priority_queue = priority_queue<T, vector<T>, greater<T> >;

constexpr ll inf = ll(1e18)+9;
int main() {
    // input
    int n; scanf("%d", &n);
    vector<ll> a(3*n); repeat (i,3*n) scanf("%lld", &a[i]);
    // compute
    vector<ll> front(3*n+1); {
        reversed_priority_queue<ll> que;
        repeat (i,3*n) {
            que.push(a[i]);
            ll b = 0;
            if (que.size() == n+1) {
                b = que.top(); que.pop();
            }
            front[i+1] = front[i] + a[i] - b;
        }
    }
    vector<ll> back(3*n+1); {
        priority_queue<ll> que;
        repeat_reverse (i,3*n) {
            que.push(a[i]);
            ll b = 0;
            if (que.size() == n+1) {
                b = que.top(); que.pop();
            }
            back[i] = back[i+1] + a[i] - b;
        }
    }
    ll result = - inf;
    repeat_from (i,n,2*n+1) {
        setmax(result, front[i] - back[i]);
    }
    // output
    printf("%lld\n", result);
    return 0;
}
```
