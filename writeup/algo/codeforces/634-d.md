---
layout: post
redirect_from:
  - /writeup/algo/codeforces/634-d/
  - /blog/2016/02/29/cf-634-d/
date: 2016-02-29T04:59:55+09:00
tags: [ "competitive", "writeup", "codeforces" ]
---

# 8VC Venture Cup 2016 - Final Round (Div. 1 Edition) D. Package Delivery

## [D. Package Delivery](http://codeforces.com/contest/634/problem/D)

ある区間$[y-1,y)$を走るために使うことのできる燃料は、その区間からタンク容量分前までにあるガソリンスタンドで買った燃料。その中で最小のもの$\min\_{x_i \in [y-n,y)} p_i$を使えばよい。

``` c++
#include <iostream>
#include <vector>
#include <algorithm>
#include <set>
#define repeat(i,n) for (int i = 0; (i) < (n); ++(i))
typedef long long ll;
using namespace std;
struct query_t { ll x, p; bool in; };
bool operator < (query_t a, query_t b) { return a.x < b.x; }
int main() {
    ll d, n; int m; cin >> d >> n >> m;
    vector<query_t> qs(2*m+3);
    repeat (i,m) {
        ll x, p; cin >> x >> p;
        qs[2*i  ] = { x,     p, true  };
        qs[2*i+1] = { x + n, p, false };
    }
    qs[2*m  ] = { 0, 0, true  };
    qs[2*m+1] = { n, 0, false };
    qs[2*m+2] = { d, 0, true  };
    sort(qs.begin(), qs.end());
    ll ans = 0;
    ll last = 0;
    multiset<ll> p;
    for (query_t q : qs) {
        if (last < q.x) {
            if (p.empty()) {
                ans = -1;
                break;
            }
            ans += (q.x - last) * *p.begin();
            last = q.x;
        }
        if (q.in) {
            p.insert(q.p);
        } else {
            auto it = p.find(q.p);
            p.erase(it);
        }
    }
    cout << ans << endl;
    return 0;
}
```
