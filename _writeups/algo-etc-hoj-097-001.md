---
layout: post
redirect_from:
  - /writeup/algo/etc/hoj-097-001/
  - /blog/2017/07/07/hoj-097-001/
date: "2017-07-07T23:30:04+09:00"
tags: [ "competitive", "writeup", "hoj", "shakutori-method" ]
---

# Hamako Online Judge #097 ukuku09: 001 - photography

-   <https://hoj.hamako-ths.ed.jp/onlinejudge/contest/97/problems/1>
-   <https://hoj.hamako-ths.ed.jp/onlinejudge/problems/766>


## solution

累積和の列をsortして潰してしゃくとり法や二分探索。$O(N \log N)$。

数列$X$に対し累積和$a$を取ると答えは$\max \\{ r - l \mid a\_r - a\_l \ge P \\}$。
添字$l$を固定したときに$a\_r \ge P + a\_l$であるような最大の$r$を求められればよい。
$r \lt r'$で$a\_r \le a\_{r'}$なら$(r, a\_r)$はまったく不要であることを使って、そのようなものを除いて列$a\_{r\_k}$を作ればこれは単調増加列。この上で二分探索とかをすればよい。

## implementation

``` c++
#include <cstdio>
#include <map>
#include <numeric>
#include <vector>
#define repeat(i, n) for (int i = 0; (i) < int(n); ++(i))
#define whole(f, x, ...) ([&](decltype((x)) whole) { return (f)(begin(whole), end(whole), ## __VA_ARGS__); })(x)
using ll = long long;
using namespace std;
template <class T> inline void setmax(T & a, T const & b) { a = max(a, b); }
template <class T> inline void setmin(T & a, T const & b) { a = min(a, b); }

int main() {
    // input
    int n; ll p; scanf("%d%lld", &n, &p);
    vector<ll> x(n); repeat (i, n) scanf("%lld", &x[i]);
    // solve
    vector<ll> acc(n + 1); whole(partial_sum, x, acc.begin() + 1);
    map<ll, int> left, right;
    repeat (i, n + 1) {
        if (not  left.count(acc[i])) {  left[acc[i]] = i; } else { setmin( left[acc[i]], i); }
        if (not right.count(acc[i])) { right[acc[i]] = i; } else { setmax(right[acc[i]], i); }
    }
    for (auto it = right.begin(); ; ) {
        auto next = it; ++ next;
        if (next == right.end()) break;
        ll a = it->first;
        ll b = next->first;
        if (a < b and right[a] <= right[b]) {
            right.erase(it);
            it = right.find(b);
            if (it != right.begin()) -- it;
        } else {
            it = next;
        }
    }
    int result = 0;
    auto r = right.begin();
    auto l = left.begin();
    for (; l != left.end(); ++ l) {
        while (r != right.end() and r->first - l->first < p) ++ r;
        if (r == right.end()) break;
        setmax(result, r->second - l->second);
    }
    // output
    printf("%d\n", result);
    return 0;
}
```
