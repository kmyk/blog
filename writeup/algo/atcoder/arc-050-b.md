---
layout: post
alias: "/blog/2016/04/03/arc-050-b/"
title: "AtCoder Regular Contest 050 B - 花束"
date: 2016-04-03T03:35:19+09:00
tags: [ "competitive", "writeup", "atcoder", "arc", "linear-programming", "simplex-method", "boost", "ublas", "scipy" ]
"target_url": [ "https://beta.atcoder.jp/contests/arc050/tasks/arc050_b" ]
---

## 解法

-   min: $- p - q$
-   sub to:
    -   $xp + q \le R$
    -   $p + yq \le B$
    -   $0 \le p, q$

線形緩和(整数制約を無視)し、simplex法等で適当に解いて、その(非整数)解の近傍(整数)を知らべる。

## 実装

### scipy

atcoder上ではscipyが古い都合上動かない。
`scipy.optimize.linprog`が入ったのが遅いため。
ubuntuのltsでaptで入れてるから仕方がない。

``` python
#!/usr/bin/env python3
import math
import scipy.optimize
r, b = map(int,input().split())
x, y = map(int,input().split())

# linear relaxation
c = [-1, -1]
a_ub = [[x, 1], [1, y]]
b_ub = [r, b]
bound = (0, None)
lpans = scipy.optimize.linprog(c, A_ub=a_ub, b_ub=b_ub, bounds=(bound, bound))

ans = 0
for i in range(-100,100+1):
    p = int(lpans.x[0]) + i
    if p < 0:
        continue
    for j in range(-100,100+1):
        q = int(lpans.x[1]) + j
        if q < 0:
            continue
        if p * x + q <= r and p + q * y <= b:
            ans = max(ans, p + q)
print(ans)
```

### ublas

軸との交点等をまったく考えてなくてWAり、つらい思いをした。

``` c++
#include <iostream>
#include <boost/numeric/ublas/matrix.hpp>
#include <boost/numeric/ublas/vector.hpp>
#include <boost/numeric/ublas/lu.hpp>
#define repeat(i,n) for (int i = 0; (i) < (n); ++(i))
#define repeat_from(i,m,n) for (int i = (m); (i) < (n); ++(i))
typedef long long ll;
using namespace std;
template <class T> bool setmax(T & l, T const & r) { if (not (l < r)) return false; l = r; return true; }
namespace ublas = boost::numeric::ublas;
typedef ublas::vector<long double> vec;
typedef ublas::matrix<long double> mat;
int main() {
    ll b1, b2, a11, a22; cin >> b1 >> b2 >> a11 >> a22;
    ll ans = 0;
    repeat (i,3) {
        ll c1, c2;
        if (i == 0) {
            mat a(2,2); vec b(2);
            a(0,0) = a11; a(0,1) =   1;    b[0] = b1;
            a(1,0) =   1; a(1,1) = a22;    b[1] = b2;
            ublas::permutation_matrix<> pm(a.size1());
            ublas::lu_factorize(a,pm);
            ublas::lu_substitute(a,pm,b);
            c1 = b[0];
            c2 = b[1];
        } else if (i == 1) {
            c1 = 0;
            c2 = min(b1, b2 / a22);
        } else if (i == 2) {
            c1 = min(b2, b1 / a11);
            c2 = 0;
        }
        repeat_from (dx,-100,100+1) {
            ll x = c1 + dx;
            if (x < 0) continue;
            repeat_from (dy,-100,100+1) {
                ll y = c2 + dy;
                if (y < 0) continue;
                if (a11 * x + y <= b1 and x + a22 * y <= b2) {
                    setmax(ans, x + y);
                }
            }
        }
    }
    cout << ans << endl;
    return 0;
}
```
