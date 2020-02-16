---
layout: post
redirect_from:
  - /blog/2017/01/22/fhc-2017-round2-b/
date: "2017-01-22T07:00:08+09:00"
tags: [ "competitive", "writeup", "facebook-hacker-cup" ]
"target_url": [ "https://www.facebook.com/hackercup/problem/1612752199040515/" ]
---

# Facebook Hacker Cup 2017 Round 2: B - Big Top

$216$th. I've got a T-shirt.

## solution

Manage poles with an ordered `set`. For each query, before inserting a pole, remove the unnecessary poles from the set. $O(N \log N)$.

## implementation

``` c++
#include <iostream>
#include <vector>
#include <set>
#include <cmath>
#define repeat(i,n) for (int i = 0; (i) < int(n); ++(i))
using ll = long long;
using namespace std;
const int inf = 1e9+7;
struct pole_t { int x, h; };
bool operator < (pole_t p, pole_t q) { return make_pair(p.x, p.h) < make_pair(q.x, q.h); }
long double area(pole_t p1, pole_t p2) {
    int dx = p2.x - p1.x;
    long double b = max(0.0l, (p1.h + p2.h - dx) / 2.0l);
    long double acc = 0;
    acc += powl(p1.h - b, 2) / 2;
    acc += powl(p2.h - b, 2) / 2;
    acc += dx * b;
    return acc;
}
long double area(pole_t p1, pole_t p2, pole_t p3) {
    return area(p1, p2) + area(p2, p3) - area(p1, p3);
}
int height_at(int x, pole_t p) {
    return max(0, p.h - abs(x - p.x));
}
long double solve(vector<pole_t> const & queries) {
    set<pole_t> poles;
    poles.insert((pole_t) { - inf, 0 });
    poles.insert((pole_t) { + inf, 0 });
    auto left  = [&](pole_t q) { auto it = poles.find(q); return *(-- it); };
    auto right = [&](pole_t q) { auto it = poles.find(q); return *(++ it); };
    long double result = 0;
    long double acc = 0;
    for (pole_t query : queries) {
        poles.insert(query);
        pole_t l = left(query);
        pole_t r = right(query);
        if (query.h <= max(height_at(query.x, l), height_at(query.x, r))) {
            poles.erase(query);
        } else {
            while (l.x != - inf and l.h <= height_at(l.x, query)) {
                acc -= area(left(l), l, r);
                poles.erase(l);
                l = left(query);
            }
            while (r.x != + inf and r.h <= height_at(r.x, query)) {
                acc -= area(l, r, right(r));
                poles.erase(r);
                r = right(query);
            }
            acc += area(l, query, r);
        }
        result += acc;
    }
    return result;
}
int main() {
    int t; cin >> t;
    repeat (i,t) {
        int n; cin >> n;
        vector<pole_t> q(n);
        int ax, bx, cx; cin >> q[0].x >> ax >> bx >> cx;
        int ah, bh, ch; cin >> q[0].h >> ah >> bh >> ch;
        repeat (i,n-1) {
            q[i+1].x = (ax *(ll) q[i].x + bx) % cx + 1;
            q[i+1].h = (ah *(ll) q[i].h + bh) % ch + 1;
        }
        cout << "Case #" << i+1 << ": "; printf("%.4Lf\n", solve(q));
    }
    return 0;
}
```
