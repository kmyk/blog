---
redirect_from:
  - /writeup/algo/atcoder/njpc2017-d/
layout: post
date: 2018-07-13T13:37:46+09:00
tags: [ "competitive", "writeup", "atcoder", "njpc", "inversion-number" ]
"target_url": [ "https://beta.atcoder.jp/contests/njpc2017/tasks/njpc2017_d" ]
---

# NPCJ2017: D - NMパズル

## note

解法は$O(N^2 + M^2)$で解けば十分なので簡単。
でもバグらせた。$NM(M-1)/2$の$/2$を忘れてた。反省しています。

## implementation

``` c++
#include <bits/stdc++.h>
#define REP(i, n) for (int i = 0; (i) < int(n); ++ (i))
#define ALL(x) begin(x), end(x)
using namespace std;
template <typename X, typename T> auto vectors(X x, T a) { return vector<T>(x, a); }
template <typename X, typename Y, typename Z, typename... Zs> auto vectors(X x, Y y, Z z, Zs... zs) { auto cont = vectors(y, z, zs...); return vector<decltype(cont)>(x, cont); }
template <typename T> ostream & operator << (ostream & out, vector<T> const & xs) { REP (i, int(xs.size()) - 1) out << xs[i] << ' '; if (not xs.empty()) out << xs.back(); return out; }

vector<int> get_invertion_number_inv(int n, int k) {
    vector<int> a(n);
    iota(ALL(a), 0);
    vector<int> b;
    REP (i, n) {
        int j = min<int>(k, a.size() - 1);
        k -= j;
        b.push_back(a[j]);
        a.erase(a.begin() + j);
    }
    return b;
}

int main() {
    // input
    int h, w, k; cin >> h >> w >> k;

    // solve
    int ky = min(k, h * (h - 1) / 2 * w) / w;
    k -= w * ky;
    vector<int> cy = get_invertion_number_inv(h, ky);
    auto c = vectors(h, w, int());
    REP (y, h) {
        int kx = min(k, w * (w - 1) / 2);
        k -= kx;
        vector<int> cx = get_invertion_number_inv(w, kx);
        REP (x, w) {
            c[y][x] = cy[y] * w + cx[x] + 1;
        }
    }
    assert (k == 0);

    // output
    REP (y, h) {
        cout << c[y] << endl;
    }
    return 0;
}
```
