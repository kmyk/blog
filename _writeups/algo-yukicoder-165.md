---
layout: post
redirect_from:
  - /writeup/algo/yukicoder/165/
  - /blog/2016/12/13/yuki-165/
date: "2016-12-13T18:26:08+09:00"
tags: [ "competitive", "writeup", "yukicoder", "shakutori-method" ]
"target_url": [ "http://yukicoder.me/problems/no/165" ]
---

# Yukicoder No.165 四角で囲え！

## solution

片側固定してしゃくとり法。$O(N^3)$。

単純に左上と右下について全列挙すると、どうやっても$O(N^4)$になる。
$3$つ決めてもう$1$つは一意に定まる、のようにして$O(N^3)$にしたい。

$y$軸について区間$[l_y, r_y)$を固定し、$x$軸について左端$l_x$をとれば、右端$r_x$は一意にさだまる。
このようにするしゃくとり法で、$O(N^3)$となる。

座標圧縮をしておくと楽だが必須ではない。

## implementation

``` c++
#include <iostream>
#include <vector>
#include <algorithm>
#include <numeric>
#include <map>
#define repeat(i,n) for (int i = 0; (i) < int(n); ++(i))
#define whole(f,x,...) ([&](decltype((x)) whole) { return (f)(begin(whole), end(whole), ## __VA_ARGS__); })(x)
typedef long long ll;
using namespace std;
template <class T> void setmax(T & a, T const & b) { if (a < b) a = b; }

template <typename T>
map<T,int> coordinate_compression_map(vector<T> const & xs) {
    int n = xs.size();
    vector<int> ys(n);
    whole(iota, ys, 0);
    whole(sort, ys, [&](int i, int j) { return xs[i] < xs[j]; });
    map<T,int> f;
    for (int i : ys) {
        if (not f.count(xs[i])) { // make unique
            int j = f.size();
            f[xs[i]] = j; // f[xs[i]] has a side effect, increasing the f.size()
        }
    }
    return f;
}
template <typename T>
vector<int> apply_compression(map<T,int> const & f, vector<T> const & xs) {
    int n = xs.size();
    vector<int> ys(n);
    repeat (i,n) ys[i] = f.at(xs[i]);
    return ys;
}

int main() {
    int n, b; cin >> n >> b;
    vector<int> x(n), y(n), p(n); repeat (i,n) cin >> x[i] >> y[i] >> p[i];
    x = apply_compression(coordinate_compression_map(x), x);
    y = apply_compression(coordinate_compression_map(y), y);
    vector<int> j(n);
    whole(iota, j, 0);
    whole(sort, j, [&](int i, int j) { return x[i] < x[j]; });
    int ans = 0;
    repeat (ry,n+1) repeat (ly,ry) {
        int li = 0, ri = 0;
        int lx = 0, rx = 0;
        int cnt = 0, sum_p = 0;
        while (rx < n) {
            ++ rx;
            while (ri < n and x[j[ri]] < rx) {
                if (ly <= y[j[ri]] and y[j[ri]] < ry) {
                    cnt += 1;
                    sum_p += p[j[ri]];
                }
                ++ ri;
            }
            while (b < sum_p) {
                ++ lx;
                while (li < n and x[j[li]] < lx) {
                    if (ly <= y[j[li]] and y[j[li]] < ry) {
                        cnt -= 1;
                        sum_p -= p[j[li]];
                    }
                    ++ li;
                }
            }
            setmax(ans, cnt);
        }
    }
    cout << ans << endl;
    return 0;
}
```
