---
layout: post
alias: "/blog/2016/05/28/abc-038-d/"
title: "AtCoder Beginner Contest 038 D - プレゼント"
date: 2016-05-28T23:00:04+09:00
tags: [ "competitive", "writeup", "atcoder", "abc", "binary-indexed-tree", "range-max-query", "greedy" ]
"target_url": [ "https://beta.atcoder.jp/contests/abc038/tasks/abc038_d" ]
---

同じ`y`をまとめてやるのを忘れていたのと、`y`と`x`を混乱させたのとで、WAを生やした。
特に後者は$2$ケースしかWAにならなかったので原因の判断にとても困った。

## 追記

-   やってることはLIS (longest increasing subsequence)を求めるのと同じ
-   $(h_i, - w_i)$でsortしておけばまとめる処理がいらなかった

## solution

ある種の貪欲。range max queryの列になおしてbinary indexed treeやsegment treeでさばく。$O(N \log \min \\{ H, W \\})$。

まず箱をその縦幅$h_i$でsortし、昇順に見ていく。
これにより、今見ている箱の中に入れるものとして、今までに見た箱のみを考えればよいという仮定を得る。
入れる箱は、(その中に入れられる横幅$w_i$な箱のなかで)中身に最も沢山箱が入っている箱を選べばよい。

つまり、横幅$w$である箱の中に入る最大の箱の個数$n_w$として、$n_w \gets \max \\{ n_j \mid j \lt w_i \\} + 1$という更新を縦幅$h_i$が小さいものから順に繰り返す。
ただし、縦幅が同じ箱群に関しては、これを同時に更新する。

## implementation

``` c++
#include <iostream>
#include <vector>
#include <algorithm>
#include <functional>
#define repeat(i,n) for (int i = 0; (i) < (n); ++(i))
template <class T> bool setmax(T & l, T const & r) { if (not (l < r)) return false; l = r; return true; }
using namespace std;

template <typename T>
struct binary_indexed_tree { // on monoid
    vector<T> a;
    T unit;
    function<T (T,T)> append; // associative
    template <typename F>
    binary_indexed_tree(size_t n, T a_unit, F a_append) : a(n, a_unit), unit(a_unit), append(a_append) {}
    void point_append(size_t i, T w) { // a[i] += w
        for (size_t j = i+1; j <= a.size(); j += j & -j) a[j-1] = append(a[j-1], w);
    }
    int initial_range_concat(size_t i) { // sum [0, i)
        T acc = unit;
        for (size_t j = i; 0 < j; j -= j & -j) acc = append(acc, a[j-1]);
        return acc;
    }
};

struct point_t { int y, x; };
pair<int,int> to_pair(point_t a) { return { a.y, a.x }; }
bool operator < (point_t a, point_t b) { return to_pair(a) < to_pair(b); }
istream & operator >> (istream & in, point_t & a) { return in >> a.x >> a.y; }

int main() {
    int n; cin >> n;
    vector<point_t> ps(n); repeat (i,n) cin >> ps[i];
    sort(ps.begin(), ps.end()); // with y
    int x_max = 0; for (auto p : ps) setmax(x_max, p.x);
    binary_indexed_tree<int> bit(x_max + 1, 0, [&](int a, int b) { return max(a, b); });
    vector<int> temp(n);
    for (int i = 0; i < n; ) {
        for (int j = i; j < n and ps[j].y == ps[i].y; ++ j) {
            temp[j] = bit.initial_range_concat(ps[j].x) + 1;
        }
        int j;
        for (j = i; j < n and ps[j].y == ps[i].y; ++ j) {
            bit.point_append(ps[j].x, temp[j]);
        }
        i = j;
    }
    cout << bit.initial_range_concat(x_max + 1) << endl;
    return 0;
}
```

---

-   Sun May 29 11:17:43 JST 2016
    -   追記
