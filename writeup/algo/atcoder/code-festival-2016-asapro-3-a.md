---
layout: post
alias: "/blog/2016/12/12/code-festival-2016-asapro-3-a/"
date: "2016-12-12T14:28:58+09:00"
title: "CODE FESTIVAL 2016 Tournament Round 3: A - ストラックアウト / Struck Out"
tags: [ "competitive", "writeup", "atcoder", "codefestival", "sliding-window-minimum", "range-maximum-query", "dp" ]
"target_url": [ "https://beta.atcoder.jp/contests/cf16-tournament-round3-open/tasks/asaporo_d" ]
---

本番ではスライド最小値を知らず部分点。蟻本に載ってるらしいので反省。

## solution

DPに落としてスライド最小値で加速。$O(NK)$。
segment木で$O(NK \log N)$だと間に合わない。

DPの関数$f(i,j)$は$i$個目の球をパネル$j$に当てるときの得点の最大値。
これは$f(i+1,j) = (i+2) A_j + \max \\{ f(i,j') \mid 1 \le j - j' \le M \\}$である。
区間$[j-m, j)$中の最大値を求める必要があり、ここでスライド最小値を使う。

## implementation

``` c++
#include <iostream>
#include <vector>
#include <algorithm>
#include <deque>
#include <functional>
#define repeat(i,n) for (int i = 0; (i) < (n); ++(i))
#define whole(f,x,...) ([&](decltype((x)) whole) { return (f)(begin(whole), end(whole), ## __VA_ARGS__); })(x)
typedef long long ll;
using namespace std;
template <class T> void setmax(T & a, T const & b) { if (a < b) a = b; }
template <typename X, typename T> auto vectors(X x, T a) { return vector<T>(x, a); }
template <typename X, typename Y, typename Z, typename... Zs> auto vectors(X x, Y y, Z z, Zs... zs) { auto cont = vectors(y, z, zs...); return vector<decltype(cont)>(x, cont); }

template <typename T>
struct sliding_window {
    deque<pair<int, T> > data;
    function<bool (T const &, T const &)> cmp;
    template <typename F>
    sliding_window(F a_lt) : cmp(a_lt) {}
    T front() { return data.front().second; } // smallest
    void push_back(int i, T a) { while (not data.empty() and cmp(a, data.back().second)) data.pop_back(); data.emplace_back(i, a); }
    void pop_front(int i) { if (data.front().first == i) data.pop_front(); }
    void push_front(int i, T a) { if (data.empty() or not cmp(data.front().second, a)) data.emplace_front(i, a); }
};

const ll inf = ll(1e18)+9;
int main() {
    int n, m, k; cin >> n >> m >> k;
    vector<int> a(n); repeat (i,n) cin >> a[i];
    vector<vector<ll> > dp = vectors(k, n, - inf);
    repeat (j,n) dp[0][j] = a[j];
    repeat (i,k-1) {
        sliding_window<ll> rmq( (greater<ll>()) );
        rmq.push_back(-1, - inf);
        repeat (j,n) {
            if (j-m-1 >= -1) rmq.pop_front(j-m-1);
            setmax(dp[i+1][j], rmq.front() + (i+2) *(ll) a[j]);
            rmq.push_back(j, dp[i][j]);
        }
    }
    cout << *whole(max_element, dp[k-1]) << endl;
    return 0;
}
```
