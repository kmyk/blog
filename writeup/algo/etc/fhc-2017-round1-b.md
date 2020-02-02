---
layout: post
alias: "/blog/2017/01/16/fhc-2017-round1-b/"
date: "2017-01-16T03:04:31+09:00"
title: "Facebook Hacker Cup 2017 Round 1: Fighting the Zombies"
tags: [ "competitive", "writeup", "facebook-hacker-cup", "geometry" ]
"target_url": [ "https://www.facebook.com/hackercup/problem/235709883547573/" ]
---

これ好き。

## problem

無限に広い平面上に点が$N$個ある。整数$R$が与えられる。以下の操作を順に行なうとき、得点を最大化せよ。

1.  中心と半径を実数値で任意に定め円を決める。さらに移動量を実数値で任意に決め、その円内の点を指定しただけまとめてずらす。
2.  軸平行な$R \times R$の区間を決める。その区間中の点の数が得点。

## solution

定めるのは円であるが、十分大きな円を考え、半直線を引いて片側をまとめて選択してよい。
これにより、$R \times R$の区間を好きに$2$個選んでその和集合内の点の数を得点としてよいことが導ける。$O(N^3)$。

## implementation

``` c++
#include <iostream>
#include <vector>
#include <algorithm>
#include <set>
#include <cassert>
#define repeat(i,n) for (int i = 0; (i) < int(n); ++(i))
#define whole(f,x,...) ([&](decltype((x)) whole) { return (f)(begin(whole), end(whole), ## __VA_ARGS__); })(x)
using ll = long long;
using namespace std;
template <class T> void setmax(T & a, T const & b) { if (a < b) a = b; }
bool is_on_field(int y, int x, int h, int w) { return 0 <= y and y < h and 0 <= x and x < w; }
int solve(int n, ll r, vector<ll> const & y, vector<ll> const & x) {
    assert (n <= sizeof(uint64_t)*8);
    set<ll> uniq_y(y.begin(), y.end());
    set<ll> uniq_x(x.begin(), x.end());
    vector<uint64_t> rects;
    for (ll ay : uniq_y) {
        for (ll ax : uniq_x) {
            repeat (dir,4) {
                ll by = ay - (dir & 2 ? r : 0);
                ll bx = ax - (dir & 1 ? r : 0);
                uint64_t rect = 0;
                repeat (i,n) {
                    if (is_on_field(y[i] - by, x[i] - bx, r+1, r+1)) {
                        rect |= 1ll << i;
                    }
                }
                rects.push_back(rect);
            }
        }
    }
    whole(sort, rects);
    rects.erase(whole(unique, rects), rects.end());
    for (int i = 0; i < rects.size(); ++ i) {
        bool is_subset = false;
        repeat (j,rects.size()) if (j != i) {
            if ((rects[i] | rects[j]) == rects[j]) {
                is_subset = true;
                break;
            }
        }
        if (is_subset) {
            rects[i] = rects.back();
            rects.pop_back();
            -- i;
        }
    }
    int result = 0;
    for (uint64_t s : rects) {
        for (uint64_t t : rects) {
            setmax(result, __builtin_popcountll(s | t));
        }
    }
    return result;
}
int main() {
    int t; cin >> t;
    repeat (i,t) {
        int n; ll r; cin >> n >> r;
        vector<ll> x(n), y(n);
        repeat (i,n) cin >> x[i] >> y[i];
        cout << "Case #" << i+1 << ": " << solve(n, r, y, x) << endl;
    }
    return 0;
}
```
