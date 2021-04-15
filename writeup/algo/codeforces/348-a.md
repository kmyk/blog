---
layout: post
redirect_from:
  - /writeup/algo/codeforces/348-a/
  - /blog/2016/03/29/cf-348-a/
date: 2016-03-29T23:12:25+09:00
tags: [ "competitive", "writeup", "codeforces" ]
"target_url": [ "http://codeforces.com/contest/348/problem/A" ]
---

# Codeforces Round #202 (Div. 1) A. Mafia

やる気の不足。どうせこれ$O(N)$で簡単に解けるのだろうなあと思いながら、深く考えるのが面倒だったので適当ににぶたんした。

## 解法

二分探索。$O(N\log \Sigma A_i)$。

全体のゲーム数を二分探索。ゲームに参加したい回数を除いて全部ゲーム管理をやらせる貪欲で判定。

## 実装

``` c++
#include <iostream>
#include <vector>
#include <algorithm>
#define repeat(i,n) for (int i = 0; (i) < (n); ++(i))
typedef long long ll;
using namespace std;
int main() {
    int n; cin >> n;
    vector<ll> a(n); repeat (i,n) cin >> a[i];
    sort(a.rbegin(), a.rend());
    auto pred = [&](ll total) {
        ll played = 0;
        auto playable = [&]() { return total - played; };
        auto required = [&](int i) { return a[i] - played; };
        repeat (i,n) {
            if (required(i) <= 0) return true;
            if (playable() < required(i)) return false;
            played += playable() - required(i);
        }
        return false;
    };
    ll low = 0, high = accumulate(a.begin(), a.end(), 0ll) + 1;
    while (low + 1 < high) {
        ll mid = (low + high) / 2;
        (pred(mid) ? high : low) = mid;
    }
    cout << high << endl;
    return 0;
}
```
