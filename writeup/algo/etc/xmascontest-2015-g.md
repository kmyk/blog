---
layout: post
redirect_from:
  - /blog/2015/12/24/xmascontest-2015-g/
date: 2015-12-24T22:55:25+09:00
tags: [ "competitive", "atcoder", "writeup", "greedy" ]
---

# Xmas Contest 2015 G - Good Sequence

## [G - Good Sequence](https://beta.atcoder.jp/contests/xmascontest2015/tasks/xmascontest2015_g) {#g}

### 解法

貪欲 $O(n)$

$A$の要素を前から順に、結果の数列に入るか決めていく。
このとき、末尾に追加して制約に反しないなら追加する。
制約に反するときは明らかに末尾の要素を置き換えるべきであるのでそうする。

きちんとした証明はしていない。

### 実装

``` c++
#include <iostream>
#include <vector>
#define repeat(i,n) for (int i = 0; (i) < (n); ++(i))
typedef long long ll;
using namespace std;
ll solve(vector<ll> const & a) {
    vector<ll> b;
    for (int c : a) {
        int l = b.size();
        if (l == 0) {
            b.push_back(c);
        } else if (l == 1) {
            if (b.back() != c) {
                b.push_back(c);
            }
        } else {
            if ((b[l-2] < b[l-1] and b[l-1] <= c) or
                (b[l-2] > b[l-1] and b[l-1] >= c)) {
                b.pop_back();
            }
            b.push_back(c);
        }
    }
    ll s = 0;
    repeat (i,b.size()-1) {
        s += abs(b[i] - b[i+1]);
    }
    return s;
}
int main() {
    int n; cin >> n;
    vector<ll> a(n); repeat (i,n) cin >> a[i];
    cout << solve(a) << endl;
    return 0;
}
```
