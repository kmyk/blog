---
layout: post
redirect_from:
  - /writeup/algo/atcoder/jag2016-domestic-b/
  - /blog/2016/04/24/jag2016-domestic-b/
date: 2016-04-24T22:28:32+09:00
tags: [ "competitive", "writeup", "atcoder", "jag", "icpc" ]
"target_url": [ "https://beta.atcoder.jp/contests/jag2016-domestic/tasks/jag2016secretspring_b" ]
---

# JAG Contest 2016 Domestic B - 豪邸と宅配便

本番はちらっと見てDP感があったので他のメンバーに投げた。

後から解いてみたらDPは不要であった。
問題の理解に少し手間取った(時刻は$T+1$個あるがそれらに幅はない、$T$単位時間ある)。

## solution

各時刻が使えるかどうかを愚直に調べていけばよい。$O(T)$。

$T \le 10000$と小さいので可能。

## implementation

``` c++
#include <iostream>
#include <vector>
#include <algorithm>
template <class T> bool setmax(T & l, T const & r) { if (not (l < r)) return false; l = r; return true; }
using namespace std;
int main() {
    int n, m, t; cin >> n >> m >> t;
    vector<bool> used(t);
    int i = 0;
    while (n --) {
        int a; cin >> a;
        for (setmax(i, a-m); i < min(t, a+m); ++ i) used[i] = true;
    }
    cout << count(used.begin(), used.end(), false) << endl;
    return 0;
}
```
