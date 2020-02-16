---
layout: post
redirect_from:
  - /blog/2016/09/14/arc-061-c/
date: "2016-09-14T13:08:52+09:00"
tags: [ "competitive", "writeup", "atcoder", "arc" ]
"target_url": [ "https://beta.atcoder.jp/contests/arc061/tasks/arc061_a" ]
---

# AtCoder Regular Contest 061 C - たくさんの数式 / Many Formulas

## solution

総当たり。$O({\|S\|}^2)$。

$\|S\| \le 10$と小さい。`+`を挿入する位置は高々$9$箇所なので、これに関して総当たりしても$512$通りである。

## implementation

``` c++
#include <iostream>
#define repeat(i,n) for (int i = 0; (i) < (n); ++(i))
typedef long long ll;
using namespace std;
int main() {
    string s; cin >> s;
    ll ans = 0;
    int n = s.size();
    repeat (x, 1<<(n-1)) {
        ll acc = 0;
        repeat (i,n) {
            acc *= 10;
            acc += s[i] - '0';
            if ((x&(1<<i)) == 0) {
                ans += acc;
                acc = 0;
            }
        }
        ans += acc;
    }
    cout << ans << endl;
    return 0;
}
```
