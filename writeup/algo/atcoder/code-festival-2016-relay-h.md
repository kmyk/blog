---
layout: post
redirect_from:
  - /blog/2016/11/30/code-festival-2016-relay-h/
date: "2016-11-30T01:33:30+09:00"
tags: [ "competitive", "writeup", "atcoder", "codefestival" ]
"target_url": [ "https://beta.atcoder.jp/contests/cf16-relay-open/tasks/relay_h" ]
---

# CODE FESTIVAL 2016 Relay: H - 早起き / Early Bird

overflowとちょうど$3,7$時の両方を含むことの見落しで$2$WA。

## solution

$T = 0$として各時刻での起床回数を計算し、早起きとなる区間をスライドさせつつ$T$を$0$から$86399$まで動かし、その最大を出力すればよい。一日の秒数を$T$として$O(N + T)$。

## implementation

``` c++
#include <iostream>
#include <vector>
#include <numeric>
#define repeat(i,n) for (int i = 0; (i) < (n); ++(i))
using namespace std;
template <class T> void setmax(T & a, T const & b) { if (a < b) a = b; }
const int l  = 60 * 60 * 24;
const int l3 = 60 * 60 * 3 + 1;
int main() {
    int n; cin >> n;
    vector<int> cnt(l);
    for (int t = 0; n --; ) {
        int a, b; cin >> a >> b;
        t += a;
        t %= l;
        cnt[t] += 1;
        t += b;
    }
    int ans = 0;
    int acc = accumulate(cnt.begin(), cnt.begin() + l3, 0);
    repeat (t,l) {
        acc += - cnt[t] + cnt[(t + l3) % l];
        setmax(ans, acc);
    }
    cout << ans << endl;
    return 0;
}
```
