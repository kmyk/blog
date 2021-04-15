---
layout: post
redirect_from:
  - /writeup/algo/atcoder/agc_002_c/
  - /writeup/algo/atcoder/agc-002-c/
  - /blog/2016/07/31/agc-002-c/
date: "2016-07-31T22:58:25+09:00"
tags: [ "competitive", "writeup", "atcoder", "agc" ]
"target_url": [ "https://beta.atcoder.jp/contests/agc002/tasks/agc002_c" ]
---

# AtCoder Grand Contest 002: C - Knot Puzzle

## solution

$a_i + a\_{i+1} \ge L$となる点を探して、これを中心に端から切る。$O(N)$。

最後に紐を切るには$a_i + a\_{i+1} \ge L$でなければならない。
点$i$でそうだと仮定すると、点$i$を含むような連続した紐に関して任意の点で切ることができる。
よって、このような点を探して、両端からこの点に向かって順番に切っていけばよい。

## implementation

pythonが適切であった。

``` c++
#include <iostream>
#include <vector>
#include <cassert>
#define repeat(i,n) for (int i = 0; (i) < (n); ++(i))
#define repeat_from_reverse(i,m,n) for (int i = (n)-1; (i) >= (m); --(i))
typedef long long ll;
using namespace std;
int main() {
    int n; ll l; cin >> n >> l;
    vector<ll> a(n); repeat (i,n) cin >> a[i];
    vector<int> ans;
    repeat (i,n-1) {
        if (a[i] + a[i+1] >= l) {
            repeat (j,i) ans.push_back(j);
            repeat_from_reverse (j,i,n-1) ans.push_back(j);
            break;
        }
    }
    if (ans.empty()) {
        assert (n >= 2);
        cout << "Impossible" << endl;
    } else {
        cout << "Possible" << endl;
        for (int i : ans) cout << i+1 << endl;
    }
    return 0;
}
```
