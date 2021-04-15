---
layout: post
redirect_from:
  - /writeup/algo/topcoder/srm-714-easy/
  - /blog/2017/05/07/srm-714-easy/
date: "2017-05-07T22:01:05+09:00"
tags: [ "competitive", "writeup", "topcoder", "srm" ]
---

# TopCoder SRM 714 Div1 Easy: ParenthesisRemoval

実験。

## solution

全ての `(` (あるいは`)`) についてそのnestの深さの積。$O(\|s\|)$。

---

# TopCoder SRM 714 Div1 Easy: ParenthesisRemoval

未証明。editorialもないしよく分からない。

ただ、各 `)` についてそれがどの `(` によって消されるかを考えるとこんな感じになりそう。

## implementation

``` c++
#include <bits/stdc++.h>
#define repeat(i,n) for (int i = 0; (i) < (n); ++(i))
typedef long long ll;
using namespace std;
class ParenthesisRemoval { public: int countWays(string s); };
constexpr int mod = 1e9+7;
int ParenthesisRemoval::countWays(string s) {
    int result = 1;
    int nest = 0;
    for (char c : s) {
        if (c == '(') {
            nest += 1;
            result = result *(ll) nest % mod;
        } else {
            nest -= 1;
        }
    }
    return result;
}
```
