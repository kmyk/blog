---
layout: post
redirect_from:
  - /blog/2017/08/27/agc-019-b/
date: "2017-08-27T00:14:21+09:00"
tags: [ "competitive", "writeup", "atcoder", "agc", "experiment" ]
"target_url": [ "https://beta.atcoder.jp/contests/agc019/tasks/agc019_b" ]
---

# AtCoder Grand Contest 019: B - Reverse and Compare

## solution

実験。$O(N)$。

区間$[l, r)$の反転で変化しないのは$\mathrm{substr}(l, r) = \mathrm{reverse}(\mathrm{substr}(l, r))$のときだけ。
$\mathrm{substr}(l, r) \ne \mathrm{reverse}(\mathrm{substr}(l, r))$と仮定して、他の反転の結果と一致するのは$A\_l = A\_{r - 1}$ (あるいは$A\_{l - 1} = A\_r$) の場合のみ。
これは実験すれば出る。
反転を左端$l$と右端$r$から$[l, r)$で見るのでなく、中心$c$と半径$\delta$で$[c - \delta, c + \delta]$で見ておくと分かりやすい。
逆に$A\_l \ne A\_{r-1}$な$l \lt r-1$があればその反転は代表元のように見れて、これを数えればよい。

## implementation

``` c++
#include <iostream>
#include <array>
#define repeat_reverse(i, n) for (int i = (n)-1; (i) >= 0; --(i))
using ll = long long;
using namespace std;

int main() {
    string s; cin >> s;
    int n = s.size();
    array<int, 26> cnt = {};
    ll result = 1;
    repeat_reverse (i, n) {
        char c = s[i] - 'a';
        cnt[c] += 1;
        result += n - i - cnt[c];
    }
    cout << result << endl;
    return 0;
}
```
