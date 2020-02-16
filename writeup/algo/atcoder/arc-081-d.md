---
layout: post
redirect_from:
  - /blog/2017/08/21/arc-081-d/
date: "2017-08-21T00:12:16+09:00"
tags: [ "competitive", "writeup", "atcoder", "arc" ]
"target_url": [ "https://beta.atcoder.jp/contests/arc081/tasks/arc081_b" ]
---

# AtCoder Regular Contest 081: D - Coloring Dominoes

縦幅が$2$というのを見落す誤読し、さらに手元でWAを重ねた。

縦幅を一般の$H$にしても丁寧にやればなんとかなる気もするし、どうにもならないという気もする。

## solution

端から順番に決めていく。$O(N)$。

次の形を縦型、

```
A
A
```

次の形をふたつまとめて認識して横型と呼ぶとする。


```
AA
BB
```

縦横の別の列が入力されるのと等しい。
ひとつ前が縦/横のときに縦/横が来たらいくつの塗り方があるかは、(間違えないように)見れば分かるのでそれらを末端の分と掛け合わせれば求まる。

## implementation

``` c++
#include <cassert>
#include <iostream>
using ll = long long;
using namespace std;

constexpr int mod = 1e9+7;
int main() {
    int n; cin >> n;
    string s0, s1; cin >> s0 >> s1;
    ll result = (s0[0] == s1[0] ? 3 : 2);
    bool prv = false;
    for (int i = 0; i < n; ) {
        if (s0[i] == s1[i]) {
            result *= (prv ? 2 : 1);
            result %= mod;
            prv = true;
            i += 1;
        } else {
            assert (i + 1 < n and s0[i] == s0[i + 1] and s1[i] == s1[i + 1]);
            result *= (prv ? 2 : 3);
            result %= mod;
            prv = false;
            i += 2;
        }
    }
    printf("%lld\n", result);
    return 0;
}
```
