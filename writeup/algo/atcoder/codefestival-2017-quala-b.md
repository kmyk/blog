---
layout: post
redirect_from:
  - /writeup/algo/atcoder/codefestival-2017-quala-b/
  - /blog/2017/10/03/codefestival-2017-quala-b/
date: "2017-10-03T06:36:50+09:00"
tags: [ "competitive", "writeup", "atcoder", "codefestival" ]
"target_url": [ "https://beta.atcoder.jp/contests/code-festival-2017-quala/tasks/code_festival_2017_quala_b" ]
---

# CODE FESTIVAL 2017 qual A: B - fLIP

最近競プロを始めた友人はここで詰まっていた。
解けるだろうのに勘違いで落としたようで、後から解法聞いて「なんか悔しいので以降の予選も受けます」って言ってたので将来有望ぽい。

## solution

行内や列内での位置は無視できるので、$R$行$C$列反転させると決まれば黒いマスの数が分かる。
$O(HW)$で総当たりすればよい。

## implementation

``` c++
#include <cstdio>
#define repeat(i, n) for (int i = 0; (i) < int(n); ++(i))
int main() {
    int h, w, k; scanf("%d%d%d", &h, &w, &k);
    bool result = false;
    repeat (y, h + 1) {
        repeat (x, w + 1) {
            if (y * w + x * h - 2 * y * x == k) {
                result = true;
            }
        }
    }
    printf("%s\n", result ? "Yes" : "No");
    return 0;
}
```
