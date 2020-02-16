---
layout: post
alias: "/blog/2017/04/08/arc-071-e/"
date: "2017-04-08T23:10:04+09:00"
tags: [ "competitive", "writeup", "atcoder", "arc" ]
"target_url": [ "https://beta.atcoder.jp/contests/arc071/tasks/arc071_c" ]
---

# AtCoder Regular Contest 071: E - TrBBnsformBBtion

## solution

`A` `B`は交換可能。累積和しておいて比較。$O(\|S\| + \|T\| + Q)$。

`AB` $\to$ `AAA` $\to$ `BBAA` $\to$ `BAAAA` $\to$ `BA`とすれば`A` `B`は交換可能。よって区間中の`A` `B`の数だけ気にすればよい。
後は適当に比較する。
両方を全て`A` (あるいは`B`)に変換してしまって、$3$で割った余りを比較するのが楽だったらしい。`A` $\to$ `BB` $\to$ `AAAA`かつ`AAAA` $\to$ `A`なので$3$つ刻みでは自由に増減できる。

## implementation

``` c++
#include <iostream>
#include <vector>
#include <array>
#include <cassert>
#define repeat(i,n) for (int i = 0; (i) < int(n); ++(i))
using ll = long long;
using namespace std;

int main() {
    array<string, 2> s; cin >> s[0] >> s[1];
    array<vector<int>, 2> a_acc;
    repeat (p,2) {
        a_acc[p].resize(s[p].length() + 1);
        repeat (i, s[p].length()) {
            a_acc[p][i+1] = a_acc[p][i] + (s[p][i] == 'A');
        }
    }
    auto pred = [&](int l0, int r0, int l1, int r1) {
        // swap is possible: AB AAA BBAA BAAAA BA
        int a0 = a_acc[0][r0] - a_acc[0][l0];
        int a1 = a_acc[1][r1] - a_acc[1][l1];
        int b0 = (r0 - l0) - a0;
        int b1 = (r1 - l1) - a1;
        assert (a0 or b0);
        if (a0 < a1) { int delta = a1 - a0; a0 += delta; b0 += delta; } // A BB AAB or B AA ABB
        if (b0 < b1) { int delta = b1 - b0; a0 += delta; b0 += delta; } // A BB AAB or B AA ABB
        assert (a1 <= a0 and b1 <= b0);
        int delta = b0 - b1;
        b0 -= delta;
        a0 += 2 * delta;
        return (a0 - a1) % 3 == 0;
    };
    int q; cin >> q;
    while (q --) {
        int l0, r0, l1, r1; cin >> l0 >> r0 >> l1 >> r1; -- l0; -- l1;
        cout << (pred(l0, r0, l1, r1) ? "YES" : "NO") << endl;
    }
    return 0;
}
```
