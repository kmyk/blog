---
layout: post
alias: "/blog/2018/01/04/codefestival-2016-grand-final-c/"
date: "2018-01-04T16:09:21+09:00"
tags: [ "competitive", "writeup", "atcodr", "codefestival", "xor", "nim" ]
"target_url": [ "https://beta.atcoder.jp/contests/cf16-exhibition-final/tasks/cf16_exhibition_final_c" ]
---

# CODE FESTIVAL 2016 Grand Final: C - Cheating Nim

## solution

数列$a$から異なる$k$項選んで$a\_i - 1$で置き換え、排他的論理和での総和を$0$にできるような$k$の最小値が答え。
$a\_i \mapsto a\_i - 1$と置き換えたときの差分$a\_i \oplus (a\_i - 1)$は常に$2^b - 1$の形をしている。
総和$\sum a\_i$から差分$a\_i \oplus (a\_i - 1)$を$b$の大きい順に引いていって$0$にしようとすればよい。
$O(N + \log a\_{\mathrm{max}})$。

## implementation

``` c++
#include <cstdio>
#include <vector>
#define repeat(i, n) for (int i = 0; (i) < int(n); ++(i))
#define repeat_reverse(i, n) for (int i = (n)-1; (i) >= 0; --(i))
using namespace std;

int main() {
    // input
    int n; scanf("%d", &n);
    vector<int> a(n); repeat (i, n) scanf("%d", &a[i]);
    // solve
    int sum_a = 0;
    vector<bool> cnt(30);
    for (int a_i : a) {
        sum_a ^= a_i;
        cnt[__builtin_ctz(a_i)] = true;
    }
    int result = 0;
    repeat_reverse (i, 30) {
        if (sum_a & (1 << i)) {
            if (not cnt[i]) {
                result = -1;
                break;
            } else {
                result += 1;
                sum_a ^= (1 << (i + 1)) - 1;
            }
        }
    }
    // output
    printf("%d\n", result);
    return 0;
}
```
