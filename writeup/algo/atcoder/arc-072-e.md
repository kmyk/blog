---
layout: post
alias: "/blog/2017/10/03/arc-072-e/"
date: "2017-10-03T04:22:39+09:00"
tags: [ "competitive", "writeup", "atcoder", "arc" ]
"target_url": [ "https://beta.atcoder.jp/contests/arc072/tasks/arc072_c" ]
---

# AtCoder Regular Contest 072: E - Alice in linear land

## solution

後ろから見ていく。$O(N + Q)$。

$i$番目の直前で位置$a\_i$に居るとして、$d\_i$を変更しても計画が実行不能 $\iff$ 全ての$b \le d\_i$から残りを動いて目的地に到着可能。
両辺否定すれば、$d\_i$を変更しても計画が実行可能 $\iff$ ある$b \le d\_i$が存在して目的地に到着不能。
特にそのようなものの最小値を$b\_i$とおけば$b\_i \le a\_i$を見るだけとなる。

$a\_i$は簡単に求まる。
$b\_i$を求めるのは明らかでないが、整理すれば$b\_{i + 1}, d\_i$の関数の形の漸化式で求まる。

## implementation

``` c++
#include <cstdio>
#include <cstdlib>
#include <vector>
#define repeat(i, n) for (int i = 0; (i) < int(n); ++(i))
#define repeat_reverse(i, n) for (int i = (n)-1; (i) >= 0; --(i))
using namespace std;

int main() {
    // input
    int n, dd; scanf("%d%d", &n, &dd);
    vector<int> d(n); repeat (i, n) scanf("%d", &d[i]);

    // solve
    vector<int> a(n + 1);
    a[0] = dd;
    repeat (i, n) {
        a[i + 1] = min(a[i], abs(a[i] - d[i]));
    }
    vector<int> b(n + 1);
    b[n] = 1;
    repeat_reverse (i, n) {
        b[i] = b[i + 1] + (b[i + 1] <= d[i] / 2 ? 0 : d[i]);
    }

    // output
    int queries; scanf("%d", &queries);
    while (queries --) {
        int q_i; scanf("%d", &q_i); -- q_i;
        bool result = b[q_i + 1] <= a[q_i];
        printf("%s\n", result ? "YES" : "NO");
    }
    return 0;
}
```
