---
layout: post
redirect_from:
  - /writeup/algo/atcoder/agc_015_d/
  - /writeup/algo/atcoder/agc-015-d/
  - /blog/2017/05/28/agc-015-d/
date: "2017-05-28T03:30:11+09:00"
tags: [ "competitive", "writeup", "atcoder", "agc" ]
"target_url": [ "https://beta.atcoder.jp/contests/agc015/tasks/agc015_d" ]
---

# AtCoder Grand Contest 015: D - A or...or B Problem

やればできそうだけどしんどい感じの問題。考察をあまりせずに書き始めたら時間が溶けるだけに終わった。

## solution

丁寧に場合分けして、MSBを取る操作を$O(1)$見做せば$O(1)$で求まる。

$A \lt B$としてよい。
$A, B$のMSBが同じなら両方からそれを除去してよい。これは再帰的にできて、$B$のMSBを$2^r$とすると$A \lt 2^r$であるようにできる。
生成される整数を$2^r$未満かどうかで分ける。

-   $2^r$未満であれば$B$は忘れて$[A, 2^r)$に制限してよい。
    $[A, 2^r)$の範囲は自明に作れて、bit和を取って小さくなるので$A$未満は作れない。
    よって$2^r - A$個。
-   $2^r$以上とする。
    $B - 2^r$のMSBを$2^k$とする。
    $B$により$2^r + 2^i$ for $i \lt k$の形の整数は全て作れ、$2^{k+1}$を含むようなものは作れない。よって$[2^r, B]$の範囲(のみ)から生成されるのは$[2^r, 2^r + 2^{k+1})$。
    $[A, 2^r)$の範囲を考えた場合はこれに$2^r$を足すことで$[2^r + A, 2^{r+1})$の範囲が作れる。
    -   $2^r + A \le 2^r + 2^{k+1}$の場合はこれらを合わせて$[2^r, 2^{r+1})$が全て作れて終わり。
    -   そうでないとき$[2^r, 2^r + 2^{k+1})$と$[2^r + A, 2^{r+1})$からその間$[2^r + 2^{k+1}, 2^r+A)$に入る整数が作れるかどうかであるが、作れない。
        $l \in [2^r, 2^r + 2^{k+1})$と$r \in [2^r + A, 2^{r+1})$の和$l + r \ge r$なので$l + r \in [2^r + A, 2^{r+1})$となるため。

## implementation

``` c++
#include <cstdio>
#include <cassert>
#define repeat(i,n) for (int i = 0; (i) < int(n); ++(i))
#define repeat_reverse(i,n) for (int i = (n)-1; (i) >= 0; --(i))
using ll = long long;
using namespace std;

const int bit_size = 60;
int msb(ll x) {
    repeat_reverse (i, bit_size) {
        ll y = 1ll << i;
        if (y & x) return i;
    }
    return -1;
}
ll solve(ll a, ll b) {
    // drop unnecessarily bits
    while (true) {
        int r = msb(b);
        if (r == -1) break;
        ll x = 1ll << r;
        if ((a & x) and (b & x)) {
            a ^= x;
            b ^= x;
        } else {
            break;
        }
    }
    // trivial case
    if (b == 0) return 1;
    assert (a < b);
    // prepare
    int r = msb(b);
    ll x = 1ll << r;
    assert (     b & x);
    assert (not (a & x));
    ll result = 0;
    // the msb is true
    if (b == x) {
        if (a == 0) {
            result += x - a;
        } else {
            result += x - a + 1;
        }
    } else {
        int k = msb(b ^ x);
        assert (k != -1);
        if (a >= (1ll << (k+1))) {
            result += 1ll << (k+1);
            result += x - a;
        } else {
            result += x;
        }
    }
    // the msb is false
    result += x - a;
    return result;
}

int main() {
    ll a, b; scanf("%lld%lld", &a, &b);
    ll result = solve(a, b);
    printf("%lld\n", result);
    return 0;
}
```
