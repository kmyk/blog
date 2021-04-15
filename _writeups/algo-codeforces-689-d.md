---
layout: post
redirect_from:
  - /writeup/algo/codeforces/689-d/
  - /blog/2017/03/07/cf-689-d/
date: "2017-03-07T23:39:50+09:00"
tags: [ "competitive", "writeup", "codeforces", "lie", "optimization", "doubling", "square-root-decomposition" ]
"target_url": [ "http://codeforces.com/contest/689/problem/D" ]
---

# Codeforces Round #361 (Div. 2): D. Friends and Subsequences

sparse tableの演習のつもりだったが、定数倍高速化で殴り倒せそうだったのでやってしまった。
始めはthread並列+SIMDを試していたが、こちらの方が楽そうだったので捨てて切り替えた。

## problem

長さ$N$の数列$a, b$が与えられる。$\|\\{ [l, r) \mid \max\_{l \le i \lt r} a_i = \min\_{l \le i \lt r} b_i \\}\|$を答えよ。

## solution

愚直解法をdoublingっぽく定数倍高速化。$O(N^2)$。

単純にやると左端$l$を固定して$r$を増やしていって$O(N^2)$。
ここで$r$を$1$ずつ増やすのでなく幅$K$ずつ増やすことを考える。
事前に数列$a,b$を幅$K$ごとのblockに分けそれぞれのblockでの最大値最小値を取っておけば実現できて、$O(N^2/K)$になる。
端数の処理には注意。loop-unrollingやSSEを思い出しつつ丁寧に。

この幅$K$は定数にすると計算量に表われない。
しかし$K = \sqrt{N}$とすると平方分割になり、
$K = 2, 4, 8, 16, \dots, N'$として全てに対して前処理した配列を用意して順に使うとdoublingと呼ばれる。
想定解らしいsparse tableともかなり似る。

## implementation

### 愚直

``` c++
#include <cstdio>
#include <algorithm>
#define repeat(i,n) for (int i = 0; (i) < int(n); ++(i))
#define repeat_from(i,m,n) for (int i = (m); (i) < int(n); ++(i))
using ll = long long;
using namespace std;
template <class T> inline void setmax(T & a, T const & b) { a = max(a, b); }
template <class T> inline void setmin(T & a, T const & b) { a = min(a, b); }
constexpr int max_n = 200000;
constexpr int inf = 1e9+7;
int a[max_n];
int b[max_n];
int main() {
    int n; scanf("%d", &n);
    repeat (i,n) scanf("%d", &a[i]);
    repeat (i,n) scanf("%d", &b[i]);
    ll cnt = 0;
    repeat (l,n) {
        int max_a = - inf;
        int min_b = + inf;
        repeat_from (r,l+1,n+1) {
            setmax(max_a, a[r-1]);
            setmin(min_b, b[r-1]);
            if (max_a == min_b) ++ cnt;
            if (max_a  > min_b) break;
        }
    }
    printf("%lld\n", cnt);
    return 0;
}
```

### 高速化後

``` c++
#include <cstdio>
#include <algorithm>
#define repeat(i,n) for (int i = 0; (i) < int(n); ++(i))
#define repeat_from(i,m,n) for (int i = (m); (i) < int(n); ++(i))
using ll = long long;
using namespace std;
template <class T> inline void setmax(T & a, T const & b) { a = max(a, b); }
template <class T> inline void setmin(T & a, T const & b) { a = min(a, b); }
constexpr int inf = 1e9+7;
constexpr int max_n = 200000;
constexpr int width = 1 << 5;
static_assert (max_n % width == 0, "");
int a[max_n];
int b[max_n];
int a_block[max_n/width];
int b_block[max_n/width];
int main() {
    // input
    int n; scanf("%d", &n);
    repeat (i,n) scanf("%d", &a[i]);
    repeat (i,n) scanf("%d", &b[i]);
    // prepare
    repeat_from (i,n,max_n) a[i] = - inf;
    repeat_from (i,n,max_n) b[i] = + inf;
    repeat (i,max_n/width) {
        a_block[i] = - inf;
        b_block[i] = + inf;
        repeat (j,width) {
            setmax(a_block[i], a[i*width+j]);
            setmin(b_block[i], b[i*width+j]);
        }
    }
    // count
    ll cnt = 0;
    repeat (l,n) {
        int max_a = - inf;
        int min_b = + inf;
        int r = l;
        // align
        for (; r+1 < n+1 and r % width != 0; ++ r) {
            setmax(max_a, a[r]);
            setmin(min_b, b[r]);
            if (max_a == min_b) ++ cnt;
            if (max_a  > min_b) break;
        }
        if (max_a > min_b) continue;
        // skip while max_a < min_b
        for (int i = r / width; r+width < n+1; r += width, ++ i) {
            if (not (max(max_a, a_block[i]) < min(min_b, b_block[i]))) break;
            setmax(max_a, a_block[i]);
            setmin(min_b, b_block[i]);
        }
        if (max_a > min_b) continue;
        // remainder
        for (; r+1 < n+1 and max_a < min_b; ++ r) {
            setmax(max_a, a[r]);
            setmin(min_b, b[r]);
            if (max_a == min_b) ++ cnt;
        }
        if (max_a > min_b) continue;
        // align
        for (; r+1 < n+1 and r % width != 0; ++ r) {
            setmax(max_a, a[r]);
            setmin(min_b, b[r]);
            if (max_a == min_b) ++ cnt;
            if (max_a  > min_b) break;
        }
        if (max_a > min_b) continue;
        // skip while max_a == min_b
        for (int i = r / width; r+width < n+1 and max_a == min_b; r += width, ++ i) {
            if (max_a < a_block[i] or b_block[i] < min_b) break;
            cnt += width;
        }
        if (max_a > min_b) continue;
        // remainder
        for (; r+1 < n+1; ++ r) {
            setmax(max_a, a[r]);
            setmin(min_b, b[r]);
            if (max_a == min_b) ++ cnt;
            if (max_a  > min_b) break;
        }
    }
    // output
    printf("%lld\n", cnt);
    return 0;
}
```

<hr>

-   2017年  3月  8日 水曜日 00:22:25 JST
    -   それ平方分割を指摘されたので修正
