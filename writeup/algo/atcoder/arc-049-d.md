---
layout: post
redirect_from:
  - /blog/2016/03/27/arc-049-d/
date: 2016-03-27T23:13:32+09:00
tags: [ "competitive", "writeup", "atcoder", "segment-tree", "tree" ]
"target_url": [ "https://beta.atcoder.jp/contests/arc049/tasks/arc049_d" ]
---

# AtCoder Regular Contest 049 D - すわっぷしまーす

解説slideは真っ白(修正されたらしいが白いまま、downloadしてviewerで開き直すと見れるとの話がある)で見れず、kmjpさんの解説を頼りに解いた。

## 問題

完全二分木がある。
葉は左から順に値$[1,2^N]$が振ってある。
以下のクエリを順次処理せよ。

-   左から$a$番目の頂点(葉)の値を答える。
-   bfs順で$[a,b]$番目の頂点(葉ではない)の左右の部分木を入れ換える。
    -   $a$番目の頂点に関して入れ換え、その後の状態における$a+1$番目の頂点に関して入れ換え、という風にやる。

## 解法

segment木 + bitmask。完全二分木の高さ$N+1$に対し$O(QN^2)$。

愚直に実装するとすると、木を作製し実際に参照をswapすればよい。
それではもちろん間に合わないので、参照を操作するのではなく、swap済みflagをtoggleすることを考える。
するとこの操作は$0,1$の区間に関するxorのようなものになるので、segment木が視野に入ることになる。
葉の参照のクエリは、左の部分木と右の部分木のどちらに降りるかを、$a-1$の$i$-bit目とswap済みflagのxorで決めながら降りていき、辿り付いた葉の位置が答えるべき値である。

木の更新であるが、更新処理それ自体もswap済みflagの影響を受ける。
子をswap $\to$ 親をswap の場合は単純にswap済みflagを立てればよいが、
親をswap $\to$ 子をswap の場合はそうではない。
例えば、親$a = 1$がswap済みのときに子$a = 2$のswapのクエリが来たとする。
この場合$a = 3$の頂点をswapせねばならない。

このswap済みflagの処理を、segment木を使って高速に処理する。
ある程度の区間をまとめて処理することが目的であるので、深さ$k$の部分木らのswap済みflagsに関して$1$本のsegment木を用意する。
つまり、管理する区間の長さがそれぞれ$1, 2, 4, 8, \dots, 2^N$個である$N+1$本のsegment木を用いる。
これらの上に、swap済みflagを考慮した上での区間更新演算を実装すればよい。
また、それぞれのsegment木の区間の要素は$1$bitであるので、$N+1$bitの整数にまとめれば$1$本のsegment木で同じ処理を行うことができる。

## 実装

愚直な実装。長い。
もう少し考察すれば簡略化できそう。

`cin`,`cout`を使用するとTLEったので注意。

``` c++
#include <vector>
#include <cstdio>
#include <cassert>
#define repeat(i,n) for (int i = 0; (i) < (n); ++(i))
#define repeat_reverse(i,n) for (int i = (n)-1; (i) >= 0; --(i))
template <class T> bool setmax(T & l, T const & r) { if (not (l < r)) return false; l = r; return true; }
template <class T> bool setmin(T & l, T const & r) { if (not (r < l)) return false; l = r; return true; }
using namespace std;
typedef uint32_t mask_t;
int  left(int i) { return 2*i+1; }
int right(int i) { return 2*i+2; }
void rec(vector<mask_t> & t, int i, int il, int ir, int k, mask_t mask, int l, int r, mask_t z) {
    if (l <= il and ir <= r) {
        t[i] ^= z;
    } else if (ir <= l or r <= il) {
        // nop
    } else {
        mask ^= t[i];
        bool is_reversed = mask & (1<<k);
        int im = (il+ir)/2;
        int ll = min(l, im);
        int lr = min(r, im);
        int rl = max(l, im);
        int rr = max(r, im);
        if (is_reversed) {
            ll += im - il;
            lr += im - il;
            rl -= im - il;
            rr -= im - il;
            swap(ll, rl);
            swap(lr, rr);
        }
        rec(t,  left(i), il, im, k-1, mask, ll, lr, z);
        rec(t, right(i), im, ir, k-1, mask, rl, rr, z);
    }
}
int main() {
    int n, q; scanf("%d%d", &n, &q);
    vector<mask_t> t((1<<n)-1);
    repeat (query,q) {
        int type, a, b; scanf("%d%d%d", &type, &a, &b); -- a;
        if (type == 1) {
            assert (b == 0);
            int i = 0;
            mask_t mask = 0;
            repeat_reverse (k,n) {
                bool is_right = a & (1<<k);
                mask ^= t[i];
                bool is_reversed = mask & (1<<k);
                if (is_reversed) is_right = not is_right;
                i = is_right ? right(i) : left(i);
            }
            printf("%d\n", i-((1<<n)-1)+1);
        } else if (type == 2) {
            repeat (i,n) {
                int l = (1<<i) - 1;
                int r = 2*l + 1;
                setmax(l, a);
                setmin(r, b);
                if (r <= l) continue;
                int j = (1<<i) - 1;
                int k = n-1-i;
                l -= j; l <<= k;
                r -= j; r <<= k;
                rec(t, 0, 0, 1<<(n-1), n-1, 0, l, r, 1<<k);
            }
        }
    }
    return 0;
}
```
