---
layout: post
alias: "/blog/2017/07/23/agc-018-b/"
date: "2017-07-23T23:17:15+09:00"
tags: [ "competitive", "writeup", "atcoder", "agc", "greedy" ]
"target_url": [ "https://beta.atcoder.jp/contests/agc018/tasks/agc018_b" ]
---

# AtCoder Grand Contest 018: B - Sports Festival

大量提出による荒らしがあったらしい。
対策の予定どうこうと言っているけど、不正(不正ではない)っぽい手法で捩じ込むようなACするやつがしにくくなりそうで嬉しくない。

## solution

貪欲。全部実施するとして始めて減らしていく。$O(M(N+M))$。

始めは全部実施するとしておく。
その状況が解でないとしたら、そのとき最も多くの参加者がいるスポーツは中止しなければならない。
他のどのスポーツを中止しても中止した以外のスポーツの参加者は増えるため。
またスポーツの中止の順序は影響しないことも重要。
これを繰り返しながら残りひとつだけにし、その過程で最小だったものが解。

厳密な証明は不勉強のため分からない。
matroidとかですっきり示せたりするのだろうか。

## implementation

``` c++
#include <algorithm>
#include <cassert>
#include <cstdio>
#include <vector>
#define repeat(i, n) for (int i = 0; (i) < int(n); ++(i))
#define whole(f, x, ...) ([&](decltype((x)) whole) { return (f)(begin(whole), end(whole), ## __VA_ARGS__); })(x)
using namespace std;
template <class T> inline void setmin(T & a, T const & b) { a = min(a, b); }
template <typename X, typename T> auto vectors(X x, T a) { return vector<T>(x, a); }
template <typename X, typename Y, typename Z, typename... Zs> auto vectors(X x, Y y, Z z, Zs... zs) { auto cont = vectors(y, z, zs...); return vector<decltype(cont)>(x, cont); }

int main() {
    int n, m; scanf("%d%d", &n, &m);
    auto a = vectors(n, m, int());
    repeat (y, n) {
        repeat (x, m) {
            scanf("%d", &a[y][x]);
            -- a[y][x];
        }
    }
    vector<int> cnt(m);
    repeat (y, n) {
        cnt[a[y][0]] += 1;
    }
    int result = *whole(max_element, cnt);
    int k = m;
    vector<int> ix(n);
    while (true) {
        repeat (x, m) {
            if (cnt[x] >= result) {
                cnt[x] = -1;
                k -= 1;
            }
        }
        if (k == 0) break;
        repeat (y, n) {
            if (cnt[a[y][ix[y]]] == -1) {
                while (cnt[a[y][ix[y]]] == -1) ++ ix[y];
                assert (ix[y] < m);
                cnt[a[y][ix[y]]] += 1;
            }
        }
        setmin(result, *whole(max_element, cnt));
    }
    printf("%d\n", result);
    return 0;
}
```
