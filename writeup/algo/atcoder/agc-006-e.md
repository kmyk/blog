---
layout: post
alias: "/blog/2017/07/26/agc-006-e/"
date: "2017-07-26T04:30:56+09:00"
tags: [ "competitive", "writeup", "atcoder", "agc", "optimization", "insertion-sort" ]
"target_url": [ "https://beta.atcoder.jp/contests/agc006/tasks/agc006_e" ]
---

# AtCoder Grand Contest 006: E - Rotate 3x3

挿入sortを使うと$O(N^2)$だが、符号の変化を転倒数とかを使って別で求めればquick sortなどができて$O(N \log N)$になるはず。だけどよく分からなかったので定数倍高速化で殴った。

## solution

挿入sortして位置を合わせ、位置を不変にしたまま向きを揃えられるか見る。簡単な定数倍高速化。$O(N^2)$。

操作は可逆なので、与えられた配置を初期配置に戻すと考えてよい。
自明に不可能な場合を落とせば、次の問題に帰着される。

数列$a = (a\_1, a\_2, \dots, a\_n)$で、$(\|a\_1\|, \|a\_2\|, \dots, \|a\_n\|)$は列$(1, 2, \dots, n)$の順列かつ$\|a\_i\| \equiv i \pmod{2}$なものが与えられる。
$1 \le i \le n - 2$を選んで連続部分列$(a\_i, a\_{i+1}, a\_{i+2})$を$(- a\_{i+2}, - a\_{i+1}, - a\_i)$で置き換える操作を繰り返して、列$(1, 2, \dots, n)$に変換できるか。

符号を無視すれば単にsortであるので、まずは符号の不一致は気にせずbubble sortや挿入sortで絶対値だけを合わせる。$O(N^2)$。
その後に絶対値を保ち符号だけ変化させられるような操作を用いて符号を一致させられるかを確認すればよい。
絶対値を保つような操作で考慮すべきは$(a, b, c, d) \mapsto (-a, -b, -c, -d)$と$(a, b, c, d, e) \mapsto (a, -b, c, -d, e)$のみであるので、これは$O(N)$となる。

## implementation

``` c++
#include <array>
#include <cassert>
#include <cstdio>
#include <vector>
#define repeat(i, n) for (int i = 0; (i) < int(n); ++(i))
#define repeat_from(i, m, n) for (int i = (m); (i) < int(n); ++(i))
using namespace std;

bool solve(int n, vector<array<int, 3> > const & a) {

    // parse
    vector<pair<int, bool> > b(n);
    repeat (x, n) {
        auto col = a[x];
        bool swapped = false;
        if (col[0] > col[2]) {
            swap(col[0], col[2]);
            swapped = true;
        }
        if (col[0] + 1 != col[1] or col[1] + 1 != col[2]) return false;
        if ((col[1] - 2) % 3 != 0) return false;
        int i = (col[1] - 2) / 3;
        if (i % 2 != x % 2) return false;
        b[x] = { i, not swapped };
    }
    if (n == 3) {
        return b[0].second == b[1].second and b[1].second == b[2].second;
    }
    assert (n >= 4);

    // sort
    {
        vector<int> c(n); // optimization
        repeat (x, n) {
            c[x] = b[x].first * 2 + b[x].second;
        }
        repeat (r, n) {
            int col = c[r];
            int l = r;
            while (l - 2 >= 0 and c[l - 2] > col) {
                c[l] = c[l - 2];
                l -= 2;
            }
            if (l < r) {
                c[l] = col;
                if ((r - l) / 2 % 2 == 1) {
                    c[l] ^= 1;
                }
                repeat_from (x, l + 1, r + 1) {
                    c[x] ^= 1;
                }
            }
        }
        repeat (x, n) {
            b[x] = { c[x] / 2, bool(c[x] % 2) };
        }
    }

    // normalize
    if (not b[0].second) {
        repeat (x, 4) b[x].second ^= true;
    }
    if (not b[n - 1].second) {
        repeat (x, 4) b[n - 1 - x].second ^= true;
    }
    repeat (x, n - 4) {
        if (not b[x + 1].second) {
            b[x + 1].second ^= true;
            b[x + 3].second ^= true;
        }
    }
    repeat (x, n) {
        if (not b[x].second) return false;
    }
    return true;

}

int main() {
    int n; scanf("%d", &n);
    vector<array<int, 3> > a(n);
    repeat (y, 3) {
        repeat (x, n) {
            scanf("%d", &a[x][y]);
        }
    }
    bool result = solve(n, a);
    printf("%s\n", result ? "Yes" : "No");
    return 0;
}
```
