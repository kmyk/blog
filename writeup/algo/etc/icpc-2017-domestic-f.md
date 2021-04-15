---
layout: post
redirect_from:
  - /writeup/algo/etc/icpc-2017-domestic-f/
  - /blog/2017/07/15/icpc-2017-domestic-f/
date: "2017-07-15T01:15:26+09:00"
tags: [ "competitive", "writeup", "icpc", "icpc-domestic" ]
---

# ACM-ICPC 2017 国内予選: F.  リボンたたみ

$2$進数でいい感じにするのだろうけどなんだか面倒だな、と思ってたら後輩氏が解法を投げてきた問題。

<del>**入出力が入手できていないのでACをするかどうかは未確認**</del> [復習用に公開されてた入出力](http://icpc.iisf.or.jp/past-icpc/domestic2017/judgedata/F/)で試したら合っていた。

## solution

印の高さに注目すれば、$k$回目の折り畳みの操作において上側になるか下側になるかが定まる。これから操作列が復元できる。$O(n)$。

最後の折り畳みの後に印のついた位置は上から$i$番目にある。このときリボンの厚み$h = 2^n$として$i <= h/2$であれば最後の折り畳みにおいて印は上側であったことが分かり、そうでなければ下側であったと分かる。
そのようにすると最後から$2$番目の折り畳みの後に上から何番目の層に印があるかが分かる。
再帰的にすると各$k$回目の折り畳みの後に上から何番目の層に印があるかが分かり、特に$k$回目の折り畳みにおいて印が上側か下側かが分かる。

この情報を参照すると、印が左から$j$番目にあるという情報と合わせると最初の折り畳みが`L`か`R`が決定する。
この後に左から何番目かは分かるので、これも再帰的にやる。

## implementation

``` c++
#include <iostream>
#include <vector>
#define repeat(i, n) for (int i = 0; (i) < int(n); ++(i))
using ll = long long;
using namespace std;

int main() {
    while (true) {
        int n; ll i, j; cin >> n >> i >> j;
        if (n == 0 and i == 0 and j == 0) break;
        vector<bool> is_up(n); {
            ll y = i - 1;
            repeat (k, n) {
                ll mid = 1ll << (n - k - 1);
                if (y < mid) {
                    is_up[n - k - 1] = true;
                    y = mid - y - 1;
                } else {
                    y -= mid;
                }
            }
        }
        string result; {
            ll x = j - 1;
            repeat (k, n) {
                ll mid = 1ll << (n - k - 1);
                if (is_up[k]) {
                    if (x < mid) {
                        result += 'L';
                        x = mid - x - 1;
                    } else {
                        result += 'R';
                        x = mid - (x - mid) - 1;
                    }
                } else {
                    if (x < mid) {
                        result += 'R';
                    } else {
                        result += 'L';
                        x -= mid;
                    }
                }
            }
        }
        cout << result << endl;
    }
    return 0;
}
```

---

# ACM-ICPC 2017 国内予選: F.  リボンたたみ

-   2017年  7月 23日 日曜日 00:39:37 JST
    -   ACを確認
