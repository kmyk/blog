---
layout: post
redirect_from:
  - /writeup/algo/etc/icpc-2017-domestic-d/
  - /blog/2017/07/14/icpc-2017-domestic-d/
date: "2017-07-14T23:50:39+09:00"
tags: [ "competitive", "writeup", "icpc", "icpc-domestic", "case-analysis" ]
---

# ACM-ICPC 2017 国内予選: D. 弁当作り

問題文の$1 \le n \times m \le 500$は太字で書かれていて親切。しかし印刷した紙ではまったく気付かなかった。

## solution

$n \times m \le 500$の制約を使って場合分け。$n$が小さいときはレシピの部分集合を全部試して$O(2^nm)$。$m$が小さいときは余った食材を引数とするDPで$O(n2^m)$。

## implementation

``` c++
#include <bitset>
#include <cassert>
#include <iostream>
#include <tuple>
#include <vector>
#define repeat(i, n) for (int i = 0; (i) < (n); ++ (i))
using namespace std;

int main() {
    while (true) {
        int n, m; cin >> n >> m;
        if (n == 0 and m == 0) break;
        vector<vector<bool> > b(n, vector<bool>(m));
        repeat (y, n) {
            repeat (x, m) {
                char c; cin >> c;
                b[y][x] = c - '0';
            }
        }
        int result = 0;
        // if ((1ll << n) < (n * (1ll << m))) {
        if (m >= 20) {
            // n is small
            vector<bitset<500> > bs(n);
            repeat (y, n) {
                repeat (x, m) {
                    bs[y][x] = b[y][x];
                }
            }
            vector<pair<bitset<500>, int> > cur, prv;
            cur.emplace_back(bitset<500>(), 0);
            repeat (i, n) {
                cur.swap(prv);
                cur = prv;
                for (auto const & it : prv) {
                    bitset<500> bs_j; int cnt; tie(bs_j, cnt) = it;
                    if ((bs[i] ^ bs_j).none()) {
                        result = max(result, cnt + 1);
                    }
                    cur.emplace_back(bs[i] ^ bs_j, cnt + 1);
                }
            }
        } else {
            assert (m < 30);
            // m is small
            vector<int> bi(n);
            repeat (y, n) {
                repeat (x, m) {
                    if (b[y][x]) {
                        bi[y] |= 1 << x;
                    }
                }
            }
            vector<int> cur(1 << m, -1), prv;
            cur[0] = 0;
            repeat (i, n) {
                cur.swap(prv);
                cur = prv;
                repeat (j, 1 << m) if (prv[j] != -1) {
                    if ((bi[i] ^ j)  == 0) {
                        result = max(result, prv[j] + 1);
                    }
                    cur[bi[i] ^ j] = max(cur[bi[i] ^ j],  prv[j] + 1);
                }
            }
        }
        cout << result << endl;
    }
}
```
