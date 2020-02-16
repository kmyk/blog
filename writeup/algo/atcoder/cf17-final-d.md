---
layout: post
alias: "/blog/2017/11/26/cf17-final-d/"
date: "2017-11-26T10:02:25+09:00"
tags: [ "competitive", "writeup", "atcoder", "codefestival", "greedy", "dp" ]
"target_url": [ "https://beta.atcoder.jp/contests/cf17-final-open/tasks/cf17_final_d" ]
---

# CODE FESTIVAL 2017 Final: D - Zabuton

正当性の証明についてhamkoさんと議論した。
editorialは読めば分かった気にはなれる(当然)のだが、もうちょっと厳密で一般的なところが気になる。
私に関しては貪欲法に関する証明のまわりが弱いので不安感が生じているはずで、マトロイドとか離散凸解析とかそのあたりをするべきなのだろうなという思いになって終わった。

## solution

見る順序は$H\_i + P\_i$の順のみでよい。この順に$i$番目まで見て$j$個取ったときの高さの最小値を$\mathrm{dp}(i, j)$としてDP。$O(N^2)$。

スケジューリング問題と見るのが楽という指摘もあった:

<blockquote class="twitter-tweet" data-lang="ja"><p lang="ja" dir="ltr">個人的には、このようなスケジューリング問題に落とせるという話が一番納得できました<a href="https://t.co/LeSuktj3Eg">https://t.co/LeSuktj3Eg</a></p>&mdash; りあん (@rian_tkb) <a href="https://twitter.com/rian_tkb/status/934592094554882048?ref_src=twsrc%5Etfw">2017年11月26日</a></blockquote>
<script async src="https://platform.twitter.com/widgets.js" charset="utf-8"></script>

## implementation

``` c++
#include <algorithm>
#include <cstdio>
#include <tuple>
#include <vector>
#define repeat(i, n) for (int i = 0; (i) < int(n); ++(i))
#define repeat_reverse(i, n) for (int i = (n)-1; (i) >= 0; --(i))
#define whole(x) begin(x), end(x)
using ll = long long;
using namespace std;
template <class T> inline void setmin(T & a, T const & b) { a = min(a, b); }

constexpr ll inf = ll(1e18)+9;
int main() {
    // input
    int n; scanf("%d", &n);
    vector<pair<int, int> > hps(n);
    repeat (i, n) {
        int h, p; scanf("%d%d", &h, &p);
        hps[i] = { h, p };
    }
    // solve
    sort(whole(hps), [&](pair<int, int> hp1, pair<int, int> hp2) {
        return hp1.first + hp1.second < hp2.first + hp2.second;
    });
    vector<ll> dp(n + 1, inf);
    dp[0] = 0;
    for (auto hp : hps) {
        int h, p; tie(h, p) = hp;
        repeat_reverse (j, n) {
            if (dp[j] <= h) {
                setmin(dp[j + 1], dp[j] + p);
            }
        }
    }
    int result = 0;
    repeat (i, n + 1) {
        if (dp[i] < inf) {
            result = i;
        }
    }
    // output
    printf("%d\n", result);
    return 0;
}
```
