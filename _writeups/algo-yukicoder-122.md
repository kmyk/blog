---
layout: post
redirect_from:
  - /writeup/algo/yukicoder/122/
  - /blog/2016/12/20/yuki-122/
date: "2016-12-20T22:15:35+09:00"
tags: [ "competitive", "writeup", "yukicoder", "implementation" ]
"target_url": [ "http://yukicoder.me/problems/298" ]
---

# Yukicoder No.122 傾向と対策：門松列（その３）

途中までdistinct制約を忘れていた(WAを生やしてから気付いた)こともあり、比較的実装が重いものになった。
後輩と食堂の唐揚げを賭けて勝負していたのだが、筋肉不足と合わさって実装が間に合わず負けてしまった。

## solution

下側の最大値と上側の最小値について総当たり。$O((\max_x x\_{\max})^2)$。

$\max \\{ a, c, e, g \\} \lt \min \\{ b, d, f \\}$の組および$\max \\{ b, d, f \\} \lt \min \\{ a, c, e, g \\}$の組についてはそのまま全て試す。

$\min$/$\max$がある値$k$になるときの$a,c,e,g$/$b,d,f$の選び方はそれぞれの$k$について$O(1)$で求まる。
例えばある$k$に関し$k = \max \\{ a,c,e,g \\}$な$a,c,e,g$を求めるとしよう。
まず$k = x$となるような$x \in \\{ a, c, e, g \\}$を固定して計算し、それぞれ足し合わせる。
$x = a$とする。他の$3$つの変数$c,e,g$についてそれぞれの動く区間$[c_l, c_r), [e_l, e_r), [g_l, g_r)$が定まる。
$a,c,e,g$はdistinctでないといけないので単純に$(c_r - c_l)(e_r - e_l)(g_r - g_l)$とはできず、区間は重なったり重ならなかったりしているので$(c_r - c_l)(e_r - e_l - 1)(g_r - g_l - 2)$ともできない。
そこで$\\{ c_l, c_r, e_l, e_r, g_l, g_r \\}$を整列し最大$5$個の区間に切り、$c, e, g$がどの区間に入るかの$5^3$通りを試して足し合わせればよい。

## implementation

ちょうど$100$行。

``` c++
#include <iostream>
#include <vector>
#include <algorithm>
#include <array>
#include <set>
#include <tuple>
#define repeat(i,n) for (int i = 0; (i) < int(n); ++(i))
#define repeat_from(i,m,n) for (int i = (m); (i) < int(n); ++(i))
#define whole(f,x,...) ([&](decltype((x)) whole) { return (f)(begin(whole), end(whole), ## __VA_ARGS__); })(x)
typedef long long ll;
using namespace std;
const int mod = 1e9+7;
ll choose_distinct(pair<int, int> x1, pair<int, int> x2, pair<int, int> x3) {
    int al, ar; tie(al, ar) = x1; // [l, r]
    int bl, br; tie(bl, br) = x2;
    int cl, cr; tie(cl, cr) = x3;
    if (al > ar) return 0;
    if (bl > br) return 0;
    if (cl > cr) return 0;
    ++ ar; // [l, r)
    ++ br;
    ++ cr;
    vector<int> xs { al, ar, bl, br, cl, cr };
    whole(sort, xs);
    xs.erase(whole(unique, xs), xs.end());
    vector<int> length(xs.size()-1);
    vector<array<bool, 3> > contained(xs.size()-1);
    repeat (i,xs.size()-1) {
        int l = xs[i];
        int r = xs[i+1];
        length[i] = r - l;
        contained[i][0] = al <= l and r <= ar;
        contained[i][1] = bl <= l and r <= br;
        contained[i][2] = cl <= l and r <= cr;
    }
    ll acc = 0;
    repeat (i,contained.size()) if (contained[i][0]) {
        repeat (j,contained.size()) if (contained[j][1]) {
            repeat (k,contained.size()) if (contained[k][2]) {
                acc += length[i] *(ll) max(0, length[j] - (j == i)) % mod * max(0, length[k] - (k == i) - (k == j)) % mod;
            }
        }
    }
    return acc % mod;
}
ll choose_distinct(pair<int, int> x1, pair<int, int> x2) {
    return choose_distinct(x1, x2, { 0, 0 });
}
int main() {
    const int A = 0, B = 1, C = 2, D = 3, E = 4, F = 5, G = 6;
    int x_min[7], x_max[7]; repeat (i,7) cin >> x_min[i] >> x_max[i]; // [l, r]
    auto is_in = [&](int a, int x) { return x_min[x] <= a and a <= x_max[x]; };
    auto range_le = [&](int upper, int x) { return make_pair(x_min[x], min(upper, x_max[x])); };
    auto range_ge = [&](int lower, int x) { return make_pair(max(lower, x_min[x]), x_max[x]); };
    int max_x_max= *whole(max_element, x_max);
    vector<int> acc_aceg_min(max_x_max+1);
    repeat(min_aceg, max_x_max+1) {
        ll acc = 0;
        if (is_in(min_aceg, A)) acc += choose_distinct( range_ge(min_aceg+1, C), range_ge(min_aceg+1, E), range_ge(min_aceg+1, G) );
        if (is_in(min_aceg, C)) acc += choose_distinct( range_ge(min_aceg+1, A), range_ge(min_aceg+1, E), range_ge(min_aceg+1, G) );
        if (is_in(min_aceg, E)) acc += choose_distinct( range_ge(min_aceg+1, A), range_ge(min_aceg+1, C), range_ge(min_aceg+1, G) );
        if (is_in(min_aceg, G)) acc += choose_distinct( range_ge(min_aceg+1, A), range_ge(min_aceg+1, C), range_ge(min_aceg+1, E) );
        acc_aceg_min[min_aceg] = acc % mod;
    }
    vector<int> acc_aceg_max(max_x_max+1);
    repeat (max_aceg, max_x_max+1) {
        ll acc = 0;
        if (is_in(max_aceg, A)) acc += choose_distinct( range_le(max_aceg-1, C), range_le(max_aceg-1, E), range_le(max_aceg-1, G) );
        if (is_in(max_aceg, C)) acc += choose_distinct( range_le(max_aceg-1, A), range_le(max_aceg-1, E), range_le(max_aceg-1, G) );
        if (is_in(max_aceg, E)) acc += choose_distinct( range_le(max_aceg-1, A), range_le(max_aceg-1, C), range_le(max_aceg-1, G) );
        if (is_in(max_aceg, G)) acc += choose_distinct( range_le(max_aceg-1, A), range_le(max_aceg-1, C), range_le(max_aceg-1, E) );
        acc_aceg_max[max_aceg] = acc % mod;
    }
    vector<int> acc_bdf_min(max_x_max+1);
    repeat (min_bdf, max_x_max+1) {
        ll acc = 0;
        if (is_in(min_bdf, B)) acc += choose_distinct( range_ge(min_bdf+1, D), range_ge(min_bdf+1, F) );
        if (is_in(min_bdf, D)) acc += choose_distinct( range_ge(min_bdf+1, B), range_ge(min_bdf+1, F) );
        if (is_in(min_bdf, F)) acc += choose_distinct( range_ge(min_bdf+1, B), range_ge(min_bdf+1, D) );
        acc_bdf_min[min_bdf] = acc % mod;
    }
    vector<int> acc_bdf_max(max_x_max+1);
    repeat (max_bdf, max_x_max+1) {
        ll acc = 0;
        if (is_in(max_bdf, B)) acc += choose_distinct( range_le(max_bdf-1, D), range_le(max_bdf-1, F) );
        if (is_in(max_bdf, D)) acc += choose_distinct( range_le(max_bdf-1, B), range_le(max_bdf-1, F) );
        if (is_in(max_bdf, F)) acc += choose_distinct( range_le(max_bdf-1, B), range_le(max_bdf-1, D) );
        acc_bdf_max[max_bdf] = acc % mod;
    }
    ll ans = 0;
    repeat_from (mx,1,max_x_max+1) {
        repeat_from (mn,mx+1,max_x_max+1) {
            ans += acc_aceg_max[mx] *(ll)  acc_bdf_min[mn] % mod;
            ans +=  acc_bdf_max[mx] *(ll) acc_aceg_min[mn] % mod;
        }
        ans %= mod;
    }
    cout << ans << endl;
    return 0;
}
```
