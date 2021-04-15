---
layout: post
redirect_from:
  - /writeup/algo/etc/poj-2823/
  - /blog/2016/11/27/poj-2823/
date: "2016-11-27T23:46:28+09:00"
tags: [ "competitive", "writeup", "poj", "pku", "sliding-window-minimum" ]
"target_url": [ "http://poj.org/problem?id=2823" ]
---

# PKU JudgeOnline 2823: Sliding Window

スライド最小値の例題として。蟻本にも載ってるらしいが知らなかった(覚えてなかった)。

## solution

スライド最小値。$O(N)$。

スライド最小値とは、列上の区間について最小値を取得およびその区間の両端での拡大と左端での縮小が各$O(1)$でできるアルゴリズム。
値と元の列でのindexの対の列$( (a\_{i_0}, i_0), (a\_{i_1}, i_1), \dots, (a\_{i\_{n-1}}, i\_{n-1}) )$で$i_0 \lt i_1 \lt \dots \lt i\_{n-1}$と$a\_{i_0} \le a\_{i_1} \le \dots \le a\_{i\_{n-1}}$を満たすものを持ち、$a\_{i_0}$が最小値、区間の拡大は端に要素を追加して条件を保つように削り、縮小はindexを見て一致してたら削る。
右端での縮小がだめなのは、右端への追加の際に捨てた情報を取り戻せないため。
区間が動く対象は列である必要はなく、例えば木でもよい。
first-in first-outの仮定を使用せず一般に集合でやると`std::multiset`をそのまま使って$O(N\log N)$だろうが、定数倍の意味も含めて高速。

## implementation

-   `G++`ではなく`C++`を選択しないとTLE
-   `std::deque`でなくて配列を使わないとTLE

``` c++
#include <cstdio>
#include <vector>
#define repeat(i,n) for (int i = 0; (i) < (n); ++(i))
using namespace std;
pair<int,int> data[1000000];
template <typename T>
struct sliding_window {
    int l, r;
    bool minmax;
    sliding_window(bool a_minmax) : minmax(a_minmax), l(0), r(0) {}
    T top() { return data[l].first; }
    void push(int i, T a) { while (l != r and ( minmax == 0 ? a < data[r-1].first : a > data[r-1].first )) -- r; data[r ++] = make_pair(a, i); }
    void pop(int i) { if (data[l].second == i) ++ l; }
};
int main() {
    int n, k; scanf("%d%d", &n, &k);
    vector<int> a(n); repeat (i,n) scanf("%d", &a[i]);
    repeat (minmax,2) {
        sliding_window<int> que = sliding_window<int>(minmax);
        repeat (i,n) {
            que.push(i, a[i]);
            if (k <= i+1) {
                if (k < i+1) printf(" ");
                printf("%d", que.top());
                que.pop(i-k+1);
            }
        }
        printf("\n");
    }
    return 0;
}
```
