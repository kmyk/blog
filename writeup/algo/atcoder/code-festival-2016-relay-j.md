---
layout: post
redirect_from:
  - /blog/2016/11/30/code-festival-2016-relay-j/
date: "2016-11-30T01:33:34+09:00"
tags: [ "competitive", "writeup", "atcoder", "codefestival" ]
"target_url": [ "https://beta.atcoder.jp/contests/cf16-relay-open/tasks/relay_j" ]
---

# CODE FESTIVAL 2016 Relay: J - 連結チェスボード / Connected Checkerboard

本番の終了後、担当だったsigmaさんが面白かったと言っていた。わかる。

## solution

以下のようにまとめていく。

```
# # # # # # # # # # # # # # # #
 # # # # # # # # # # # # # # # #
# # # # # # # # # # # # # # # #
 # # # # # # # # # # # # # # # #
# # # # # # # # # # # # # # # #
 # # # # # # # # # # # # # # # #
# # # # # # # # # # # # # # # #
 # # # # # # # # # # # # # # # #
```

```
### ### ### ### ### ### ### ###
 # # # # # # # # # # # # # # # #
# ### ### ### ### ### ### ### ##
 # # # # # # # # # # # # # # # #
### ### ### ### ### ### ### ###
 # # # # # # # # # # # # # # # #
# ### ### ### ### ### ### ### ##
 # # # # # # # # # # # # # # # #
```

```
####### ####### ####### #######
 # # # # # # # # # # # # # # # #
# ### ### ### ### ### ### ### ##
 # # # # # # # # # # # # # # # #
### ####### ####### ####### ####
 # # # # # # # # # # # # # # # #
# ### ### ### ### ### ### ### ##
 # # # # # # # # # # # # # # # #
```

```
############### ###############
 # # # # # # # # # # # # # # # #
# ### ### ### ### ### ### ### ##
 # # # # # # # # # # # # # # # #
### ####### ####### ####### ####
 # # # # # # # # # # # # # # # #
# ### ### ### ### ### ### ### ##
 # # # # # # # # # # # # # # # #
```

```
###############################
 # # # # # # # # # # # # # # # #
# ### ### ### ### ### ### ### ##
 # # # # # # # # # # # # # # # #
### ####### ####### ####### ####
 # # # # # # # # # # # # # # # #
# ### ### ### ### ### ### ### ##
 # # # # # # # # # # # # # # # #
```

端は千切れているので、適当につないでおく。

```
################################
## # # # # # # # # # # # # # # #
# ### ### ### ### ### ### ### ##
## # # # # # # # # # # # # # # #
### ####### ####### ####### ####
## # # # # # # # # # # # # # # #
# ### ### ### ### ### ### ### ##
################################
```

## implementation

``` c++
#include <iostream>
#include <vector>
#define repeat(i,n) for (int i = 0; (i) < (n); ++(i))
using namespace std;
template <typename X, typename T> auto vectors(X x, T a) { return vector<T>(x, a); }
template <typename X, typename Y, typename Z, typename... Zs> auto vectors(X x, Y y, Z z, Zs... zs) { auto cont = vectors(y, z, zs...); return vector<decltype(cont)>(x, cont); }
int main() {
    // input
    int n; cin >> n;
    // compute
    vector<vector<bool> > f = vectors(n, n, bool());
    for (int k = 1; k <= n; k *= 2) {
        repeat (y,n) repeat (x,n) {
            if (y % k == 0 and (y + x) % (2*k) == (k-1)) f[y][x] = true;
        }
    }
    repeat (y,n) f[y][0] = f[y][n-1] = true;
    repeat (x,n) f[0][x] = f[n-1][x] = true;
    // output
    int k = 0;
    repeat (y,n) repeat (x,n) if (f[y][x] and (y + x) % 2 == 1) ++ k;
    cout << k << endl;
    repeat (y,n) repeat (x,n) if (f[y][x] and (y + x) % 2 == 1) cout << x << ' ' << y << endl;
    return 0;
}
```
