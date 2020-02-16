---
layout: post
redirect_from:
  - /writeup/algo/atcoder/agc-001-d/
  - /blog/2017/10/03/agc-001-d/
date: "2017-10-03T05:44:31+09:00"
tags: [ "competitive", "writeup", "atcoder", "agc", "graph", "palindrome" ]
---

# AtCoder Grand Contest 001: D - Arrays and Palindrome

## solution

等式制約の片側(つまり「先頭の a1 文字、続く a2 文字、さらに続く a3 文字 ... はすべて回文である。」)を図示すると次のようになる。
$a = ( 5, 8, 1, 3 )$である。

```
          +-------------+
+-------+ | +---------+ |
| +---+ | | | +-----+ | |   +---+
| |   | | | | | +-+ | | |   |   |
A B C b a D E F G g f e d H I J i
```

このようなグラフを$b$についても作って繋げたときに連結になっていればよい。
各点の次数は高々$2$なので、連結であれば木か閉路のどちらか。
$a$中に奇数の項が$3$つ以上あるとき次数を考えれば明らかに不可能である。

$a$中の奇数の項が$2$つ以下なら可能である。
これは両端に奇数の項を配し、偶数の項には$1$だけずらして以下のように重ねればできる。

```
+-------------+
| +---------+ |
| | +-----+ | |
| | | +-+ | | |
A B C D d c b a z
  | | | +-+ | | |
  | | +-----+ | |
  | +---------+ |
  +-------------+
```

## implementation

``` python
#!/usr/bin/env python3
def solve(n, m, a):
    odd = []
    even = []
    for a_i in a:
        if a_i % 2 == 0:
            even += [ a_i ]
        else:
            odd += [ a_i ]
    if len(odd) >= 3:
        return None
    a, b = [], []
    if odd:
        x = odd.pop()
        a += [ x ]
        b += [ x - 1 ]
    else:
        x = even.pop()
        a += [ x ]
        b += [ x - 1 ]
    a += even
    b += even
    if odd:
        x = odd.pop()
        a += [ x ]
        b += [ x + 1 ]
    else:
        b += [ 1 ]
    return a, b

n, m = map(int, input().split())
a = list(map(int, input().split()))
it = solve(n, m, a)
if it is None:
    print('Impossible')
else:
    a, b = it
    b = list(filter(lambda b_i: b_i, b))
    print(*a)
    print(len(b))
    print(*b)
```
