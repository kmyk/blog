---
layout: post
redirect_from:
  - /writeup/algo/etc/gcj-2016-round1b-a/
  - /blog/2016/05/01/gcj-2016-round1b-a/
date: 2016-05-01T03:54:08+09:00
tags: [ "competitive", "writeup", "google-code-jam", "gcj" ]
"target_url": [ "https://code.google.com/codejam/contest/11254486/dashboard#s=p0" ]
---

# Google Code Jam 2016 Round 1B A. Getting the Digits

競技の問題としては珍しめだなあという印象(転職系のサービスとかでならありそう)

## problem

広義単調増加な数字の列$X$があった。
そのそれぞれの数字をその対応する英単語(例: $0$ $\to$ `ZERO`)で置き換え、結合し、シャッフルしたもの$Y$が与えられる。
$Y$から$X$を復元せよ。

## solution

Dicide the numbers, digit by digit.

The character `Z` is appeared only in the word `ZERO`, so the number of $0$ can be decided by counting `Z`. Next, the `X` is appeared only in the word `SIX`, and so on.

## implementation

``` python
#!/usr/bin/env python3
for t in range(int(input())):
    s = input()
    freq = {}
    words = \
        [ "ZERO"
        , "ONE"
        , "TWO"
        , "THREE"
        , "FOUR"
        , "FIVE"
        , "SIX"
        , "SEVEN"
        , "EIGHT"
        , "NINE"
        ]
    for c in ''.join(words):
        freq[c] = 0
    for c in s:
        freq[c] += 1
    cnt = [0] * 10
    def use(i, n):
        cnt[i] += n
        for c in words[i]:
            freq[c] -= n
    use(0, freq['Z'])
    use(2, freq['W'])
    use(6, freq['X'])
    use(8, freq['G'])
    use(7, freq['S'])
    use(5, freq['V'])
    use(4, freq['F'])
    use(1, freq['O'])
    use(3, freq['R'])
    use(9, freq['E'])
    ans = ''
    for c, n in zip('0123456789', cnt):
        ans += c * n
    print('Case #{}: {}'.format(t+1, ans))
```
