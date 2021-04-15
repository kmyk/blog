---
layout: post
redirect_from:
  - /writeup/golf/yukicoder/3028/
  - /blog/2017/04/01/yuki-3028/
date: "2017-04-01T02:31:23+09:00"
tags: [ "competitive", "writeup", "yukicoder", "submit-debug", "guessing", "golf", "oeis" ]
"target_url": [ "http://yukicoder.me/problems/no/3028" ]
---

# Yukicoder No.3028 Function Guessing

後から見ると解説欄に*謝罪*の文字が見えましたが、私は好きです。解けたからというのはあるかも。

これのおかげでantaさんを下して$1$位を取れた: <http://yukicoder.me/contests/161/table>

## solution

guessing あるいは MD5探索。

guessingなら以下のように。

1.  単調増加性を仮定して入力$4$のときの出力をsubmit debugして当てる
2.  をれを元にOEISに投げる: <http://oeis.org/search?q=2%2C4%2C9%2C18%2C37>
3.  残りをsubmit debugで割り出す
    -   OEISの数列は途中までは当たりでも一致するものはなく、近い値を投げてみる必要がある
4.  golf

MD5探索なら$0$WAが可能。
ちょうどそのようなツールを書いたところなので叩いて待つだけ: <https://github.com/kmyk/libproofofwork>。
ただし探索文字に`>`を入れ忘れないようにしたい。

## implementation

``` ruby
#!/usr/bin/env ruby
f='600>>9-n'
n=gets().to_i
puts(n==-1?f:eval(f))
```
