---
category: blog
layout: post
title: "lazy kでquine書いた (iota記法)"
date: 2014-04-17T23:45:00+09:00
tags: [ "quine", "lazyk", "iota" ]
---

-   [@fumieval](https://twitter.com/fumieval)氏のそれの再実装であって、独自性は特に無い
    -   [文字列リテラルが無いLazy Kで黒魔術も力技も使わずにクワイン - fumievalの日記](http://d.hatena.ne.jp/fumiexcel/20120402/1333343067)
-   自己満足性は非常に高いのでおすすめ
-   [前回記事](/blog/2014/04/17/how-to-write-a-quine/)に沿って命名/実装した
    -   もちろん先人の知恵も借りた

<!-- more -->

## code

``` scheme
(load "/path/to/lazier.scm")
(load "/path/to/prelude.scm")
(load "/path/to/prelude-numbers.scm")

(lazy-def 'map '(Y (lambda (recur f xs) (null? xs () (cons (f (car xs)) (recur f (cdr xs)))))))
(lazy-def 'append '(Y (lambda (recur xs ys) (null? xs ys (cons (car xs) (recur (cdr xs) ys))))))
(lazy-def 'concat '(Y (lambda (recur xs) (null? xs () (append (car xs) (recur (cdr xs)))))))

(lazy-def 'star 42) ; apply operator `*'
(lazy-def 'base 105) ; one point basis `i'
(lazy-def 'newline 10)

; if x then `*' else `i'
(lazy-def '(bit->program x) '(x star base))
(lazy-def '(str x) '(map bit->program x))

; #t -> *i*i*ii
; #f -> **i*i*ii*ii
; cons #t -> ***i*i*i*ii**i*i*ii**i*i*i*ii***i*i*i*ii*ii**i*i*ii*i*i*ii*i*i*ii
; cons #f -> ***i*i*i*ii**i*i*ii**i*i*i*ii***i*i*i*ii*ii**i*i*ii**i*i*ii*ii*i*i*ii
; () -> **i*i*ii*i*i*ii
(lazy-def '(bit->data x)
          '(x (str ((lambda (t f) (t (t (t (t (f (t (f (t (f (t (f (f (t (t (f (t (f (t (f (f (t (t (f (t (f (t (f (t (f (f (t (t (t (f (t (f (t (f (t (f (f (t (f (f (t (t (f (t (f (t (f (f (t (f (t (f (t (f (f (t (f (t (f (t (f (f ()))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))) (cons #t) (cons #f))) ; `` cons #t
              (str ((lambda (t f) (t (t (t (t (f (t (f (t (f (t (f (f (t (t (f (t (f (t (f (f (t (t (f (t (f (t (f (t (f (f (t (t (t (f (t (f (t (f (t (f (f (t (f (f (t (t (f (t (f (t (f (f (t (t (f (t (f (t (f (f (t (f (f (t (f (t (f (t (f (f ()))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))) (cons #t) (cons #f))) ; `` cons #f
              ))
(lazy-def '(repr x) '(append (concat (map bit->data x)) (str ((lambda (t f) (t (t (f (t (f (t (f (f (t (f (t (f (t (f (f ())))))))))))))))) (cons #t) (cons #f)))))

(lazy-def '(main input) '(s (lambda (x y) (append (str x) (append y (append (cons newline ()) end-of-output)))) repr code))
(print-as-iota (laze 'main))
```
{:title="quine.scm"}

``` sh
#!/bin/sh
code() {
    gosh quine.scm | sed -e 's/\[code\]$//'
}
quote() {
    # /*/` cons #t/ ; /i/` cons #f/
    tr -t '*i' 'tf' |
    sed -e 's/t/****i*i*i*ii**i*i*ii**i*i*i*ii***i*i*i*ii*ii**i*i*ii*i*i*ii*i*i*ii/g
    ; s/f/****i*i*i*ii**i*i*ii**i*i*i*ii***i*i*i*ii*ii**i*i*ii**i*i*ii*ii*i*i*ii/g
    ; s/$/**i*i*ii*i*i*ii/'
}
echo $(code)$(code | quote)
```
{:title="quine.scm"}

``` sh
$ ./quine.sh > quine.lazy
$ lazy quine.lazy > out.lazy
$ diff quine.lazy out.lazy
```

## ハマりpoints

### strとreprの接合
formatのような関数を用意するのは辛いので、単に`append`を使用したい

lazier.scmは解決できない識別子を`[code]`のようにbracketで囲って出力する  
しかし単に`((lambda (x) (append (str x) (repr x))) code)`とすると、`lambda`が簡約され、`[code]`が式の内部に2つ出現する  
これを回避するために`s`コンビネータを使い、`[code]`が変換後の式の末尾に登場するよう調整する

### 実行が遅い
2分かかった 諦めよう

### デバッグ
何処が違うのか特定するのにひと手間要した  
最終的には、

1.  `s/(i+)/\1 /g`等として、適当に空白で分ける
2.  `wdiff quine.lazy out.lazy | colordiff`として、単語単位diff+色
