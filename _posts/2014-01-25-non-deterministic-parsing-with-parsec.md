---
category: blog
layout: post
date: 2014-01-25T18:28:27+09:00
tags: [ "haskell", "parsec" ]
---

# parsecで非決定的パース

ざっくりparseして、出力を`filter`や`head`で加工したかった

``` haskell
fork :: [ParsecT s u [] a] -> ParsecT s u [] a
fork = join . lift
```

※ list-monadで非決定的計算できるのは、parsecに限った話ではない

<!-- more -->

`ParsecT`をlist-monadと合成するだけなので、上のように定義する  
型注釈なしなら`join . lift :: (Monad (t m), Monad m, MonadTrans t) => m (t m a) -> t m a`

非決定的の厳密な定義を知らないが、chooseとfail[^1]が使えるので非決定的と呼んでいいはず  
ただし`fail = fork []`であって、`Prelude.fail`(`Text.Parsec.parserFail`)ではない

## 例

``` haskell
p = try p' <|> many1 anyChar where
    p' = do
        x <- manyTill anyChar $ char '+'
        fork
            [ return x
            , (x ++) <$> p
            ]

>>> runParserT p () "input" "a+b+c" where
[Right "a",Right "ab",Right "abc"]
```

``` haskell
q = try q' <|> fork [] where
    q' = do
        x <- p
        fork
            [ return [x]
            , (x :) <$> q
            ]

>>> runParserT p () "input" "a+b+c" where
[Right ["a"],Right ["a","b"],Right ["a","b","c"],Right ["a","bc"],Right ["ab"],Right ["ab","c"],Right ["abc"]]
```

`ここではきものをぬいでください`のような文をparseするとき便利なんじゃないでしょうか


## 参考

-   [On Lisp --- 非決定性](http://www.asahi-net.or.jp/~kc7k-nd/onlispjhtml/nondeterminism.html)
-   [雑草ブログ Listモナドで非決定的計算をしよう](http://hooki.blog23.fc2.com/blog-entry-74.html)

---

# parsecで非決定的パース

[^1]: On Lispの説明による
