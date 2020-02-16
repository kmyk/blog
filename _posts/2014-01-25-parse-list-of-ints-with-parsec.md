---
category: blog
layout: post
date: 2014-01-25T17:50:35+09:00
tags: [ "haskell", "parsec" ]
---

# [Int]をparsecでパースする

``` haskell
>>> parse (many even') "numbers" [0,0,2,4,9999]
Right [0,0,2,4]

>>> parse (many (zero <|> odd') >> eof) "numbers" [0,1,1,3,5,8]
Left "numbers" (line 1, column 6):
unexpected 8
expecting zero, odd or end of input
```

`[Int]`だとおふざけだが、複雑な何かだと便利かもしれない[^1]


<!-- more -->

`Monad m => Stream [tok] m tok`とあるので、`list`に包めば何でもparse可能に見える  
しかし`Stream s m Char =>`制約の代わりに`(Stream s m tok, Eq tok) =>`なものが<del>見当たらない</del>  
標準の`satisfy`さえ`:: Stream s m Char => (Char -> Bool) -> ParsecT s u m Char`と、`Char`しか受け入れてくれない[^2]  
<del>仕方がないので</del><ins>仕方なくなかった([追記](#ins))</ins>`satisfy`を再定義する

``` haskell
updatePos :: SourcePos -> Column -> SourcePos
updatePos p n = setSourceColumn p (sourceColumn p + n)

satisfy' :: (Stream s m t, Show t) => (t -> Bool) -> ParsecT s u m t
satisfy' f = tokenPrim show
    (\ pos _ _ -> updatePos pos 1)
    (\ c -> if f c then Just c else Nothing)
```

`Text.Parsec.Char`のほぼ全ての関数[^3]は`satisfy`経由で定義されているので、  
`Text.Parsec.Int`を作ることが可能になる

``` haskell
zero :: (Num a, Eq a, Stream s m a, Show a) => ParsecT s u m a
zero = satisfy' (== 0) <?> "zero"
even', odd' :: (Integral a, Stream s m a, Show a) => ParsecT s u m a
even' = satisfy' even <?> "even"
odd' = satisfy' odd <?> "odd"
```

## 参考
-   [Hackage: parsec: Monadic parser combinators](http://hackage.haskell.org/package/parsec)
-   [Haskell - Parsecのソースちら見(3) - Qiita](http://qiita.com/hiratara/items/a451b04fb19bfcc7ff08)


## 追記 {#ins}
定義されてた

[Text.Parsec.Combinator.anyToken](http://hackage.haskell.org/package/parsec-3.1.5/docs/Text-Parsec-Combinator.html#v:anyToken)  
`anyToken :: (Stream s m t, Show t) => ParsecT s u m t`

なので

``` haskell
satisfy' f = try $ lookAhead (anyToken >>= (\ x -> if f x then return x else unexpected $ show x))
```
としても良い


---

# [Int]をparsecでパースする

[^1]: 便利でないかもしれない
[^2]: parser-libraryなので当然
[^3]: `Text.Parsec.Char.string`以外の全て
[^4]: 似たようなのはあった (追記参照)
