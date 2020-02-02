---
category: blog
layout: post
title: "haskellのlensの使い方 (基本)"
date: 2014-12-14T00:00:00+09:00
tags: [ "haskell", "lens" ]
---

ekmett先生のlensに関して

`Lens'`は便利に使えはするけど、`Prism`,`Iso`,`Traversal`,`Fold`みたいなのは触ったことがなかったので調べた。

<!-- more -->

## Lensの利用

``` haskell
import Control.Lens
```

して

``` haskell
>>> ("hello",("world","!!!")) ^. _2 . _1
"world"
>>> ("hello",("world","!!!")) & _2 . _1 .~ 42
("hello",(42,"!!!"))
>>> ("hello",("world","!!!")) & _2 . _1 %~ map toUpper
("hello",("WORLD","!!!"))
```

みたいに使う。優先順位は以下のようになっている:

``` haskell
>>> ("hello",("world","!!!")) ^. (_2 . _1)
>>> ("hello",("world","!!!")) & ((_2 . _1) .~ 42)
>>> ("hello",("world","!!!")) & ((_2 . _1) %~ map toUpper)
```

同じ動きをする非演算子もある:

``` haskell
>>> view (_2 . _1) ("hello",("world","!!!"))
"world"
>>> set (_2 . _1) 42 ("hello",("world","!!!"))
("hello",(42,"!!!"))
>>> over (_2 . _1) (map toUpper) ("hello",("world","!!!"))
("hello",("WORLD","!!!"))
```

また、

``` haskell
x & f = f x
```

``` haskell
>>> [0..] & tail & take 4 & product & show
"24"
```

である。関数合成が向きのせいで苦手な人は(lensとは無関係に)常用するとよいと思う。

### Lensを作る

この`_1`,`_2`のようなものを作るには大抵

``` haskell
{-# LANGUAGE TemplateHaskell #-}
data Foo a = Foo { _bar :: Int, _baz :: Int, _quux :: a }
makeLenses ''Foo
```

とする。この場合

``` haskell
bar, baz :: Lens' (Foo a) Int
quux :: Lens (Foo a) (Foo b) a b
```

のように定義され

``` haskell
>>> Foo 3 4 "foo" & baz %~ succ
Foo {_bar = 3, _baz = 5, _quux = "foo"}
>>> Foo 3 4 "foo" & quux .~ [2,3]
Foo {_bar = 3, _baz = 4, _quux = [2,3]}
```

のように使える。`Lens' s a = Lens s s a a`である。

また

``` haskell
lens :: (s -> a) -> (s -> b -> t) -> Lens s t a b
```

を使って

``` haskell
bar' :: Lens' (Foo a) Int
bar' = lens _bar (\ s b -> s { _bar = b })
```

のように、自分で定義を与えて作ることもできる。


## Lensっぽいもの

取り出すだけでいい/入れるだけでいいものも同じように扱うことができる。例えばlistの長さの取得や標準出力への出力は

``` haskell
>>> "hoge" ^. to length
4
>>> let _print = sets (\ f x -> do { a <- f <$> x ; print a })
>>> return () & _print .~ "hello"
"hello" -- *side effect*
```

のように作ることができる。それぞれ`Getter`,`Setter`という型であり、以下の関数で作られる:

``` haskell
to :: (s -> a) -> Getter s a
sets :: ((a -> b) -> s -> t) -> Setter s t a b
mapped :: Functor f => Setter (f a) (f b) a b
```

結論だけ言うと、`Getter`は関数、`Setter`は関手に、lensのinterfaceを与えたものです。


## 様々なlens類

最後に全体図を見てみよう。

![*class階層図*](hierarchy.png)

`Lens`は`Getter`かつ`Setter`であるものの中で最も制約が弱いもの、なにか上限のようなものだと分かる。つまり`view`,`set`,`over`などは`Getter`,`Setter`のmethodだったということです。

問題ないレベルではあるが補足: 図はところどころhaddockと食い違い(見易さのために手が入ってたり、単に古かったり)がある。この記事でも図にならって見易く型を書いています。

## 続く [Haskellのlensの使い方 (詳しめ)](/blog/2014/12/14/how-to-use-lens-b/)

長くなったので分割しました。

## 参考

-   <https://hackage.haskell.org/package/lens>
-   <https://github.com/ekmett/lens>
-   [Lens で Haskell をもっと格好良く！ for 2013/3/31 ekmett 勉強会 ちゅーん](http://www.slideshare.net/itsoutoftunethismymusic/ekmett-17955009)
    -   基本から`Lens`と`Traversable`の関係
-   [Lensで行こう！ - みょんさんの。](http://myuon-myon.hatenablog.com/entries/2012/12/28)
    -   基本から`Lens`と`Getting`,`Setting`の関係
-   [Lensで行こう！(2):Isoへの拡張 - みょんさんの。](http://myuon-myon.hatenablog.com/entries/2012/12/28)
    -   `Prism`や`Lens`

記述時のlensのversionは4.6.0.1でした。

## This post is the No.15 article of [Haskell Advent Calendar 2014](http://qiita.com/advent-calendar/2014/haskell)
- Day 13: [mr\_konnさん](http://qiita.com/mr_konn)
- Day 15: [ruiccさん](http://qiita.com/ruicc)
