---
category: blog
layout: post
date: 2014-12-16T22:40:43+09:00
tags: [ "haskell", "monoid", "monad", "category-theory" ]
math: true
---

# MonoidからMonadを作る

``` haskell
import Data.Monoid

data Stamp m a = Stamp a m

instance Monoid m => Monad (Stamp m) where
    return a = Stamp a mempty
    (Stamp a m) >>= f = let Stamp b n = f a in Stamp b (m <> n)

stamp :: Monoid m => m -> Stamp m ()
stamp = Stamp ()

runStamp :: Stamp m a -> (a, m)
runStamp (Stamp a m) = (a, m)
```

任意のモノイドからモナドが作れると聞いて書いてみた。monoidal stamping monadと言うそうです。

## <time>Mon Dec 22 23:26:10 JST 2014</time> : 追記

<blockquote class="twitter-tweet" data-conversation="none" lang="en"><p><a href="https://twitter.com/solo_rab">@solo_rab</a> というか、Writerモナドが monoidal stamping monad そのものです。</p>&mdash; Masahiro Sakai (@masahiro_sakai) <a href="https://twitter.com/masahiro_sakai/status/546970563453808640">December 22, 2014</a></blockquote><script async src="//platform.twitter.com/widgets.js" charset="utf-8"></script>

ありがたいことに訂正をいただいた。

つまりこの`Stamp`は`Writer`そのものであるらしい。実際、`mtl`での`Writer`の定義[^1]を見ると

``` haskell
newtype Writer w a = Writer (a, w)
instance (Monoid w) => Monad (Writer w) where
    ...
```

であり、`Monad`の実装も一致している。

<!-- more -->

## 例

<del>自由モノイド`[a]`はWriter</del>

monoidal stamping monadは`Writer`そのもの

``` haskell
>>> runStamp $ do { stamp "foo" ; (do { stamp "bar" ; return "baz" }) >>= stamp }
((), "foobarbaz")
>>> runWriter $ do { tell "foo" ; (do { tell "bar" ; return "baz" }) >>= tell }
((), "foobarbaz")
```

左自明モノイド`First a`は単一代入

``` haskell
>>> runStamp $ do { stamp (First (Just 'a')) ; stamp (First (Just 'b')) ; return 'c' }
('c', First (Just 'a'))
```

右自明モノイド`Last a`は破壊的代入

``` haskell
>>> runStamp $ do { stamp (Last (Just 'a')) ; stamp (Last (Just 'b')) ; return 'c' }
('c', First (Just 'b'))
```

自明モノイド`()`はIdentity

``` haskell
>>> runStamp $ do { stamp () ; stamp () ; return 42 }
(42, ())
```

面白いですね。

## 詳しく

モノイド$(M,\cdot,e)$に対し

-   関手 $X \rightarrowtail X \times M$
-   単位元 $\eta(x) := x \times e$
-   乗法 $\mu((x \times n) \times m) = x \times (m \cdot n)$

とすると、これはモナド(monoidal stamping monad)になる。

同様にcomonoidからcomonadが作れるらしい。


## 参考

-   [単一代入のモノイド、スタンピングモナド、モナド工場 - 檜山正幸のキマイラ飼育記](http://d.hatena.ne.jp/m-hiyama/20090701/1246410984)
-   [mtl-1.1.0.2 Control.Monad.Writer.Lazy](https://hackage.haskell.org/package/mtl-1.1.0.2/docs/Control-Monad-Writer-Lazy.html)

[^1]: ここでは`WriterT`を使わない古いものを用いた
