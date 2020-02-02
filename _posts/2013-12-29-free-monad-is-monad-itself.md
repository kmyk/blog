---
category: blog
layout: post
title: "free monadとはmonadそのものである"
date: 2013-12-29T17:22:11+09:00
tags: [ "haskell", "category-theory" ]
---

以前少し挑戦して敗れたが、ふと思い出してリベンジした

結論としては`free monad`とはmonadをdataとして表現したものであると

``` haskell
data Free f a = Pure a | Free (f (Free f a))
instance Functor f => Monad (Free f) where
    return = Pure
    Pure a >>= k = k a
    Free fm >>= k = Free (fmap (>>=k) fm)
```

<!-- more -->

## 型のイメージ
型レベルで、`ffffffffa`や`ffa`のような構造を畳み込む  
つまり`Free f a`は`fffffffa`と読み替えられる

たとえば

-   `Free [] a` ~ `[[[[[a]]]]]`
-   `Free Maybe a` ~ `Maybe (Maybe (Maybe a))`


## 値と型
``` haskell
Free [Free [Free [Pure ()]]] :: Free [] ()
Free [Pure 3, Pure 2, Free [Pure 1, Free []], Pure 0] :: Num a => Free [] a
Free [] :: Free [] a
Pure () :: Free f ()
Free [Pure $ Free [Pure ()]] :: Free [] (Free [] ())
```
よく分からない


## 手を動かす: join
`>>=`や`bind`と呼ばれる`Monad m => m a -> (a -> m b) -> m b`は  
`Control.Monad.join`こと`Monad m => m (m a) -> m a`で定義できる[^1][^2]ので  
理解のため`join`を定義してみる

``` haskell
join' :: Functor f => Free f (Free f a) -> Free f a
join' (Pure a) = a
join' (Free fFreefa) = Free (fmap join' fFreefa)
```

### 実際に: Maybe
``` haskell
>>> let x = Free$Just (Free$Just (Pure (Free$Just (Pure Nothing))))
>>> :t x
x :: Free Maybe (Free Maybe (Maybe a))
>>> join x
Free (Just (Free (Just (Free (Just (Pure Nothing))))))
```
手で追う

``` haskell
join          (Free$Just (Free$Just (Pure (Free$Just (Pure Nothing)))))
Free (fmap   join $ Just (Free$Just (Pure (Free$Just (Pure Nothing)))))
Free (Just $ join        (Free$Just (Pure (Free$Just (Pure Nothing)))))
Free$Just          (join (Free$Just (Pure (Free$Just (Pure Nothing)))))
Free$Just          (Free$Just (join (Pure (Free$Just (Pure Nothing)))))
Free$Just          (Free$Just             (Free$Just (Pure Nothing)))
               Free$Just (Free$Just       (Free$Just (Pure Nothing)))
```

1. 初期状態
2. `join`の展開
3. `fmap`の展開: `fmap f (Just a) = Just (f a)`
4. 見やすくしただけ: `join`と`Free$Just`が入れ替わったのが分かる
5. 同様にする
6. `Pure`は`join`と対消滅する
7. 見やすくしただけ: 外側のPureを道連れにjoinが消え、外側と内側のFreeの境目を潰しているのが分かる

### もう少し複雑な例: List
``` haskell
>>> let x = Free[ Free[ Free[], Pure( Free[] ) ], Pure( Free[ Pure() ] ) ]
>>> :t x
x :: Free [] (Free [] ())
>>> join x
Free [Free [Free [],Free []],Free [Pure ()]]
```

``` haskell
join$Free[      Free[      Free[],      Pure( Free[] ) ],      Pure( Free[ Pure() ] ) ]
     Free[ join$Free[      Free[],      Pure( Free[] ) ], join$Pure( Free[ Pure() ] ) ]
     Free[      Free[ join$Free[], join$Pure( Free[] ) ],            Free[ Pure() ]   ]
     Free[      Free[      Free[],            Free[]   ],            Free[ Pure() ]   ]
```

### 解釈
`join`の型が`Free f (Free f a) -> Free f a`で、`Free f a`は`fffffffa`などと読み替えられることから、  
`join`とは`ffff(ffffa) -> ffffffffa`的ななにかである  
それともつじつまの合う結果である  
なんとなく雰囲気はつかめた

### bindへ
そして

``` haskell
bind :: (Functor m, Monad m) => m a -> (a -> m b) -> m b
bind x f = join $ fmap f x
```
である[^3]

``` haskell
>>> Free[ Pure 7, Pure 2 ] >>= (\ x -> Free[ Pure (show x), Pure (show (x ^ x)) ])
Free [Free [Pure "7",Pure "823543"],Free [Pure "2",Pure "4"]]
```
右辺のPureの位置に左辺が埋め込まれている


## 自由
弄っていたらいつの間にか気がついた  
`Free`の`free`とはおそらくfree monoidやfree magmaの`free`であろう[^4]  
つまり、公理の等式以外に元の間の関係式をもたない、という意味  
この場合公理とはモナド則

つまりGADTsで定義して見やすくすると

``` haskell
class Functor m => Monad m where
    unit :: a -> m a
    join :: m (m a) -> m a
data FreeMonad f a where
    Unit :: a -> FreeMonad f a
    Join :: f (FreeMonad f a) -> FreeMonad f a
```
とある程度綺麗に対応している

## 結論
`Free`とはmonadそのものであり、monadをdataとして表現したものである  
lispに似ているなと感じる


## 予防線と残った疑問
`free monad`には別の定義も存在して

``` haskell
-- join / f無し
data FreeMonad a where
    Unit :: a -> FreeMonad a
    Join :: FreeMonad (FreeMonad a) -> FreeMonad a
```

``` haskell
-- bind / f無し
data FreeMonad a where
    Return :: a -> FreeMonad a
    Bind :: FreeMonad x -> (x -> FreeMonad a) -> FreeMonad a
```

``` haskell
-- bind / f有り(BindのFreeMonad消去)
data FreeMonad f a where
    Return :: a -> FreeMonad f a
    Bind :: f x -> (x -> FreeMonad f a) -> FreeMonad f a
```
と思いつく範囲だけで3つ  
しかもこの3つは`f Functor`制約なしでmonadになる

``` haskell
-- bind / f無し
instance Monad FreeMonad where
    return = Return
    (>>=) = Bind
```

``` haskell
-- bind / f有り(BindのFreeMonad消去)
instance Monad (FreeMonad f) where
    return = Return
    (>>=) (Return a) a2fb = a2fb a
    (>>=) (Bind fx x2fa) a2fb = Bind fx ((>>= a2fb) . x2fa)
```

一方`Free`で使われている定義は

``` haskell
-- join / f有り(JoinのFreeMonad消去)
instance Functor f => Functor (FreeMonad f) where
    fmap a2b (Unit a) = Unit $ a2b a
    fmap a2b (Join ffa) = Join $ fmap (fmap a2b) ffa
join' :: Functor f => FreeMonad f (FreeMonad f a) -> FreeMonad f a
join' (Unit a) = a
join' (Join ffa) = Join $ fmap join' ffa
instance Functor f => Monad (FreeMonad f) where
    return = Unit
    (>>=) fa a2fb = join' $ fmap a2fb fa
```
と要Functor制約  
`Join`の`f (FreeMonad f a)`を展開するのにどうしても必要なようだ[^5]

そしてそもそも`f`が入るとはどういうことなのかいまいち分からない  
もしかしたら`Free`はfree monadでなく類似の別な概念のfreeかもしれない  
圏論に精通していないので分からない[^6]

### operational
さらに強いと聞くoperational monadはこのbind型のfree monadなのではと考えた

``` haskell
type Program t = Free (Coyoneda t)
```
らしく、

``` haskell
data Coyoneda t x where
    Coyoneda :: t r -> (r -> a) -> Coyoneda t a
instance Functor (Coyoneda t) where
    fmap f (Coyoneda t g) = Coyoneda t (f . g)
```
とcoyonedaは制約なしでfunctorを作るので、ただのdataからmonadになるのだそうだ

coyonedaのmoduleも`Data.Functor.Coyoneda`にあるので、free functor的ななにかだと思い、  
free functorとfree monadを合成してもfree monadだろうという発想から少し頑張った  
しかし型パズルが解けずinterpretが定義できないので、全く違うのかもしれないし、haskell力足りていないだけかもしれない


## 参考
- [そろそろFreeモナドに関して一言いっとくか - fumievalの日記](http://d.hatena.ne.jp/fumiexcel/20121111/1352614885)
- [Freeモナドって何なのさっ！？ - capriccioso String Creating(Object something){ return My.Expression(something); }](http://d.hatena.ne.jp/its_out_of_tune/20121111/1352632815)

### operational
- [YonedaとCoYoneda、そしてFunctor - capriccioso String Creating(Object something){ return My.Expression(something); }](http://d.hatena.ne.jp/its_out_of_tune/20130601/1370109743)
- [Operationalモナドをゲームに応用した話 - モナドとわたしとコモナド](http://fumieval.hatenablog.com/entry/2013/11/11/154146)
- [Yoneda lemmaとOperational Monad - Just $ A sandbox](http://myuon-myon.hatenablog.com/entry/2013/06/09/135407)
- [Operational Monad - Togetterまとめ](http://togetter.com/li/526588)

## packages
- <http://hackage.haskell.org/package/free> # 推奨
- <http://hackage.haskell.org/package/control-monad-free> # ?
- <http://hackage.haskell.org/package/transformers-free> # deprecated

### operational
- <http://hackage.haskell.org/package/operational> # 一番人気
- <http://hackage.haskell.org/package/free-operational> # freeを使った実装
- <http://hackage.haskell.org/package/minioperational> # 上に挙げたoperationalの解説記事など書いてる人の再実装

[^1]: <https://ja.wikibooks.org/wiki/Haskell/%E5%9C%8F%E8%AB%96#.E3.83.A2.E3.83.8A.E3.83.89>
[^2]: むしろmonadの定義としてはjoinの方が自然に見える
[^3]: functorの制約はhaskellのmonadの定義が悪い
[^4]: あまり圏論に明るくないので少し怪しい
[^5]: haskellのmonadがbindである理由かもしれない
[^6]: 圏論に精通していれば分かるのかどうかも分からない
