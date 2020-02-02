---
category: blog
layout: post
title: "extensible-effects上にoperational monad作ってみた"
date: 2014-03-13T22:29:54+09:00
tags: [ "haskell", "extensible-effects", "operational" ]
---

extensible-effects上にoperational作った  
正確には、型パズル解いて遊んでいたらoperationalができていた

利点:

-   extensible-effectsとoperationalが合わさって最強に見える

欠点:

-   Typeable1の宣言が必要
    -   GADTs使うとderivingできないので面倒 (THで解決?)

<!-- more -->

## code

``` haskell
{-# LANGUAGE ExistentialQuantification #-}
{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE MultiParamTypeClasses #-}
{-# LANGUAGE Rank2Types #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE TypeOperators #-}
module Control.Eff.Operational (Program, singleton, runProgram) where

import Control.Eff (Eff, Member, (:>), VE(Val, E), inj, send, admin, handleRelay)
import Data.Typeable (Typeable1, typeOf1, mkTyCon3, mkTyConApp)

data Program m v = forall a. Program (m a) (a -> v)

instance Functor (Program m) where
    fmap f (Program m k) = Program m (f . k)

instance Typeable1 m => Typeable1 (Program m) where
    typeOf1 _ = mkTyConApp (mkTyCon3 "" "Control.Eff.Operational" "Program")
                           [typeOf1 (undefined :: m ())]

singleton :: (Typeable1 m, Member (Program m) r) => m a -> Eff r a
singleton m = send (inj . Program m)

runProgram :: Typeable1 f => (forall x. f x -> Eff r x) -> Eff (Program f :> r) a -> Eff r a
runProgram advent = loop . admin where
    loop (Val x) = return x
    loop (E u) = handleRelay u loop
        (\ (Program m k) -> loop . k =<< advent m)
```


## 比較
``` haskell
runProgram :: Typeable1 f          => (forall x. f x -> Eff r x) -> Eff (Program f :> r) a -> Eff r a
interpret  :: (Functor m, Monad m) => (forall x. instr x -> m x) ->      Program instr   a ->     m a
```

当然似ている

## example

``` haskell
data Jail a where
    Print :: String -> Jail ()
    Scan :: Jail String

instance Typeable1 Jail where
    typeOf1 _ = mkTyConApp (mkTyCon3 "test" "Main" "Jail") []

prog :: Member (Program Jail) r => Eff r ()
prog = do
    singleton $ Print "getting input..."
    str <- singleton Scan
    singleton $ Print "ok"
    singleton $ Print ("the input is " ++ str)

adventIO :: (Member (Lift IO) r, SetMember Lift (Lift IO) r) => Jail a -> Eff r a
adventIO (Print a) = lift $ putStrLn a
adventIO Scan = lift getLine

main :: IO ()
main = runLift $ runProgram adventIO prog
```

もちろんrunProgramの第一引数は自由に差し替えられる

``` haskell
adventPure :: (Member (Writer String) r, Member (State [String]) r) => Jail a -> Eff r a
adventPure (Print a) = tell a
adventPure Scan = do
    x <- (fromMaybe [] . headMay) <$> get
    modify (tailSafe :: [String] -> [String])
    return x
```

型注釈はextensible-effectsの問題 newtypeすれば消えます


## おまけ
advent部分の制約にoperationalを使うと、つまりoperationalの実装をoperationalで与えるといろいろ楽しい

``` haskell
advent :: (Member (Program t) r) => t a -> Eff r a
runProgram advent :: (Member (Program t) r) => Eff (Program t :> r) a -> Eff r a
```

``` haskell
advent :: (Member (Program t) r, Member (Program u) r) => s a -> Eff r a
runProgram advent :: (Member (Program t) r, Member (Program u) r) => Eff (Program s :> r) a -> Eff r a
```

``` haskell
advent  :: (Member (Program u) r) => s a -> Eff r a
advent' :: (Member (Program u) r) => t a -> Eff r a
runProgram advent' . runProgram advent :: (Member (Program u) r) => Eff (Program s :> Program t :> r) a -> Eff r a
```


## 関連
-   [IOアクションひとつひとつを利用許諾し・テスト可能にする - ぼくのぬまち 出張版](http://notogawa.hatenablog.com/entry/2014/02/22/004828)
-   [Freeモナドを超えた！？operationalモナドを使ってみよう - モナドとわたしとコモナド](http://fumieval.hatenablog.com/entry/2013/05/09/223604)


---

2014/04/11
:   冗長だった部分を削減
