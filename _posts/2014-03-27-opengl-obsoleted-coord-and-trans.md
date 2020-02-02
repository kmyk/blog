---
category: blog
layout: post
title: "openglの固定機能の座標変換を調べた"
date: 2014-03-27T00:24:12+09:00
tags: [ "opengl", "obsoleted", "coordinates", "transformation", "matrix", "sharder", "c", "c++" ]
---

-   座標変換がよく分かってないので調べた
-   固定機能と言って時代遅れで削除予定な部分
-   学習の過程には必要なのではないでしょうか
-   間違っているところもあると思う

<!-- more -->

## 主な参考
-   [OpenGL覚え書き3 座標系 - white wheelsのメモ](http://d.hatena.ne.jp/white_wheels/20100405/p1)
-   [OpenGLの座標系](http://oshiro.bpe.es.osaka-u.ac.jp/people/staff/imura/computer/OpenGL/coordinates/disp_content)
-   [GLUTによる「手抜き」OpenGL入門](http://www.wakayama-u.ac.jp/~tokoi/opengl/libglut.html)
-   [Lichu's_Base](http://homepage3.nifty.com/li-chu/OpenGL/OpenGL04.html)

## モデリング座標系 オブジェクト座標系
-   モデル固有の座標系
-   ポリゴンの左上や重心付近などが原点

## モデリング変換
-   モデリング座標系 -> ワールド座標系
-   modelview行列
-   操作する行列らしい行列はこれだけ
-   glTranslate\* glScale\* glRotate\*

## ワールド座標系 世界座標系
-   ゲーム内の物体の共通の座標系
-   原点は任意

## 視野変換
-   ワールド座標系 -> 視点座標系
-   modelview行列
-   [gluLookAt](https://www.opengl.org/sdk/docs/man2/xhtml/gluLookAt.xml)
    -   単に行列掛けているだけ 冪等性なし
    -   modelview行列の頭に呼ぶ
    -   projection行列の最後でも変わらない? 陰影計算に影響する?

## 視点座標系 眼点座標系
-   カメラが原点
-   スケールはワールド座標系に同じ

## 投影変換
-   視点座標系 -> 正規化デバイス座標系
-   視界に入る部分を切り出す
-   projection行列
-   透視投影
    -   glFrustum gluPerspective
    -   遠近感ある 遠くにあるほど小さい
-   平行投影 正射影
    -   glOrtho gluOrtho2D
    -   遠近感ない つまり2D
    -   メニューとか書きたいときなど
-   これらも単に行列掛けているだけ 冪等性なし

## 正規化デバイス座標系 クリッピング座標系
-   (-1,-1,-1) ~ (1,1,1) -- 1辺の長さ2の立方体で中心が原点

## ビューポート変換
-   正規化デバイス座標系 -> ウィンドウ座標系
-   3D -> 2D
-   z軸を潰して、xy軸引き伸ばして、できた画像を画面に配置
-   [glViewport](https://www.opengl.org/sdk/docs/man/html/glViewport.xhtml)
    -   obsoletedでない
    -   冪等性あり
    -   少なくとも表面的には行列でない
    -   たいていwindowの大きさが変わった時に`glViewport(0, 0, screen_width, screen_height)`して画面いっぱいに表示

## ウィンドウ座標系
-   画面そのまま
-   単位はpixel
-   左上が原点
