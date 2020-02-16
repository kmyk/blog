---
category: blog
layout: post
date: "2016-12-10T09:22:36+09:00"
tags: [ "competitive", "codevs", "marathon-match", "game", "beam-search", "chokudai-search" ]
---

# CODE VS for STUDENT 2016: 提出AI 解説

<https://student.codevs.jp>

-   ソースコード等はgithubで公開してある[^1]: <https://github.com/kmyk/codevs-for-student-2016>
-   最終提出したバイナリも置いておいた: <https://github.com/kmyk/codevs-for-student-2016/blob/master/history/final.out>

---

# CODE VS for STUDENT 2016: 提出AI 解説

-   探索<sup>[source](https://github.com/kmyk/codevs-for-student-2016/blob/ce1466ade2c0734f0e50b8e49bc84be61a92f5b7/Main.cpp#L974)</sup>はビームサーチ
    -   特にbeam stack search (通称chokudai search)にした<sup>[source](https://github.com/kmyk/codevs-for-student-2016/blob/ce1466ade2c0734f0e50b8e49bc84be61a92f5b7/Main.cpp#L764)</sup>
    -   ほとんど一人ゲームなので、前ターンの探索結果を保存しておいてそこから追加で探索<sup>[source](https://github.com/kmyk/codevs-for-student-2016/blob/ce1466ade2c0734f0e50b8e49bc84be61a92f5b7/Main.cpp#L811)</sup>し高速化した
        -   `std::shared_ptr`/`std::weak_ptr`の参照カウントを悪用して、現在ターンからの到達可能性判定をすると実装は楽であった

-   近傍について
    -   基本は単純に$1$手進める
    -   しかし操作列の途中があまり改善されない問題があり、操作列として取り出して途中のみを変更する(焼き鈍しをする場合のような)近傍<sup>[source](https://github.com/kmyk/codevs-for-student-2016/blob/ce1466ade2c0734f0e50b8e49bc84be61a92f5b7/Main.cpp#L734)</sup>もたまに使う
        -   (効果はあるが、足りていない)

-   探索用の評価関数<sup>[source](https://github.com/kmyk/codevs-for-student-2016/blob/ce1466ade2c0734f0e50b8e49bc84be61a92f5b7/Main.cpp#L534)</sup>
    -   主に空きマスに8近傍で隣接するブロックを消してみて<sup>[source](https://github.com/kmyk/codevs-for-student-2016/blob/ce1466ade2c0734f0e50b8e49bc84be61a92f5b7/Main.cpp#L434)</sup>連鎖結果を見るもの
    -   各列に$1 \sim 9$のブロックを落としてみて試す方式<sup>[source](https://github.com/kmyk/codevs-for-student-2016/blob/ce1466ade2c0734f0e50b8e49bc84be61a92f5b7/Main.cpp#L467)</sup>は、単に遅いことと発火点が下がりやすいことから(実装したが)棄却した
    -   また、無駄な消しへの罰として、盤面にある数字ブロックに正の評価を与える

-   最終決定用の評価関数<sup>[source](https://github.com/kmyk/codevs-for-student-2016/blob/ce1466ade2c0734f0e50b8e49bc84be61a92f5b7/Main.cpp#L644)</sup>
    -   探索用の評価関数とは別のものを用いた。発火に成功しているかどうか、その発火が相手を殺せるかどうか<sup>[source](https://github.com/kmyk/codevs-for-student-2016/blob/ce1466ade2c0734f0e50b8e49bc84be61a92f5b7/Main.cpp#L633)</sup>が基準
    -   発火が基準なので(有効な)発火まで辿り着きやすくなる

-   枝刈りについて
    -   連鎖し(数個以上ブロックを消し)<sup>[source](https://github.com/kmyk/codevs-for-student-2016/blob/ce1466ade2c0734f0e50b8e49bc84be61a92f5b7/Main.cpp#L697)</sup>していたら横に控え、枝としてはそこで打ち切り
    -   各ターンで、控えていたものの中で最良のものを採用判定にかける
    -   (重複盤面除去は盤面の合流がないと考え無視していた。効果はあったらしい)

-   発火に関して
    -   発火ターンは固定ではない (相手を殺せるかを見ているので)
        -   早期発火して反撃されることは減るが、相手の様子を伺いながらふらふらと発火時期が揺れるため連鎖効率では損をする
    -   相手盤面を簡易に探索し、現在知られている手で殺せそうなら強制的に発火させる<sup>[source](https://github.com/kmyk/codevs-for-student-2016/blob/ce1466ade2c0734f0e50b8e49bc84be61a92f5b7/Main.cpp#L1053)</sup>

-   相手の盤面
    -   適当にビームサーチしただけ

-   ビームの深さ等<sup>[source](https://github.com/kmyk/codevs-for-student-2016/blob/ce1466ade2c0734f0e50b8e49bc84be61a92f5b7/Main.cpp#L981)</sup>
    -   横幅に関しては計測していない
    -   深さはゲームの進行に従って増減させる
        -   $20$ターン前後で発火してほしいので、最初はそのような深さまで見、だんだんと減少させた
        -   (あまり深くまで見ると、遠くの大連鎖に気を取られるなどの調整が面倒というのも一因)

-   他
    -   スレッド等は面倒なので使わなかった
    -   profile-guided optimizationはコードに手を入れなくて済んだため利用<sup>[source](https://github.com/kmyk/codevs-for-student-2016/blob/ce1466ade2c0734f0e50b8e49bc84be61a92f5b7/Makefile#L19)</sup>
        -   $0.8$倍ぐらいに高速化されたはず

[^1]: Sat Dec 10 09:28:43 JST 2016: TODO: 決勝戦終わったらpublicにする
