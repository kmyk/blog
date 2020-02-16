---
category: blog
layout: post
date: "2017-12-07T23:59:59+09:00"
tags: [ "tutorial", "wxwidgets" ]
---

# wxWidgetsでお絵描きするまでの例

## インストール

-   記事はここ: <https://wiki.wxwidgets.org/Install>
-   Ubuntuだと特にこれ: <https://wiki.wxwidgets.org/Installing_and_configuring_under_Ubuntu>

Ubuntu 16.04LTSでは次:

``` sh
$ sudo apt install libwxgtk3.0-dev
```

## Hello, world!

-   サンプルコードはここ: <http://docs.wxwidgets.org/stable/overview_helloworld.html>
-   コンパイル方法はここ: <https://wiki.wxwidgets.org/Compiling_and_getting_started>

特に上のサンプルを元に必要最小限まで削ったものは以下:

``` c++
#include <wx/wx.h>

class MyApp : public wxApp {
public:
    virtual bool OnInit() {
        wxFrame *frame = new wxFrame(NULL, wxID_ANY, "Hello, world!");
        frame->Show();
        return true;
    }
};

wxIMPLEMENT_APP(MyApp);
```

コンパイルは次:

``` sh
$ $CXX mmvis.cpp `wx-config --cxxflags --libs`
```

![](/blog/2017/12/07/wxwidgets-tutorial/ss-1.png)


## 絵を書く

-   <https://wiki.wxwidgets.org/WxPaintDC>
-   <https://wiki.wxwidgets.org/Painting_your_custom_control>

`EVT_PAINT()`を発生させhandlerを呼びその中で`wxPaintDC`を生成して絵を書く。
それ以外の方法はあまり推奨されていないように見える。

![](/blog/2017/12/07/wxwidgets-tutorial/ss-2.png)

``` c++
#include <wx/wx.h>

class MyPanel : public wxPanel {
public:
    MyPanel(wxFrame *parent)
            : wxPanel(parent) {
        Bind(wxEVT_PAINT, &MyPanel::myOnPaint, this);
    }

    void myOnPaint(wxPaintEvent & evt) {
        wxPaintDC dc(this);
        wxPen pen(*wxBLACK, /* width = */ 1);
        dc.SetPen(pen);
        dc.DrawText(wxT("Hello, "), 40, 60);
        int dx = 90;
        int dy = 60;
        int scale = 5;
        auto draw_line = [&](int x1, int y1, int x2, int y2) {
            x1 = dx + x1 * scale;
            y1 = dy + y1 * scale;
            x2 = dx + x2 * scale;
            y2 = dy + y2 * scale;
            dc.DrawLine(x1, y1, x2, y2);
        };
        { // se
            draw_line(0, 1, 4, 1);
            draw_line(1, 0, 1, 3);
            draw_line(1, 3, 4, 3);
            draw_line(2, 0, 2, 2);
            draw_line(2, 2, 3, 2);
            draw_line(3, 0, 3, 2);
        }
        { // kai
            dx = 120;
            dy = 60;
            scale = 4;
            for (int z = 0; z < 3; ++ z) {
                draw_line(1, z, 3, z);
                draw_line(z + 1, 0, z + 1, 2);
            }
            draw_line(2, 2, 0, 4);
            draw_line(2, 2, 5, 4);
            draw_line(2, 3, 1, 5);
            draw_line(3, 3, 3, 5);
        }
        dc.SetPen(wxNullPen);
    }
};

class MyApp : public wxApp {
public:
    virtual bool OnInit() {
        wxFrame *frame = new wxFrame(NULL, wxID_ANY, "Hello, world!");
        MyPanel *panel = new MyPanel(frame);
        frame->Show();
        return true;
    }
};

wxIMPLEMENT_APP(MyApp);
```

## 動的に更新する

例えば`EVT_TIMER`を発生させてデータ列を生成しグラフにしてみる。

画面への反映は`Refresh`を呼ぶ。`Update`は好みで: <https://forums.wxwidgets.org/viewtopic.php?t=10114>

![](/blog/2017/12/07/wxwidgets-tutorial/ss-3.png)

``` c++
#include <deque>
#include <wx/wx.h>

class MyPanel : public wxPanel {
public:
    MyPanel(wxFrame *parent)
            : wxPanel(parent),
              timer(this) {
        Bind(wxEVT_PAINT, &MyPanel::myOnPaint, this);
        Bind(wxEVT_TIMER, &MyPanel::myOnTimer, this, timer.GetId());
        timer.Start(10); // msec
    }

    void myOnPaint(wxPaintEvent & evt) {
        wxPaintDC dc(this);
        for (int x = 0; x < int(points.size()) - 1; ++ x) {
            dc.DrawLine(x, points[x], x + 1, points[x + 1]);
        }
    }

    void myOnTimer(wxTimerEvent & event) {
        int value = wxGetMouseState().GetY() - GetScreenPosition().y;
        points.push_back(value);
        if (points.size() > 640) {
            points.pop_front();
        }
        Refresh();
    }

private:
    wxTimer timer;
    std::deque<int> points;
};

class MyApp : public wxApp {
public:
    virtual bool OnInit() {
        wxFrame *frame = new wxFrame(NULL, wxID_ANY, "Hello, world!",
                wxDefaultPosition, wxSize(640, 480));
        MyPanel *panel = new MyPanel(frame);
        frame->Show();
        return true;
    }
};

wxIMPLEMENT_APP(MyApp);
```


## その他

-   `frame`の`delete`は自動でやってくれるので不要
    -   `wxWindow` (`wxFrame`のsuperclass)のchilderenは親の`delete`にあわせて`delete`されるとの記述はある。`wxApp`については見つからないが、どれも基本的に自動で開放されるようだ
    -   <https://wiki.wxwidgets.org/Avoiding_Memory_Leaks>
-   `main`関数は`wxIMPLEMENT_APP()`macroが自動で挿入する
    -   嫌なら: <https://stackoverflow.com/questions/208373/wxwidgets-how-to-initialize-wxapp-without-using-macros-and-without-entering-the>
-   イベントハンドラの登録は`Bind`が推奨 (3.0の前あたりから)
    -   <http://murank.github.io/wxwidgetsjp/2.9.4/overview_events.html>
-   `EVT_TIMER`への`Bind`ではtimerのIDを指定する (そうでないと全てのtimerの発するイベントを拾ってしまう)
