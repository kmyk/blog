---
layout: post
redirect_from:
  - /writeup/algo/yukicoder/522/
  - /blog/2017/06/02/yuki-522/
date: "2017-06-02T23:06:28+09:00"
tags: [ "competitive", "writeup", "yukicoder" ]
"target_url": [ "http://yukicoder.me/problems/no/522" ]
---

# Yukicoder No.522 Make Test Cases(テストケースを作る)

`std::cout`死ねってことかと思ったがそうでもなかった。

-   `printf`: $0.121572$sec
-   `std::cout`: $0.857700$sec

```
$ echo 3000 | ./a.out | wc
 750000 2250000 9840918
```

## implementation

``` c++
#include <cstdio>
#define repeat(i,n) for (int i = 0; (i) < int(n); ++(i))
#define repeat_from(i,m,n) for (int i = (m); (i) < int(n); ++(i))
int main() {
    int n; scanf("%d", &n);
    repeat_from (a, 1, n+1) {
        repeat_from (b, a, n-a+1) {
            int c = n-a-b;
            if (b <= c) {
                printf("%d %d %d\n", a, b, c);
            }
        }
    }
    return 0;
}
```
