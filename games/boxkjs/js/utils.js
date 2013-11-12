var browserLanguage = (navigator.browserLanguage || navigator.language || navigator.userLanguage).substr(0,2);
function isJapanese() {
    return browserLanguage == 'ja';
}

function internationalize(dict) {
    if (browserLanguage in dict) {
        return dict[browserLanguage];
    } else {
        return dict['en'];
    }
}

function clamp(mx, n) {
    if (mx < n) {
        return mx
    } else {
        return n
    }
}

function clampMin(mn, n) {
    if (n < mn) {
        return mn
    } else {
        return n
    }
}

// new Array: length is len, filled with val
function newArray(len, val) {
    var ary = new Array(len);
    for (var i = 0; i < len; ++i) {
        ary[i] = val;
    }
    return ary;
}

function zipWith(f,x,y) {
    var len = Math.min(x.length, y.length);
    for (var i = 0; i < len; ++i) {
        f(x[i], y[i]);
    }
}

function deleteElem(ary, elem) {
    for (var i = 0; i < ary.length; ++i) {
        if (ary[i] == elem) {
            ary.splice(i,1);
            --i;
        }
    }
}
