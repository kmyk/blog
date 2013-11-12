// destructive
function shuffle(list) {
    var i = list.length;
    while (--i) {
        var j = Math.floor(Math.random() * (i + 1));
        if (i == j) continue;
        var k = list[i];
        list[i] = list[j];
        list[j] = k;
    }
    return list;
}

var height;
var width;
var bombs;

(function(){
    var url = document.URL.replace(/^.*\?/, '')
    var qstr = url ? $.deserialize(url) : {};
    height = parseInt(qstr['height']);
    width = parseInt(qstr['width']);
    bombs = parseInt(qstr['bombs']);
    if (! (height && width && bombs)) {
        location.href = '?' + $.param({ width: width || 9, height: height || 9, bombs: bombs || 15 });
    }
})();

function at(y, x) {
    if (!on_board(y, x)) { return; }
    return y * width + x;
}
function on_board(y, x) {
    return 0 <= y && y < height && 0 <= x && x < width;
}
function around(y, x, f) {
    for (var dy = -1; dy <= 1; ++dy) {
        for (var dx = -1; dx <= 1; ++dx) {
            if (on_board(y + dy, x + dx) && (! (dy == 0 && dx == 0))) {
                f(y + dy, x + dx);
            }
        }
    }
}
var cells = new Array(height * width);

var open_neighbors;
(function(){
    var open_neighbors_lock = false;
    open_neighbors = function(y, x) {
        if (open_neighbors_lock) { return; }
        open_neighbors_lock = true;

        var is_done = new Array(height * width);
        for (var i = is_done.length - 1; 0 <= i; --i) { is_done[i] = false; }
        var neighbors = [];
        var next = [cells[at(y, x)]];
        while (0 < next.length) {
            neighbors = [];
            for (var i = next.length - 1; 0 <= i; --i) {
                around(next[i][0].y, next[i][0].x, function(y, x) {
                    if (!is_done[at(y, x)]) {
                        is_done[at(y, x)] = true;
                        var neighbor = cells[at(y, x)];
                        if (neighbor.hasClass('closed')) {
                            neighbors.push(neighbor);
                        }
                    }
                });
            }
            next = [];
            for (var j = neighbors.length - 1; 0 <= j; --j) {
                var neighbor = neighbors[j];
                neighbor.click();
                if (neighbor[0].count == 0) { next.push(neighbor); }
            }
        }
        open_neighbors_lock = false;
    }
})();

$(document).ready(function(){
    (function(){
        var board = $('table.board')
        for (var y = 0; y < height; ++y) {
            var col = $('<tr>').appendTo(board);
            for (var x = 0; x < width; ++x) {
                var cell = $('<td>').appendTo(col);
                cell[0].y = y;
                cell[0].x = x;
                cells[at(y, x)] = cell;
            }
        }
        $('.board td').addClass('closed');
    })();

    (function(){
        function initialize(evt){
            var is_bomb = new Array(height * width);
            for (var i = 0; i < is_bomb.length; ++i) { is_bomb[i] = i < bombs; }
            shuffle(is_bomb);
            while (true) {
                var count = 0;
                around(evt.target.y, evt.target.x, function(y, x){
                    if (is_bomb[at(y, x)]) { ++count; }
                });
                if (!is_bomb[at(evt.target.y, evt.target.x)] && count == 0) { break; }
                shuffle(is_bomb);
            }

            (function(){
                for (var y = 0; y < height; ++y) {
                    for (var x = 0; x < width; ++x) {
                        var cell = cells[at(y, x)];
                        cell[0].count = 0;
                        around(y, x, function(y, x){
                            if (is_bomb[at(y, x)]) { cell[0].count += 1; }
                        });
                        if (is_bomb[at(y, x)]) {
                            cell.addClass('bomb');
                        } else {
                            cell
                                .addClass('non-bomb')
                                .addClass('n' + cell[0].count.toString());
                        }
                    }
                }
            })();

            function open_nonbomb(target) {
                $(target)
                    .removeClass('closed')
                    .addClass('opened')
                    .unbind('contextmenu', flag);
                var t = target;
                var y = t.y;
                var x = t.x;
                if (0 < t.count) {
                    $(t).text(t.count.toString());
                } else {
                    open_neighbors(y, x);
                }
            }

            function open_bomb(target) {
                $('.board td.bomb')
                    .text('*')
                    .removeClass('closed')
                    .addClass('opened');
                $('.board td')
                    .unbind('click', open)
                    .unbind('contextmenu', flag);
            }

            function open(evt) {
                if ($(evt.target).hasClass('bomb')) {
                    return open_bomb(evt.target);
                } else {
                    return open_nonbomb(evt.target);
                }
            }
            $('.board td').click(open);

            function flag(evt){
                if ($(evt.target).hasClass('flagged')) {
                    $(evt.target)
                        .text('?')
                        .removeClass('flagged')
                        .addClass('question');
                } else if ($(evt.target).hasClass('question')) {
                    $(evt.target)
                        .text('')
                        .removeClass('question')
                        .click(open);
                } else {
                    $(evt.target)
                        .text('F')
                        .addClass('flagged')
                        .unbind('click', open);
                }
                return false;
            }
            $('.board td').bind('contextmenu', flag);

            $('.board td').unbind('click', initialize);
            open_nonbomb(evt.target);
        }
        $('.board td').click(initialize);
    })();
});
