var b2Vec2 = Box2D.Common.Math.b2Vec2;
var b2Body = Box2D.Dynamics.b2Body;
var b2BodyDef = Box2D.Dynamics.b2BodyDef;
var b2FixtureDef = Box2D.Dynamics.b2FixtureDef;
var b2PolygonShape = Box2D.Collision.Shapes.b2PolygonShape;
var b2CircleShape = Box2D.Collision.Shapes.b2CircleShape;
var b2Math = Box2D.Common.Math.b2Math;

function parseQueryString(str){
    var dec = decodeURIComponent;
    var arr = [];
    var item;
    if (typeof(str) == 'undefined') { return arr; }
    if (str.indexOf('?', 0) > -1) { str = str.split('?')[1]; }
    str = str.split('&');
    for (var i = 0; i < str.length; ++i){
        item = str[i].split("=");
        if(item[0] != ''){
            arr[item[0]] = typeof(item[1]) == 'undefined' ? true : dec(item[1]);
        }
    }
    return arr;
}

function inspect(dict) {
    var str = '';
    for (var key in dict){
        str += key + "=" + dict[key] + "\n";
    }
    alert(str);
}

function randomPM() { return Math.random() * 2 - 1; }

function color(r, g, b) {
    var f = function(g) {
        return ('0' + Math.floor(g()).toString(16)).slice(-2);
    };
    return "#" + f(r) + f(g) + f(b);
}
function whitish()  { return Math.random() *  64 + 192; }
function light()    { return Math.random() * 128 + 128; }
function middle()   { return Math.random() * 128 +  64; }
function dark()     { return Math.random() * 128      ; }
function blackish() { return Math.random() *  64      ; }

function updateShape(evt) {
    evt.body.shape.x = evt.body.GetPosition().x * ppm;
    evt.body.shape.y = evt.body.GetPosition().y * ppm;
    evt.body.shape.rotation = evt.body.GetAngle() * 360.0 / (2.0 * Math.PI)
}

function smooth(times, interval, func) {
    var i = interval;
    var j = times;
    var tick = function() {
        if (0 < i) {
            --i;
        } else {
            i = interval;
            if (0 < j) {
                --j;
                func();
            } else {
                createjs.Ticker.removeEventListener("tick", tick);
            }
        }
    }
    createjs.Ticker.addEventListener("tick", tick);
}
