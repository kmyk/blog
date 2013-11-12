// LICENSE: public domain

enchant();



/**************************************************************
 * global bars
 *************************************************************/

var game;
var world;
var garbageArray;
var blockCounter;



/**************************************************************
 * util funcs
 *************************************************************/

function fillRoundedRect(ctx, x1, y1, x2, y2, d) {
    ctx.beginPath();
    ctx.moveTo(x1+d, y1);
    ctx.lineTo(x2-d, y1);
    ctx.quadraticCurveTo(x2, y1, x2, y1+d);
    ctx.lineTo(x2, y2-d);
    ctx.quadraticCurveTo(x2, y2, x2-d, y2);
    ctx.lineTo(x1+d, y2);
    ctx.quadraticCurveTo(x1, y2, x1, y2-d);
    ctx.lineTo(x1, y1+d);
    ctx.quadraticCurveTo(x1, y1, x1+d, y1);
    ctx.fill();
}

function strokeRoundedRect(ctx, x1, y1, x2, y2, d) {
    ctx.beginPath();
    ctx.moveTo(x1+d, y1);
    ctx.lineTo(x2-d, y1);
    ctx.quadraticCurveTo(x2, y1, x2, y1+d);
    ctx.lineTo(x2, y2-d);
    ctx.quadraticCurveTo(x2, y2, x2-d, y2);
    ctx.lineTo(x1+d, y2);
    ctx.quadraticCurveTo(x1, y2, x1, y2-d);
    ctx.lineTo(x1, y1+d);
    ctx.quadraticCurveTo(x1, y1, x1+d, y1);
    ctx.stroke();
}

// copy from the property
function vecp(a) {
    return new b2Vec2(a.x, a.y);
}



/**************************************************************
 * graphcis
 *************************************************************/

var _blockSurfaceWithCache = [];
function makeBlockSurfaceWithCache(ifw, ifh, r, g, b) {
    var key = '' + [ifw, ifh, r, g, b];
    if (key in _blockSurfaceWithCache) {
        return _blockSurfaceWithCache[key].clone();
    }

    var surf = new Surface(ifw, ifh);
    var f;
    for (var i = 0; i < 8; ++i) {
        f = function (x) {
            x *= (100 - (3-i)*16)/100;
            return Math.floor(x);
        }
        surf.context.fillStyle = 'rgb('+[f(r),f(g),f(b)]+')';
        fillRoundedRect(surf.context, i, i, ifw-i, ifh-i, 8);
    }

    _blockSurfaceWithCache[key] = surf;
    return surf;
}



/**************************************************************
 * sounds
 *************************************************************/

var minNote = 36;
var maxNote = 47;

function mkSoundPath(i) {
    return 'wav/'+i+'.wav';
}

function preloadSounds() {
    if (location.search.match(/[?&]sound=t(&|$)/)) {
        // bgm
        var bgm = Sound.load('wav/yuki.ogg');
        bgm.volume = 0.05;
        game.addEventListener('enterframe', function () {
            bgm.play();
        });

        // se
        for (var i = minNote; i <= maxNote; ++i) {
            game.preload(mkSoundPath(i));
        }
    }
}

function playHitSound() {
    if (location.search.match(/[?&]sound=t(&|$)/)) {
        var n = Math.floor(Math.random() * (maxNote - minNote)) + minNote;
        var p = mkSoundPath(n);
        game.assets[p].play();
    }
}



/**************************************************************
 * define block class
 *************************************************************/

// set at Shape's userData
var sleepingBlock = 1<<0;
var wakenBlock = 1<<1;
var activeBall = 1<<2;
var deadBall = 1<<3;
var userBar = 1<<4;
var worldWall = 1<<5;

// center-x, center-y, full-width, full-height
function addBlock(cx, cy, fw, fh) {
    var hw = fw/2;
    var hh = fh/2;
    var ifw = Math.floor(fw);
    var ifh = Math.floor(fh);

    var spr = new Sprite(ifw, ifh);
    spr.x = cx - hw;
    spr.y = cy - hh;
    spr.image = makeBlockSurfaceWithCache(ifw, ifh, 128,128,128);

    var bdy;

    var sd = new b2BoxDef();
    sd.extents.Set(hw, hh);
    sd.friction = 0.6;
    sd.restitution = 0.8;
    sd.density = 1;
    sd.userData = {
        kind : sleepingBlock,
        next : function () {
            var ud = bdy.GetShapeList().GetUserData();
            if (ud.kind == sleepingBlock) {
                ud.kind = wakenBlock;
                spr.image = makeBlockSurfaceWithCache(ifw, ifh, 32,128,32); // green, not yellowish-green
                blockCounter.dec(); // decrement global counter
            } else if (ud.kind == wakenBlock) {
                var now = new Date();
                ud.activedTime = now.getTime();

                ud.kind = activeBall;
                spr.image = makeBlockSurfaceWithCache(ifw, ifh, 128,32,32); // red
            } else if (ud.kind == activeBall) {
                ud.kind = deadBall;
                spr.image = makeBlockSurfaceWithCache(ifw, ifh, 32,32,128); // blue
            }
        },
        hitTime : 0,
        repeled : function () {
            // to fix bug (adhoc)
            // bdy is undefiend when 'q' key is pressed and collision happens
            if (bdy == undefined) { return; }

            var ud = bdy.GetShapeList().GetUserData();
            var now = new Date();
            if (ud.hitTime + 1000 < now.getTime()) {
                ud.hitTime = now.getTime();

                playHitSound();
                bdy.WakeUp();
                ud.next();
            }
        }
    };
    spr.addEventListener('enterframe', function () {
        var ud = bdy.GetShapeList().GetUserData();
        var now = new Date();
        if (('activedTime' in ud) && (ud.activedTime + 500 < now.getTime())) {
            bdy.m_mass /= 30;
            delete ud.activedTime;
        }
    });

    var bd = new b2BodyDef();
    bd.AddShape(sd);
    bd.position.Set(cx,cy);
    bd.isSleeping = true;

    bdy = world.CreateBody(bd);
    bdy.sprite = spr;
    spr.box2dBody = bdy;

    game.currentScene.addChild(spr);
    garbageArray.push(spr); // store to be removed at restart
    blockCounter.inc(); // increment global counter
    return spr;
}



/**************************************************************
 * define bar class
 *************************************************************/

// start, end
function addBar(v1,v2) {
    var diff = v2.Copy();
    diff.Subtract(v1);
    var hdiff = diff.Copy();
    hdiff.Multiply(0.5);
    var dlen = diff.Length();
    var hdlen = dlen / 2;
    var cntr = v1.Copy();
    cntr.Add(v2);
    cntr.Multiply(0.5);

    var idlen = Math.floor(dlen);
    var surf = new Surface(idlen, 2);
    surf.context.fillStyle = 'white';
    surf.redraw = function () { surf.context.fillRect(0,0,idlen,2); };
    surf.redraw();

    var spr = new Sprite(idlen, 2);
    spr.x = cntr.x - hdlen;
    spr.y = cntr.y - 1;
    spr.image = surf;
    spr.rotation = Math.atan(diff.y / diff.x)/3.14159*180;

    var sd = new b2BoxDef();
    sd.extents.Set(hdlen, 1);
    sd.friction = 1.0;
    sd.restitution = 3.5;
    sd.userData = {
        kind : userBar
    };

    var bd = new b2BodyDef();
    bd.AddShape(sd);
    bd.position = cntr.Copy();
    bd.rotation = Math.atan(diff.y / diff.x);

    // CreateBody must be called after you've prepared for collisions
    // collision may happen immidiately, in the func
    var bdy = world.CreateBody(bd);
    bdy.sprite = spr;
    spr.box2dBody = bdy;

    var birth = new Date();
    spr.addEventListener('enterframe', function() {
        var now = new Date();
        // 0 <= rest(t) = 3 - 2t
        var t = clampMin(0, 2 + 2 * ((birth.getTime() - now.getTime()) / 1000));
        spr.box2dBody.GetShapeList().m_restitution = t;

        function f(x) { return Math.floor(255*(x+1)/4); }
        surf.context.fillStyle = 'rgb('+f(t)+','+f(t)+','+f(t)+')';
        surf.redraw();

        if (birth.getTime() + 2000 < now.getTime()) {
            world.DestroyBody(spr.box2dBody);
            deleteElem(garbageArray, spr);
            game.currentScene.removeChild(spr);
        }
    });

    garbageArray.push(spr); // store to be removed at restart
    game.currentScene.addChild(spr);
    return spr;
}



/**************************************************************
 * define wall class
 *************************************************************/

function addWall(x1, y1, x2, y2) {
    var dx = x2 - x1;
    var dy = y2 - y1;
    var surf = new Surface(dx, dy);
    surf.context.fillStyle = 'rgb(128,128,128)';
    surf.context.fillRect(0,0,dx,dy);

    var spr = new Sprite(dx, dy);
    spr.x = x1;
    spr.y = y1;
    spr.image = surf;

    var sd = new b2BoxDef();
    sd.extents.Set((x2-x1)/2, (y2-y1)/2);
    sd.userData = { kind : worldWall };

    var bd = new b2BodyDef();
    bd.AddShape(sd);
    bd.position.Set((x1+x2)/2, (y1+y2)/2);

    var bdy = world.CreateBody(bd);
    bdy.sprite = spr;
    spr.box2dBody = bdy;

    game.currentScene.addChild(spr);
}



/**************************************************************
 * entry point
 *************************************************************/

var gameAreaMargin = 120;
var gameAreaX = 640;
var gameAreaY = 640;
var windowX = gameAreaX + 2*gameAreaMargin;
var windowY = gameAreaY + 2*gameAreaMargin;
function moveByMargin(x) {
    x.moveBy(gameAreaMargin, gameAreaMargin);
}

window.onload = function() {
    game = new Game(windowX, windowY);
    game.fps = 60;

    preloadSounds();

    game.onload = function() {
        game.pushScene(new Scene());
        game.currentScene.backgroundColor = "black";

        // show how to play
        var hlplbl0 = new Label();
        internationalize({
            ja : function () {
                hlplbl0.scale(1.4,1.4);
                hlplbl0.moveTo(360,4);
                hlplbl0.text = [
                    "      マウスのドラッグで線を引きます",
                    "ブロックは線に当たるたびに色を",
                    "          緑 -> 赤 -> 青 と変化させます",
                    "赤ブロックだけが白ブロックと衝突でき",
                    "  衝突された白ブロックは緑色になります"].join("<br>");
            },
            en : function () {
                hlplbl0.scale(1.4,1.4);
                hlplbl0.moveTo(320,4);
                hlplbl0.text = [
                    "        drag mouse to draw segment",
                    "when a block bounce on it, the color changes:",
                    "             green -> red -> blue",
                    "   only a red block collides with a white one",
                    "             then the white become green"].join("<br>");
            }
        })();
        moveByMargin(hlplbl0);
        hlplbl0.color = 'white';
        game.currentScene.addChild(hlplbl0);

        // show title
        var ttllbl = new Label();
        ttllbl.scale(1.6,1.6);
        ttllbl.moveTo(320,320);
        moveByMargin(ttllbl);
        ttllbl.text = internationalize({
            ja : "BOXkJS<br> <br>           クリックでスタート",
            en : "BOXkJS<br> <br>           click to start"
        });
        ttllbl.color = 'white';
        game.currentScene.addChild(ttllbl);

        // show how to play
        var hlplbl1 = new Label();
        internationalize({
            ja : function () {
                hlplbl1.scale(1.4,1.4);
                hlplbl1.moveTo(320,500);
                hlplbl1.text = [
                    "すべての白ブロックを撃ち落とせばクリア",
                    "                      'q'キーでリスタート",
                    "                ※音が出ます"].join("<br>");
            },
            en : function () {
                hlplbl1.scale(1.4,1.4);
                hlplbl1.moveTo(340,500);
                hlplbl1.text = [
                    "complete this when you down all white blocks",
                    "                press 'q' key to restart",
                    "              notice: it sounds"].join("<br>");
            }
        })();
        moveByMargin(hlplbl1);
        hlplbl1.color = 'white';
        game.currentScene.addChild(hlplbl1);



        // block counter as score
        blockCounter = {
            value : 0,
            inc : function () { ++blockCounter.value; scrlbl.redraw(); },
            dec : function () {
                --blockCounter.value;
                scrlbl.redraw();
                if (blockCounter.value <= 0) {
                    clrlbl.text = internationalize({
                        en : "COMPLETED",
                        ja : 'ゲーム クリアー'
                    });
                }
            },
        };

        // score board
        var scrlbl = new Label();
        scrlbl.scale(2,2);
        scrlbl.moveTo(530,400);
        moveByMargin(scrlbl);
        scrlbl.text = '';
        scrlbl.color = 'white';
        scrlbl.redraw = internationalize({
            en : function() {
                scrlbl.text = blockCounter.value + "blocks remain";
            },
            ja : function() {
                scrlbl.text = "残り" + blockCounter.value + "ブロック";
            }
        });
        game.currentScene.addChild(scrlbl);

        // show "GAME CLEAR"
        var clrlbl = new Label();
        clrlbl.scale(4,4);
        clrlbl.text = '';
        clrlbl.moveTo(windowX/2, windowY/3);
        clrlbl.color = "white";
        game.currentScene.addChild(clrlbl);

        // initialize world
        var worldAABB = new b2AABB();
        var worldMargin = 256;
        worldAABB.minVertex.Set(-worldMargin, -worldMargin);
        worldAABB.maxVertex.Set(windowX+worldMargin, windowY+worldMargin);
        var gravity = new b2Vec2(0, 98);
        var doSleep = true;
        world = new b2World(worldAABB, gravity, doSleep);
        world.SetFilter(new (function () { this.ShouldCollide = function (s1_,s2_) {
            function f(s1,s2) {
                if (s1.GetUserData().kind == sleepingBlock) {
                    if (s2.GetUserData().kind == activeBall) {
                        return true;
                    } else {
                        return false;
                    }
                }
                return true;
            }
            var a = f(s1_,s2_);
            var b = f(s2_,s1_);
            return a && b;
        }}));

        // walls around screen: not to drop blocks
        (function () {
            var p = gameAreaMargin;
            var x = windowX;
            var y = windowY;
            floort = addWall(0, 0, x, p);
            floorl = addWall(0, 0, p, y);
            floorr = addWall(x-p, 0, x, y);
            floorb = addWall(0, y-p, x, y);
        })();

        // step the world
        var prev = new Date();
        game.currentScene.addEventListener('enterframe', function() {
            // limit 't' to valid physical simulation
            var now = new Date();
            var t = (now.getTime()-prev.getTime()) / 1000;
            t = clamp(0.1, t);
            world.Step(t, 4);
            prev = now;

            for (var it = world.GetBodyList(); it; it = it.GetNext()) {
                if ("sprite" in it) {
                    it.sprite.x = it.GetOriginPosition().x - it.sprite.image.width/2;
                    it.sprite.y = it.GetOriginPosition().y - it.sprite.image.height/2;
                    it.sprite.rotation = Math.round(it.GetRotation()/3.14159*180);
                }
            }
            for (var it = world.GetContactList(); it; it = it.GetNext()) {
                var f = function (ud1, ud2) {
                    var k1 = ud1.kind;
                    var k2 = ud2.kind;
                    if (((k1 == sleepingBlock)
                         && (k2 == activeBall))
                        || ((k2 == userBar)
                            && ((k1 == wakenBlock) || (k1 == activeBall)))) {
                        if (it.GetManifoldCount() != 0) {
                            ud1.repeled();
                        }
                    }
                }
                f( it.GetShape1().GetUserData(), it.GetShape2().GetUserData());
                f( it.GetShape2().GetUserData(), it.GetShape1().GetUserData());
            }
        });

        // make the bar segment with mouse
        var startV = null;
        game.currentScene.addEventListener('touchstart', function (e) {
            startV = vecp(e);
        });
        game.currentScene.addEventListener('touchend', function (e) {
            if (startV) {
                addBar(startV, vecp(e));
            }
            startV = null;
        });

        var restart;
        game.keybind(81 ,'a'); // q
        // game.keybind(82 ,'a'); // r
        // game.keybind(88 ,'a'); // x
        game.addEventListener('enterframe', function () {
            if (game.input.a) {
                restart();
            }
        });

        // define initializing to call many times
        garbageArray = [];
        restart = function () {
            clrlbl.text = '';
            blockCounter.value = 0;
            scrlbl.redraw();

            // clear all blocks
            for (var i = 0; i < garbageArray.length; ++i) {
                game.currentScene.removeChild(garbageArray[i]);
                world.DestroyBody(garbageArray[i].box2dBody);
            }
            garbageArray = [];


            // add blocks
            var f = function addBlock32(x,y) { return addBlock(x+gameAreaMargin, y+gameAreaMargin, 32, 32); };
            for (var i = 0; i < 10; ++i) { f(20+i*40, 20+i*15); }
            for (var i = 0; i < 10; ++i) { f(420-i*35, 170+i*20); }
            for (var i = 0; i < 5; ++i) { f (70-i*10, 370-i*40); }

            // first greens
            for (var i = 0; i < 4; ++ i) {
                var ball = f(440-i*2*35, 230+i*2*20);
                ball.box2dBody.WakeUp();
                ball.box2dBody.GetShapeList().GetUserData().next();
            }

            // add blocks for a tutorial
            for (var i = 0; i < 4; ++i) { f(560+(i+1)*8, 160+(i+1)*60); }
            var ball2 = f(560, 100);
            ball2.box2dBody.WakeUp();
            ball2.box2dBody.GetShapeList().GetUserData().next();
            ball2.box2dBody.GetShapeList().GetUserData().next();
            var ball3 = f(590, 160);
            ball3.box2dBody.WakeUp();
            ball3.box2dBody.GetShapeList().GetUserData().next();
            ball3.box2dBody.GetShapeList().GetUserData().next();
            ball3.box2dBody.GetShapeList().GetUserData().next();
        };

        function startGame() {
            restart();
            game.currentScene.removeChild(ttllbl);
            game.currentScene.removeEventListener('touchstart', startGame)
        }
        game.currentScene.addEventListener('touchstart', startGame);
    };
    game.start();
};
