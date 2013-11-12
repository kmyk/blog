// common
var fps = 30.0;
var ppm = 32.0 * 3.0;
var query;
var dscreen, dscreenCenter, bscreen, bscreenCenter;
var longside, shortside;

// createjs
var canvas;
var stage;

// box2d
var world;
var racket;
var walls;
var balls = [];
var ballDeathCallback = function(){};

function createRacket() {
    function createGrip(dpos, dradius, color) {
        // body
        var bodyDef = new b2BodyDef;
        bodyDef.type = b2Body.b2_dynamicBody;
        bodyDef.position = dpos.Copy();
        bodyDef.position.Multiply(1 / ppm);
        var body = world.CreateBody(bodyDef);
        body.type = "racket";
        createjs.EventDispatcher.initialize(body);

        // fixture
        var fixDef = new b2FixtureDef;
        fixDef.density = 0.2;
        fixDef.friction = 0.8;
        fixDef.restitution = -0.2;
        fixDef.shape = new b2CircleShape();
        fixDef.shape.m_radius = dradius / ppm;
        body.CreateFixture(fixDef);

        // shape
        body.shape = new createjs.Shape();
        body.shape.graphics.setStrokeStyle(16);
        body.shape.graphics.beginStroke(color);
        body.shape.graphics.drawCircle(0, 0, dradius);
        body.shape.alpha = 0.8;
        body.shape.compositeOperation = "lighter";
        body.addEventListener("update", updateShape);
        stage.addChild(body.shape);

        return body;
    }

   function createRubber(dpos, dsize, doff, color) {
        // body
        var bodyDef = new b2BodyDef;
        bodyDef.type = b2Body.b2_dynamicBody;
        bodyDef.position = dpos.Copy();
        bodyDef.position.Multiply(1 / ppm);
        bodyDef.bullet = true;
        var body = world.CreateBody(bodyDef);
        body.type = "racket";
        createjs.EventDispatcher.initialize(body);

        // fixture
        var fixDef = new b2FixtureDef;
        fixDef.density = 1.0;
        fixDef.friction = 1.0;
        fixDef.restitution = 1.0;
        fixDef.shape = new b2PolygonShape;
        fixDef.shape.SetAsBox(dsize.x / ppm, dsize.y / ppm);
        body.CreateFixture(fixDef);

        // shape
        body.shape = new createjs.Shape();
        body.shape.graphics.setStrokeStyle(16);
        body.shape.graphics.beginStroke(color);
        body.shape.graphics.rect(- dsize.x, - dsize.y, dsize.x * 2 - doff.x, dsize.y * 2 - doff.y);
        body.shape.alpha = 0.8;
        body.shape.compositeOperation = "lighter";
        body.addEventListener("update", updateShape);
        stage.addChild(body.shape);

        return body;
    }

    function joinParts(grip, rubber) {
        // mouse joint
        var jDef = new Box2D.Dynamics.Joints.b2MouseJointDef();
        jDef.bodyA = world.GetGroundBody();
        jDef.bodyB = grip;
        jDef.target = grip.GetPosition();
        jDef.maxForce = 1200.0 * (grip.GetMass() + rubber.GetMass());
        jDef.collideConnected = true;
        var mjoint = world.CreateJoint(jDef);
        stage.addEventListener("stagemousemove", function(evt) {
            var v = new b2Vec2(evt.stageX, evt.stageY);
            if ("3walls" in query && dscreen.x / 2 < v.x) {
                v.x = dscreen.x / 2;
            }
            v.Multiply(1 / ppm);
            mjoint.SetTarget(v);
        });

        stage.addEventListener("stagemousedown", function() {
            grip.SetLinearDamping(16);
            rubber.SetLinearDamping(16);
            grip.SetAngularDamping(800);
            rubber.SetAngularDamping(800);
            grip.SetFixedRotation(true);
            rubber.SetFixedRotation(true);
        });
        stage.addEventListener("stagemouseup", function() {
            grip.SetLinearDamping(0);
            rubber.SetLinearDamping(0);
            grip.SetAngularDamping(0);
            rubber.SetAngularDamping(0);
            grip.SetFixedRotation(false);
            rubber.SetFixedRotation(false);
        });

        var jDef = new Box2D.Dynamics.Joints.b2RevoluteJointDef();
        jDef.Initialize(grip, rubber, grip.GetPosition());
        var rjoint = world.CreateJoint(jDef);
        return [ mjoint, rjoint ];
    }

    var dradius = 4;
    var dsize = new b2Vec2(longside / 12.0, 1);
    var doff = new b2Vec2(longside / 20.0, 1);
    var dposg = dscreenCenter.Copy();
    dposg.y += shortside * 0.45;
    var dposr = dposg.Copy();
    dposr.x -= dradius + dsize.x;
    var clrg = color(whitish, light, dark);
    var clrr = color(whitish, dark, dark);

    var grip   = createGrip(  dposg, dradius,     clrg);
    var rubber = createRubber(dposr, dsize, doff, clrr);
    joinParts(grip, rubber);

    return { grip: grip, rubber: rubber };
}

function createWalls() {
    var dlines = [
        [new b2Vec2(             0, dscreen.y *  2), new b2Vec2(            0, dscreen.y * -1)], // l
        [new b2Vec2(dscreen.x * -1,              0), new b2Vec2(dscreen.x * 2,              0)], // t
        [new b2Vec2(dscreen.x     , dscreen.y * -1), new b2Vec2(dscreen.x    , dscreen.y *  2)], // r
        [new b2Vec2(dscreen.x * -1, dscreen.y     ), new b2Vec2(dscreen.x * 2, dscreen.y     )], // b
        ];
    if ("3walls" in query) {
        dlines = dlines.slice(1, dlines.length);
    } else {
        dlines = [ dlines[2] ];
    }
    var bodies = [];

    for (var i = 0; i < dlines.length; ++i) {
        var dv0 = dlines[i][0];
        var bv0 = dv0.Copy(); bv0.Multiply(1 / ppm);
        var dv1 = dlines[i][1];
        var bv1 = dv1.Copy(); bv1.Multiply(1 / ppm);
        var dcenter = dv0.Copy(); dcenter.Add(dv1); dcenter.Multiply(0.5);
        var bcenter = dcenter.Copy(); bcenter.Multiply(1 / ppm);

        // body
        var bodyDef = new b2BodyDef;
        bodyDef.type = b2Body.b2_staticBody;
        bodyDef.position = bcenter.Copy();
        bodyDef.bullet = true;
        var body = world.CreateBody(bodyDef);
        body.type = "wall";
        if ("3walls" in query) { body.role = (i == 1) ? "main" : "sub"; }
        createjs.EventDispatcher.initialize(body);

        // fixture
        var fixDef = new b2FixtureDef;
        fixDef.friction = 0.0;
        fixDef.restitution = 1.0;
        fixDef.shape = new b2PolygonShape;
        var ev0 = bv0.Copy(); ev0.Subtract(bcenter);
        var ev1 = bv1.Copy(); ev1.Subtract(bcenter);
        fixDef.shape.SetAsEdge(ev0, ev1);
        body.CreateFixture(fixDef);

        // shape
        body.shape = new createjs.Shape();
        body.shape.graphics.setStrokeStyle(64);
        body.shape.graphics.beginStroke("#FFF");
        body.shape.graphics.moveTo(dv0.x - dcenter.x, dv0.y - dcenter.y);
        body.shape.graphics.lineTo(dv1.x - dcenter.x, dv1.y - dcenter.y);
        body.shape.alpha = 0.8;
        body.shape.compositeOperation = "lighter";
        body.addEventListener("update", updateShape);
        stage.addChild(body.shape);

        bodies.push(body);
    }
    return bodies;
}

function updateWorld() {
    var evt = new createjs.Event("update");
    for (var i = world.GetBodyList(); i; i = i.GetNext()) {
        if (i !== world.GetGroundBody()) {
            evt.body = i;
            i.dispatchEvent(evt);
        }
    }
    var now = createjs.Ticker.getTime();
    // world.Step((now - world.last) / 1000.0, 10, 10);
    world.Step(1 / 60, 10, 10);
    world.ClearForces();
    world.last = now;
}


function init() {
    query = parseQueryString(location.search);

    canvas = document.getElementById("canvas");
    stage = new createjs.Stage(canvas);
    stage.enableDOMEvents(true);
    stage.enableMouseOver(10);
    createjs.Touch.enable(stage);

    // util vars
    dscreen = new b2Vec2(canvas.width, canvas.height);
    dscreenCenter = dscreen.Copy();
    dscreenCenter.Multiply(0.5);
    bscreen = dscreen.Copy();
    bscreen.Multiply(1 / ppm);
    bscreenCenter = dscreenCenter.Copy();
    bscreenCenter.Multiply(1 / ppm);
    longside  = (dscreen.y < dscreen.x) ? dscreen.x : dscreen.y;
    shortside = (dscreen.y < dscreen.x) ? dscreen.y : dscreen.x;

    // background
    canvas.style.backgroundColor = color(function(){return 0;}, dark, dark);
    (function() {
        var line = new createjs.Shape();
        var width = 4;

        // lines
        line.graphics.beginStroke("#666");
        // vertical
        line.graphics.setStrokeStyle(width);
        line.graphics.moveTo(        0, dscreenCenter.y);
        line.graphics.lineTo(dscreen.x, dscreenCenter.y);
        // frame
        line.graphics.setStrokeStyle(width * 2);
        line.graphics.moveTo(        0,         0);
        line.graphics.lineTo(        0, dscreen.y);
        line.graphics.lineTo(dscreen.x, dscreen.y);
        line.graphics.lineTo(dscreen.x,         0);
        line.graphics.lineTo(        0,         0);

        // net
        var d = width;
        var y = - d * Math.random();
        line.graphics.setStrokeStyle(width);
        line.graphics.beginStroke("#ccc");
        while (y <= dscreen.y) {
            line.graphics.moveTo(dscreenCenter.x, y);
            y += d;
            line.graphics.lineTo(dscreenCenter.x, y);
            y += d;
        }

        stage.addChild(line);
    })();

    // box2d
    world = new Box2D.Dynamics.b2World(new b2Vec2(0, 0), true);
    world.last = createjs.Ticker.getTime();
    walls = createWalls();
    racket = createRacket();
    createjs.EventDispatcher.initialize(world);
    function dispatch(evt) {
        world.dispatchEvent(evt);
        var a = evt.contact.GetFixtureA();
        var b = evt.contact.GetFixtureB();
        if ("dispatchEvent" in a) { evt.dispatchedFixture = "a"; a.dispatchEvent(evt); }
        if ("dispatchEvent" in b) { evt.dispatchedFixture = "b"; b.dispatchEvent(evt); }
        if ("dispatchEvent" in a.GetBody()) { evt.dispatchedFixture = "a"; a.GetBody().dispatchEvent(evt); }
        if ("dispatchEvent" in b.GetBody()) { evt.dispatchedFixture = "b"; b.GetBody().dispatchEvent(evt); }
    }
    world.SetContactListener({
        BeginContact: function(a)   { var evt = new createjs.Event("begincontact"); evt.contact = a;                      dispatch(evt); },
        EndContact:   function(a)   { var evt = new createjs.Event("endcontact");   evt.contact = a;                      dispatch(evt); },
        PreSolve:     function(a,b) { var evt = new createjs.Event("presolve");     evt.contact = a; evt.oldManifold = b; dispatch(evt); },
        PostSolve:    function(a,b) { var evt = new createjs.Event("postsolve");    evt.contact = a; evt.impulse     = b; dispatch(evt); },
    });

    // updater
    createjs.Ticker.setInterval(1000 / fps);
    createjs.Ticker.addEventListener("tick", function(evt) {
        updateWorld();
        stage.update(evt);
    });

    createjs.Ticker.addEventListener("tick", function(evt) {
        for (var i = balls.length - 1; 0 <= i; --i) {
            var p = balls[i].GetPosition();
            var m = 16 / ppm;
            if (p.x < 0-m || p.y < 0-m || m+bscreen.x < p.x || m+bscreen.y < p.y) {
                ballDeathCallback(balls[i]);
                destroyBall(balls[i]);
            }
        }
    });
}

var title = (function() {
    var first = true;
    return function() {
        var title = new createjs.Text(
            "SinglePong",
            "48px Arial", "#999");
        title.x = dscreen.x * 0.05;
        title.y = dscreen.y * 0.6;
        stage.addChild(title);

        var text = new createjs.Text(
            "Click to " + (first ? "S" : "Res") + "tart Game",
            "24px Arial", "#999");
        text.x = dscreen.x * 0.1;
        text.y = dscreen.y * 0.3;
        stage.addChild(text);

        var hint = new createjs.Text(
            "the wall ->",
            "20px Arial", "#999");
        hint.x = dscreen.x * 0.8;
        hint.y = dscreen.y * 0.3;
        stage.addChild(hint);

        stage.update();

        var stagemouseup = function() {
            stage.removeChild(title);
            stage.removeChild(text);
            stage.removeChild(hint);
            mainloop();
            stage.removeEventListener("stagemouseup", stagemouseup);
        };
        stage.addEventListener("stagemouseup", stagemouseup);

        first = false;
    };
})();

function createParticle(radius, color) {
    var shape = new createjs.Shape();
    shape.graphics.beginFill(color);
    shape.graphics.drawCircle(0, 0, radius);
    shape.alpha = 0.8;
    shape.compositeOperation = "lighter";
    var bstr = 1 + radius / 2.0;
    var bfilt = new createjs.BlurFilter(bstr, bstr, 2);
    var margin = bfilt.getBounds();
    shape.filters = [bfilt];
    shape.cache(- radius + margin.x, -radius + margin.y, radius * 2 + margin.width, radius * 2 + margin.height);
    stage.addChild(shape);
    return shape;
}

function createBall() {
    var speed = 1.2;
    var bodyDef = new b2BodyDef;
    bodyDef.type = b2Body.b2_dynamicBody;
    bodyDef.position = bscreenCenter.Copy();
    bodyDef.position.Add(new b2Vec2(Math.random() * 2 - 1, Math.random() * 2 - 1));
    if ("3walls" in query) {
        bodyDef.linearVelocity.Set(- speed * Math.random(), speed * randomPM());
    } else {
        bodyDef.linearVelocity.Set(speed * randomPM(), speed * randomPM());
    }
    if (! ("3walls" in query)) { bodyDef.linearDamping = 0.6; }
    var body = world.CreateBody(bodyDef);
    body.type = "ball";
    createjs.EventDispatcher.initialize(body);

    var dradius = 8;
    var bradius = dradius / ppm;
    var fixDef = new b2FixtureDef;
    fixDef.density = 1.0;
    fixDef.friction = ("3walls" in query) ? 0.0 : 0.4;
    fixDef.restitution = ("3walls" in query) ? 1.0 : 0.6;
    fixDef.shape = new b2CircleShape();
    fixDef.shape.m_radius = bradius;
    body.CreateFixture(fixDef);

    body.shape = new createjs.Shape();
    body.shape.graphics.beginFill(color(function(){return 0xff;}, light, light));
    body.shape.graphics.drawCircle(0, 0, dradius);
    body.shape.alpha = 0.8;
    body.shape.compositeOperation = "lighter";
    body.addEventListener("update", updateShape);
    stage.addChild(body.shape);

    body.addEventListener("postsolve", function(evt) {
        var t = body.lastContactTime ? body.lastContactTime : 0;
        if (createjs.Ticker.getTime() < t + 1000 / 3) { return; }
        body.lastContactTime = createjs.Ticker.getTime();
        var m = new Box2D.Collision.b2WorldManifold();
        evt.contact.GetWorldManifold(m);
        for (var i = evt.contact.GetManifold().m_pointCount - 1; 0 <= i; --i) {
            var p = m.m_points[i];
            p.Multiply(ppm);
            createExplosion({
                pos: p,
                color: color(light, light, light),
                radius: Math.random() * 4 + 8,
                size: Math.random() * 16 + 16,
            });
        }
    });

    body.addEventListener("update", function(evt) {
        var v = racket.grip.GetPosition().Copy();
        v.Subtract(body.GetPosition());
        v.Normalize();
        v.Multiply(0.004);
        body.ApplyForce(v, body.GetPosition());
    });

    body.addEventListener("update", function(evt) {
        var v = body.GetLinearVelocity().Copy();
        v.NegativeSelf();
        v.Multiply(0.002 * v.Length());
        body.ApplyForce(v, body.GetPosition());
    });

    if (! ("3walls" in query)) {
        body.addEventListener("update", function(evt) {
            var v = new b2Vec2(0, bscreenCenter.y - body.GetPosition().y);
            if (v.y * body.GetLinearVelocity().y < 0) {
                v.Multiply(Math.abs(0.02 * body.GetLinearVelocity().y * v.y));
                body.ApplyForce(v, body.GetPosition());
            }
        });
    }

    balls.push(body);
    return body;
}

function destroyBall(ball) {
    var dp = ball.GetPosition().Copy();
    dp.Multiply(ppm);
    createGeyser(dp);

    stage.removeChild(ball.shape);
    world.DestroyBody(ball);
    for (var i = balls.length - 1; 0 <= i; --i) {
        if (balls[i] === ball) {
            balls.splice(i, 1);
        }
    }
}

function clearBalls() {
    for (var i = balls.length - 1; 0 <= i; --i) {
        stage.removeChild(balls[i].shape);
        world.DestroyBody(balls[i]);
    }
    balls.length = 0; // clear the array
}

function createGeyser(dpos) {
    var p = dpos.Copy();

    var v = { x:0, y:0 }; // int
    if (dpos.x < 0) { p.x = 0; v.x = 1; } else if (dscreen.x < dpos.x) { p.x = dscreen.x; v.x = -1; }
    if (dpos.y < 0) { p.y = 0; v.y = 1; } else if (dscreen.y < dpos.y) { p.y = dscreen.y; v.y = -1; }
    if (v.x == 0 && v.y == 0) { return; }
    v = new b2Vec2(v.x, v.y); // to float
    v.Multiply(32);
    p.Add(v);

    smooth(Math.random() * 16 + 16, 0, function() {
        for (var i = 0; i < 2; ++i) {
            createExplosion({
                pos: p,
                color: color(light, light, light),
                radius: Math.random() * 8 + 8,
                size: Math.random() * 32 + 32,
            });
        }
    });
}

// args is a dict, which has [radius, color, size, pos]
function createExplosion(args) {
    var shape = createParticle(args.radius, args.color);

    var v = new b2Vec2(randomPM(), randomPM());
    v.Multiply(args.size);
    shape.x = args.pos.x + v.x;
    shape.y = args.pos.y + v.y;

    var tween = createjs.Tween.get(shape);
    tween.to({
        x: shape.x + v.x,
        y: shape.y + v.y
    }, 200, createjs.Ease.quietOut);
    tween.call(function() { stage.removeChild(shape); });

    return shape;
}

var updateHighscore = (function() {
    var highscore = 0;
    var suffix = '';
    var text = null;
    return function(score, sfx) {
        highscore = Math.max(highscore, score);
        if (! text) {
            text = new createjs.Text("", "20px Arial", "#999");
            text.x = dscreen.x * 0.6;
            text.y = dscreen.y * 0.8;
            stage.addChild(text);
        }
        if (highscore + (suffix.length / 1000.0) < score + (sfx.length / 1000.0)) {
            highscore = score; suffix = sfx;
        }
        text.text = "highscore: " + highscore + suffix;
    };
})();

var updateScore = (function() {
    var text = null;
    return function(score) {
        if (! text) {
            text = new createjs.Text("", "20px Arial", "#999");
            text.x = dscreen.x * 0.6;
            text.y = dscreen.y * 0.8 + 20 * 1.5;
            stage.addChild(text);
        }
        text.text = "score: " + Math.floor(score);
    };
})();

function mainloop() {
    var gameover = false;
    var age = 0;
    var start = createjs.Ticker.getTime();
    var score = 0;

    var tick = function(evt) {
        updateScore(score);

        age += 1 + Math.random();
        if (false && 80 < age) {
            createBall();
            age = 0;
        }
    };
    createjs.Ticker.addEventListener("tick", tick);

    clearBalls();
    var ball = createBall();

    var hit = function(evt) {
        var slf = (evt.dispatchedFixture == "a") ? evt.contact.GetFixtureA() : evt.contact.GetFixtureB();
        var opp = (evt.dispatchedFixture == "a") ? evt.contact.GetFixtureB() : evt.contact.GetFixtureA();
        var p = evt.impulse;
        for (var i = 0; i < evt.contact.GetManifold().m_pointCount; ++i) {
            var point = Math.floor(Math.sqrt(p.normalImpulses[i] * slf.GetBody().GetLinearVelocity().Length()) * 100);
            var oppbody = opp.GetBody();
            if ("3walls" in query) {
                if ((oppbody.type == "wall") && (oppbody.role == "main")) {
                    score += point;
                }
            } else {
                if (oppbody.type == "racket") {
                    if (oppbody.IsFixedRotation()) {
                        // score += 0;
                    } else {
                        score += point;
                    }
                } else {
                    score += point;
                }
            }
        }
    };
    ball.addEventListener("postsolve", hit);

    var nofix = true;
    var fixed = function(evt) { nofix = false; };
    stage.addEventListener("stagemousedown", fixed);

    ballDeathCallback = function(ball) {
        gameover = true;
        updateHighscore(score, nofix ? "+" : "");
        dtor();
    };

    var dtor = function() {
        createjs.Ticker.removeEventListener("tick", tick);
        ball.removeEventListener("postsolve", hit);
        stage.removeEventListener("stagemousedown", fixed);
        ballDeathCallback = function(){};
        title();
    };
}


window.onload = function() {
    init();
    title();
    createBall();
    createBall();
};
