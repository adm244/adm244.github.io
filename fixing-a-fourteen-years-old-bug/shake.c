//#include "somevars.inc"

var e = Scene.LoadEntity("scenes\spr\bricks1.entity");
e.ScaleX = 200;
e.ScaleY = Scene.Height * 100 / 480;
e.Active = TRUE;
var s = e.GetSpriteObject(); // <-- this returns valid object pointer

// this comment is lost in time
if (Scene.Name == "outdoor") { return null; }

var dx;
var dy;

Set("bg");
Set("l1bg");
Set("l2bg");

Sleep(Random(0, 60) * 1000);
while (TRUE) {
  e.X = Random(0, Scene.Width - 35);
  e.SetSprite("scenes\spr\bricks" + ToString(Random(1, 2)) + ".sprite"); // <-- this destroys object
  s.Reset(); // <-- this tries to access destroyed object and crashes
  s.Play();
  e.PlaySound("sound\bricks" + ToString(Random(1, 4)) + ".ogg");
  e.SetSoundVolume(sound_volume * 100);
  var i = Random(0, 4);
  while (i > 0) {
    i = i - 1;
    if (i == 0) {
      dx = NULL;
      dy = NULL;
    } else {
      dx = 0;
      dy = Random(-1, 1);
    }
    Set("bg", dx, dy);
    Set("l1bg", dx, dy);
    Set("l2bg", dx, dy);
    Sleep(15);
  }
  Sleep(Random(30, 60) * 1000);
}

//#include "somecode.inc"

function Set(node, dx, dy) {
  return null;
  node = Scene.GetNode(node);
  if (node == NULL) { return null; }
  if (node.OriginalX == NULL) { node.OriginalX = node.X; }
  if (node.OriginalY == NULL) { node.OriginalY = node.Y; }
  if (dx == NULL) { dx = 0; }
  if (dy == NULL) { dy = 0; }
  node.X = node.OriginalX + dx;
  node.Y = node.OriginalY + dy;
  return null;
}

