// Ambient canvas animation doesn't need 60 fps. A security monitor sits open all day,
// so the visual loops draw at a modest rate and slow down further when the window
// isn't focused. Hidden windows don't draw at all.
const FOCUSED_FPS = 24;
const BLURRED_FPS = 8;

export function frameGate() {
  let last = -Infinity;
  return (now: number): boolean => {
    if (document.hidden) return false;
    const fps = document.hasFocus() ? FOCUSED_FPS : BLURRED_FPS;
    if (now - last < 1000 / fps - 1) return false;
    last = now;
    return true;
  };
}
