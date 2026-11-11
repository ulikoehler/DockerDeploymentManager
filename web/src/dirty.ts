/// Global unsaved-changes registry. Editors acquire a token while they
/// hold modifications; the app shell warns on in-app navigation and the
/// browser warns on tab close/reload.
let count = 0;
let unloadHooked = false;

export function acquireDirty(): () => void {
  count++;
  if (!unloadHooked && typeof window !== 'undefined') {
    unloadHooked = true;
    window.addEventListener('beforeunload', (e) => {
      if (count > 0) e.preventDefault();
    });
  }
  let released = false;
  return () => {
    if (!released) {
      released = true;
      count = Math.max(0, count - 1);
    }
  };
}

export function dirtyCount(): number {
  return count;
}
