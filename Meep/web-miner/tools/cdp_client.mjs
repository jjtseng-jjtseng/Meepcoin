// A minimal Chrome DevTools Protocol client for the live runners: one WebSocket, request/response by
// id, events (flattened Worker sessions included) to listeners.
//
// CLOSING REJECTS WHAT IS PENDING. A runner cancelled by a signal closes this socket to unblock its
// body; a request still waiting for an answer must then settle at once rather than hold the one
// finalization path open until its 60-second timeout.

export function connectCdp(url) {
  const socket = new WebSocket(url);
  const pending = new Map();
  const listeners = [];
  let nextId = 1;
  let closed = false;
  const rejectAll = (why) => {
    for (const [id, { reject }] of pending) { pending.delete(id); reject(new Error(why)); }
  };
  const ready = new Promise((res, rej) => { socket.onopen = res; socket.onerror = () => rej(new Error('DevTools connect failed')); });
  ready.catch(() => {});
  socket.onmessage = (event) => {
    const msg = JSON.parse(event.data);
    if (msg.id && pending.has(msg.id)) {
      const { ok, reject } = pending.get(msg.id);
      pending.delete(msg.id);
      if (msg.error) reject(new Error(msg.error.message)); else ok(msg.result);
    } else if (msg.method) {
      for (const fn of listeners) fn(msg.method, msg.params, msg.sessionId ?? null);
    }
  };
  socket.onclose = () => { closed = true; rejectAll('DevTools connection closed'); };
  return {
    ready,
    onEvent(fn) { listeners.push(fn); },
    send(method, params = {}, sessionId = undefined) {
      if (closed) return Promise.reject(new Error('DevTools connection closed'));
      const id = nextId++;
      return new Promise((ok, reject) => {
        pending.set(id, { ok, reject });
        try { socket.send(JSON.stringify({ id, method, params, ...(sessionId ? { sessionId } : {}) })); } catch (err) { pending.delete(id); reject(err); return; }
        setTimeout(() => { if (pending.delete(id)) reject(new Error(`CDP ${method} timed out`)); }, 60_000);
      });
    },
    close() {
      closed = true;
      rejectAll('DevTools connection closed');
      try { socket.close(); } catch { /* gone */ }
    },
  };
}

export async function evaluate(c, expression) {
  const r = await c.send('Runtime.evaluate', { expression, returnByValue: true, awaitPromise: true });
  if (r.exceptionDetails) throw new Error(`page threw: ${String(r.exceptionDetails.text ?? '').slice(0, 300)}`);
  return r.result.value;
}
