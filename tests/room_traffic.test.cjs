const test = require("node:test");
const assert = require("node:assert/strict");
const RoomTraffic = require("../frontend/traffic.js");

function accountedFor(traffic) {
  return traffic.queue.length + traffic.inFlight.length +
    traffic.delivered.server + traffic.delivered.quarantine + traffic.dropped;
}

test("steady input keeps running past the old replay duration", () => {
  const t = new RoomTraffic();
  t.advance(14000);
  const atFourteen = t.delivered.server;
  t.advance(14000);
  assert.equal(accountedFor(t), 140);
  assert.equal(t.delivered.server - atFourteen, 70);
});

test("queued and in-flight packets keep their route when new traffic is redirected", () => {
  const t = new RoomTraffic();
  t.setRate(0);
  t.enqueue(20);
  t.advance(500);
  assert.equal(t.inFlight.length, 5);
  assert.equal(t.queue.length, 15);
  t.target = "quarantine";
  t.enqueue(20);
  t.advance(3100);
  assert.equal(t.delivered.server, 14);
  assert.equal(t.delivered.quarantine, 0);
  t.advance(3000);
  assert.deepEqual(t.delivered, { server: 20, quarantine: 20 });
  assert.equal(t.queue.length + t.inFlight.length, 0);
});

test("overload fills the bounded queue; manual input lets it drain", () => {
  const t = new RoomTraffic();
  t.setRate(20);
  t.advance(20000);
  assert.equal(t.queue.length, 80);
  assert.equal(t.dropped, 121);
  assert.equal(accountedFor(t), 400);
  t.setRate(0);
  t.advance(15000);
  assert.equal(t.delivered.server, 279);
  assert.equal(t.queue.length + t.inFlight.length, 0);
  assert.equal(accountedFor(t), 400);
});

test("event accounting is independent of redraw cadence", () => {
  const once = new RoomTraffic();
  const frames = new RoomTraffic();
  for (const t of [once, frames]) { t.setRate(2); t.enqueue(20); }
  once.advance(17000);
  for (let i = 0; i < 1000; i++) frames.advance(17);
  assert.deepEqual(frames, once);
});
