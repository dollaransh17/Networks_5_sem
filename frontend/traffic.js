// Time and traffic exist only inside this browser simulation. Each queued packet
// keeps the destination it had when it entered the gateway.
class RoomTraffic {
  constructor() {
    this.now = 0;
    this.rate = 5;
    this.target = "server";
    this.queue = [];
    this.inFlight = [];
    this.delivered = { server: 0, quarantine: 0 };
    this.dropped = 0;
    this.nextArrival = 1000 / this.rate;
    this.nextDeparture = Infinity;
  }

  setRate(rate) {
    if (![0, 2, 5, 20].includes(rate)) throw new RangeError("Unsupported simulated packet rate.");
    if (this.rate === rate) return;
    this.rate = rate;
    this.nextArrival = rate ? this.now + 1000 / rate : Infinity;
  }

  enqueue(count, target = this.target) {
    const admitted = Math.min(count, 80 - this.queue.length);
    if (!this.queue.length && admitted) this.nextDeparture = this.now + 100;
    for (let i = 0; i < admitted; i++) this.queue.push(target);
    this.dropped += count - admitted;
    return admitted;
  }

  advance(milliseconds) {
    const end = this.now + milliseconds;
    while (Math.min(this.nextArrival, this.nextDeparture) <= end) {
      this.now = Math.min(this.nextArrival, this.nextDeparture);
      if (this.nextDeparture === this.now) {
        const target = this.queue.shift();
        const travel = target === "server" ? 2200 : 2500;
        this.inFlight.push({ target, start: this.now, end: this.now + travel });
        this.nextDeparture = this.queue.length ? this.now + 100 : Infinity;
      }
      if (this.nextArrival === this.now) {
        this.enqueue(1);
        this.nextArrival += 1000 / this.rate;
      }
    }
    this.now = end;
    for (let i = this.inFlight.length - 1; i >= 0; i--) {
      const packet = this.inFlight[i];
      if (packet.end <= end) {
        this.delivered[packet.target]++;
        this.inFlight.splice(i, 1);
      }
    }
  }
}

if (typeof module !== "undefined" && module.exports) module.exports = RoomTraffic;
