const get = (id) => document.getElementById(id);
const number = new Intl.NumberFormat();
const time = new Intl.DateTimeFormat(undefined, { dateStyle: "medium", timeStyle: "short" });
const clock = new Intl.DateTimeFormat(undefined, { hour: "numeric", minute: "2-digit" });
const percent = new Intl.NumberFormat(undefined, { style: "percent", maximumFractionDigits: 1 });
const labels = {
  benign: "Benign",
  bruteforce: "Brute force",
  dos: "Denial of service",
  portscan: "Port scan",
  within_baseline: "Within baseline",
  unusual: "Unusual",
};
const haikuMetrics = {
  xgboost: "XGBoost-style · Gateway pressure",
  bilstm: "Bi-LSTM-style · Queue pressure",
  isolation_forest: "Isolation Forest-style · Baseline deviation",
};
const form = get("flow-form");
let latestBurst;
let savingBurst = false;
let savedBurstId;
const simulationForm = get("simulation-form");
const pages = ["overview", "live-lab", "simulations"];
const example = {
  packet_rate: 12,
  byte_rate: 6480,
  avg_packet_size: 540,
  flow_duration_sec: 2.5,
  packet_count: 30,
  byte_count: 16200,
};
const chartFrame = get("chart-frame");
const chartMetric = get("chart-metric");
const roomPanel = get("server-room");
const room = typeof createServerRoom === "function" ? createServerRoom() : null;
if (!room) {
  get("room-viewport").textContent = "The 3D renderer could not load. Reload the console to try again.";
  get("room-device").disabled = true;
  get("room-target").disabled = true;
}
const roomTraffic = typeof RoomTraffic === "function" ? new RoomTraffic() : null;
if (!roomTraffic) {
  get("room-load").disabled = true;
  get("room-burst").disabled = true;
  get("room-inputs").querySelector("span").textContent = "Restart the console backend and reload to enable simulated traffic.";
}
const reduceMotion = matchMedia("(prefers-reduced-motion: reduce)");
const incidentFilter = get("incident-filter");
const stepFilter = get("step-filter");
const preview = globalThis.sdnConsolePreview;
const hasRecordedCheck = preview && Object.hasOwn(preview, "/api/flow-check");
const modes = {
  baseline: "Baseline",
  fixed: "Fixed",
  surge: "Surge",
  cooldown: "Cooldown",
  backpressure: "Backoff",
};
const sourceNames = {
  gateway: "Gateway",
  suricata: "Suricata",
  "risk-policy": "Risk policy",
  "sdn-controller": "SDN controller",
  "switch-counter": "Switch counters",
};
const chartMetrics = {
  wait: { field: "next_interval_s", units: "seconds between reply and next poll" },
  rate: { field: "packet_rate", units: "packets per second" },
  latency: { field: "rtt_ms", units: "round-trip milliseconds" },
};
let models = {};
let online = false;
let modelsLoading = false;
let checking = false;
let refreshingHealth = false;
let healthPoll;
let scenarioCatalogLoaded = false;
let simulationResult;
let overviewData;
let overviewError;
let overviewTimer;
let refreshingOverview = false;
let selectedBucket = -1;
let simulatedAudit;
let roomFrame = 0;
let previousFrame;
let roomSource = "simulation";
let captureSnapshot;
let captureMessage = "Waiting for the first collector report.";

async function request(path, options) {
  if (preview) {
    if (path === "/api/flow-check") {
      const measurements = JSON.parse(options.body);
      if (!Object.keys(example).every((feature) => measurements[feature] === example[feature])) {
        throw new Error("Select Use example to view recorded predictions in this preview.");
      }
    }
    if (Object.hasOwn(preview, path)) return preview[path];
    throw new Error("This request is unavailable in the preview.");
  }
  const response = await fetch(path, options);
  const payload = await response.json();
  if (!response.ok) throw new Error(payload.error);
  return payload;
}

function element(tag, value, className) {
  const node = document.createElement(tag);
  node.textContent = value;
  if (className) node.className = className;
  return node;
}

function dateLabel(timestamp) {
  const date = new Date(timestamp);
  return Number.isNaN(date.valueOf()) ? timestamp : time.format(date);
}

function displayName(value) {
  const words = value.replaceAll("_", " ");
  return words.charAt(0).toUpperCase() + words.slice(1);
}

function changePage(event) {
  const route = location.hash === "#flow-check" ? "simulations" : location.hash.slice(1);
  const current = pages.includes(route) ? route : "overview";
  for (const id of pages) {
    get(`${id}-page`).hidden = id !== current;
    const link = document.querySelector(`nav a[href="#${id}"]`);
    if (id === current) link.setAttribute("aria-current", "page");
    else link.removeAttribute("aria-current");
  }
  if (current === "simulations" || current === "live-lab") {
    const slot = get(current === "simulations" ? "simulation-room-slot" : "live-room-slot");
    if (roomPanel.parentElement !== slot) slot.append(roomPanel);
    syncRoomSource();
    if (current === "simulations" && !scenarioCatalogLoaded) loadScenarios();
    if (current === "simulations") renderChart();
  }
  syncRoomClock();
  if (event) {
    scheduleOverview(0);
    get("content").focus({ preventScroll: true });
    window.scrollTo(0, 0);
  }
}

function renderOverview(data, error) {
  renderOverviewAudit(data, error);

  const events = data?.events ?? [];
  for (const item of document.querySelectorAll("[data-count]")) {
    const count = data?.counts?.[item.dataset.count];
    item.textContent = count == null ? "—" : number.format(count);
  }

  renderIncidents(data, error);

  get("events").replaceChildren(...events.map((event) => {
    const row = document.createElement("li");
    const marker = element("span", "", "activity-dot");
    marker.dataset.source = event.source;
    marker.setAttribute("aria-hidden", "true");
    const detail = document.createElement("div");
    const timestamp = element("time", dateLabel(event.occurred_at));
    timestamp.dateTime = event.occurred_at;
    detail.append(element("div", displayName(event.event_type)), element("small", event.source));
    row.append(marker, detail, timestamp);
    return row;
  }));
  get("events").hidden = events.length === 0;
  get("events-empty").hidden = events.length > 0;
  get("events-empty").textContent = error ? "Activity is unavailable." : "No events to show.";
}

function renderOverviewAudit(data, error) {
  const toggle = get("audit-demo");
  toggle.textContent = simulatedAudit ? "Show recorded audit" : "Simulate audit";
  const waiting = data?.audit_store === "waiting";
  const status = simulatedAudit ? "Demo events generated in this browser." : error || (waiting
    ? "Waiting for the lab to write its first audit records."
    : (preview ? "Sample audit records for this preview." : "From the local incident store · refreshes every 5 s."));
  if (get("audit-status").textContent !== status) get("audit-status").textContent = status;
  renderAuditChart(simulatedAudit ?? data?.historical_activity ?? data?.activity,
    !simulatedAudit && error, !simulatedAudit && Boolean(data?.historical_activity));
}

function createAuditDemo() {
  const bucketSeconds = 300;
  const asOf = Math.floor(Date.now() / 1000);
  const counts = [0, 0, 1, 0, 1, 0, 2, 3, 6, 4, 2, 1];
  return {
    as_of: asOf,
    bucket_seconds: bucketSeconds,
    buckets: counts.map((count, index) => ({
      start_at: asOf - (counts.length - index) * bucketSeconds,
      count,
    })),
    sources: { suricata: 8, "risk-policy": 5, "sdn-controller": 7 },
  };
}

function renderAuditChart(activity, stale, historical) {
  const badge = get("audit-mode");
  badge.dataset.state = stale ? "stale" : (simulatedAudit || preview || historical ? "preview" : "live");
  badge.textContent = simulatedAudit ? "Simulated audit" : stale ? "Last successful read" : (preview ? "Sample data" : historical ? "Historical audit" : "Live audit");
  badge.hidden = !activity && !stale;
  get("audit-visuals").hidden = !activity;
  if (!activity) return;

  const { buckets, bucket_seconds: interval, sources, as_of: asOf } = activity;
  get("audit-trend-title").textContent = simulatedAudit ? "Simulated events over one hour" : historical
    ? `Most recent hour with events · ${new Date(asOf * 1000).toLocaleDateString()}`
    : "Events in the last hour";
  const total = buckets.reduce((sum, bucket) => sum + bucket.count, 0);
  const max = Math.max(1, ...buckets.map((bucket) => bucket.count));
  const events = (count) => `${number.format(count)} ${count === 1 ? "event" : "events"}`;
  const label = (seconds) => clock.format(seconds * 1000);
  const bars = get("audit-bars");
  if (selectedBucket < 0) selectedBucket = buckets.length - 1;

  function select(index, moveFocus = false) {
    selectedBucket = index;
    for (const [slot, bar] of Array.from(bars.children).entries()) {
      bar.tabIndex = slot === index ? 0 : -1;
      bar.setAttribute("aria-pressed", String(slot === index));
    }
    get("audit-chart-detail").textContent = bars.children[index].dataset.detail;
    if (moveFocus) bars.children[index].focus();
  }

  if (bars.children.length !== buckets.length) {
    bars.replaceChildren(...buckets.map((_, index) => {
      const bar = element("button", "", "audit-bar");
      bar.type = "button";
      bar.addEventListener("pointerenter", () => select(index));
      bar.addEventListener("focus", () => select(index));
      bar.addEventListener("click", () => select(index));
      bar.addEventListener("keydown", (event) => {
        const targets = { ArrowLeft: index - 1, ArrowRight: index + 1, Home: 0, End: buckets.length - 1 };
        if (!Object.hasOwn(targets, event.key)) return;
        event.preventDefault();
        select(Math.max(0, Math.min(buckets.length - 1, targets[event.key])), true);
      });
      return bar;
    }));
  }

  for (const [index, { start_at: start, count }] of buckets.entries()) {
    const bar = bars.children[index];
    bar.style.setProperty("--bar-fill", `${count / max * 100}%`);
    bar.dataset.events = count;
    bar.dataset.detail = `${label(start)} – ${label(start + interval)} · ${events(count)}`;
    bar.setAttribute("aria-label", `${label(start)} to ${label(start + interval)}, ${events(count)}`);
  }
  select(Math.min(selectedBucket, buckets.length - 1));
  get("audit-window-total").textContent = events(total);
  get("audit-window-start").textContent = label(buckets[0].start_at);
  get("audit-window-end").textContent = label(asOf);

  const orderedSources = Object.entries(sources).sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]));
  const visibleSources = orderedSources.slice(0, 5);
  if (orderedSources.length > 5) {
    visibleSources.push(["Other sources", orderedSources.slice(5).reduce((sum, [, count]) => sum + count, 0)]);
  }
  get("audit-source-list").replaceChildren(...visibleSources.map(([source, count]) => {
    const row = element("li", "", "audit-source");
    const meter = element("meter", "");
    meter.max = total;
    meter.value = count;
    meter.setAttribute("aria-hidden", "true");
    const name = Object.hasOwn(sourceNames, source) ? sourceNames[source] : source;
    row.append(element("span", name), element("strong", number.format(count)), meter);
    return row;
  }));
  get("audit-sources-empty").hidden = orderedSources.length > 0;
}

function renderIncidents(data, error) {
  const allIncidents = data?.incidents ?? [];
  const selection = incidentFilter.value;
  const incidents = selection ? allIncidents.filter((incident) => incident.status === selection) : allIncidents;
  incidentFilter.disabled = allIncidents.length === 0;
  get("incident-rows").replaceChildren(...incidents.map((incident) => {
    const row = document.createElement("tr");
    const status = element("td", "", "status-label");
    status.dataset.status = incident.status;
    status.append(element("span", displayName(incident.status), "status-pill"));
    row.append(
      element("td", incident.id, "mono"),
      element("td", incident.subject_ip, "mono"),
      status,
      element("td", dateLabel(incident.opened_at)),
    );
    return row;
  }));
  get("incident-table").hidden = incidents.length === 0;
  get("incidents-empty").hidden = incidents.length > 0;
  get("incidents-empty").textContent = error ? "Incidents are unavailable." : (data?.audit_store === "waiting"
    ? "Incidents will appear when the store is available."
    : (selection ? "No recent incidents match this status." : "No incidents have been recorded."));
}

function renderChart() {
  if (!simulationResult || !chartFrame.clientWidth) return;
  const canvas = get("polling-chart");
  const width = chartFrame.clientWidth;
  const height = chartFrame.clientHeight;
  const dpi = Math.min(window.devicePixelRatio || 1, 2);
  const pixelWidth = Math.round(width * dpi);
  const pixelHeight = Math.round(height * dpi);
  if (canvas.width !== pixelWidth) canvas.width = pixelWidth;
  if (canvas.height !== pixelHeight) canvas.height = pixelHeight;
  const ctx = canvas.getContext("2d");
  if (!ctx) return;
  ctx.setTransform(dpi, 0, 0, dpi, 0, 0);
  ctx.clearRect(0, 0, width, height);
  ctx.setLineDash([]);
  ctx.lineWidth = 1;

  const { adaptive, fixed, duration_s: duration } = simulationResult;
  const { field } = chartMetrics[chartMetric.value] ?? chartMetrics.wait;
  const boundary = { left: 42, top: 16, right: width - 18, bottom: height - 28 };
  const baseline = fixed.steps[0].next_interval_s;
  const highest = Math.max(1, ...[fixed, adaptive].flatMap((run) => run.steps.map((step) => step[field] ?? 0)));
  const magnitude = 10 ** Math.floor(Math.log10(highest / 4));
  const stepSize = [1, 2, 5, 10].find((size) => size * magnitude >= highest / 4) * magnitude;
  const ticks = Math.ceil(highest / stepSize);
  const maxValue = ticks * stepSize;
  const x = (seconds) => boundary.left + seconds / duration * (boundary.right - boundary.left);
  const y = (value) => boundary.bottom - value / maxValue * (boundary.bottom - boundary.top);
  const styles = getComputedStyle(canvas);
  const color = (name) => styles.getPropertyValue(`--${name}`).trim();
  ctx.font = `12px ${styles.fontFamily}`;
  ctx.fillStyle = color("secondary");
  ctx.strokeStyle = color("rule");
  ctx.textAlign = "right";
  ctx.textBaseline = "middle";
  for (let index = 0; index <= ticks; index++) {
    const tick = index * stepSize;
    ctx.beginPath();
    ctx.moveTo(boundary.left, y(tick));
    ctx.lineTo(boundary.right, y(tick));
    ctx.stroke();
    ctx.fillText(number.format(tick), boundary.left - 8, y(tick));
  }
  ctx.textAlign = "center";
  for (let tick = 0; tick <= duration; tick += 2) {
    if (width < 420 && tick % 4 && tick !== duration) continue;
    ctx.beginPath();
    ctx.moveTo(x(tick), boundary.top);
    ctx.lineTo(x(tick), boundary.bottom);
    ctx.stroke();
    ctx.fillText(`${tick} s`, x(tick), boundary.bottom + 16);
  }

  // Samples and policy changes become observable when the poll reply arrives.
  for (const [strategy, tone, dash, stroke] of [
    [adaptive, "primary", [], 3], [fixed, "secondary", [5, 5], 1.5],
  ]) {
    let previous = field === "next_interval_s" ? baseline : null;
    const points = [];
    ctx.beginPath();
    if (previous != null) ctx.moveTo(x(0), y(previous));
    for (const step of strategy.steps) {
      const value = step[field];
      const position = x(step.reply_at_s);
      if (value != null) {
        if (previous == null) ctx.moveTo(position, y(value));
        else {
          if (field === "next_interval_s") ctx.lineTo(position, y(previous));
          ctx.lineTo(position, y(value));
        }
        if (field !== "next_interval_s") points.push([position, y(value)]);
      }
      previous = value;
    }
    if (field === "next_interval_s") ctx.lineTo(x(duration), y(previous));
    ctx.strokeStyle = color(tone);
    ctx.lineWidth = stroke;
    ctx.setLineDash(dash);
    ctx.stroke();
    ctx.fillStyle = color(tone);
    for (const [px, py] of points) ctx.fillRect(px - 1.5, py - 1.5, 3, 3);
  }
}

function renderTraffic() {
  room?.draw(roomTraffic);
  const counts = roomTraffic.delivered;
  for (const [id, count] of [
    ["room-delivered", counts.server + counts.quarantine],
    ["room-server-count", counts.server], ["room-quarantine-count", counts.quarantine],
    ["room-queued", roomTraffic.queue.length], ["room-in-flight", roomTraffic.inFlight.length],
    ["room-dropped", roomTraffic.dropped],
  ]) {
    const field = get(id);
    const label = number.format(count);
    if (field.textContent !== label) field.textContent = label;
  }
}

function advanceRoom(now) {
  if (previousFrame !== undefined) {
    // A suspended browser can return hours later without a visibility event.
    // Freeze that interval, as when switching away from the room.
    const elapsed = now - previousFrame;
    if (elapsed > 0 && elapsed < 2000) roomTraffic.advance(elapsed);
  }
  previousFrame = now;
}

function runRoom(now) {
  const interval = reduceMotion.matches ? 200 : 1000 / 30;
  if (previousFrame === undefined || now - previousFrame >= interval) {
    advanceRoom(now);
    renderTraffic();
  }
  roomFrame = requestAnimationFrame(runRoom);
}

function syncRoomClock() {
  const visible = !document.hidden && roomSource === "simulation" &&
    !get("simulations-page").hidden;
  if (visible && roomTraffic && !roomFrame) {
    previousFrame = performance.now();
    renderTraffic();
    roomFrame = requestAnimationFrame(runRoom);
  } else if (!visible && roomFrame) {
    advanceRoom(performance.now());
    cancelAnimationFrame(roomFrame);
    previousFrame = undefined;
    roomFrame = 0;
  }
}

function changeTraffic(action) {
  if (!roomTraffic) return;
  if (roomFrame) advanceRoom(performance.now());
  action();
  renderTraffic();
}

get("room-burst").addEventListener("click", () => changeTraffic(() => roomTraffic.enqueue(20)));
get("room-load").addEventListener("change", event => changeTraffic(() => roomTraffic.setRate(Number(event.target.value))));
get("room-target").addEventListener("change", event => changeTraffic(() => { roomTraffic.target = event.target.value; }));

function renderRoomCapture() {
  if (roomSource !== "capture") return;
  const observedPort = captureSnapshot?.interface;
  const device = get("room-device").value;
  const selectedPort = { sensor: "s1-eth1", server: "s1-eth2", quarantine: "s1-eth3" }[device];
  const matches = device === "switch" || (selectedPort && selectedPort === observedPort);
  const interval = matches ? captureSnapshot?.intervals?.at(-1) : undefined;
  get("room-capture-rate").textContent = interval ? number.format(interval.packets / interval.elapsed) : "—";
  get("room-capture-port").textContent = matches ? (observedPort ?? "—") : "Not monitored";
  get("room-capture-count").textContent = interval ? number.format(interval.packets) : "—";
  const status = get("room-capture-status");
  const message = observedPort && !matches
    ? `No capture for this device. Collector is monitoring ${observedPort}.`
    : captureMessage;
  if (status.textContent !== message) status.textContent = message;
  room?.showCapture(captureSnapshot);
}

function syncRoomSource() {
  const source = get("live-lab-page").hidden ? "simulation" : "capture";
  if (source === roomSource) return;
  roomSource = source;
  const capture = source === "capture";
  for (const id of ["room-target", "room-target-label", "room-sim-readings", "room-inputs", "room-flow-check"]) {
    get(id).hidden = capture;
  }
  get("room-capture-readings").hidden = !capture;
  get("room-capture-status").hidden = !capture;
  get("room-title").textContent = capture ? "3D switch capture" : "3D server room";
  get("room-source-label").textContent = capture ? "Collector reports" : "Synthetic traffic";
  roomPanel.dataset.source = source;
  room?.setSource(source);
  renderRoomCapture();
  syncRoomClock();
}

get("room-device").addEventListener("change", renderRoomCapture);
window.addEventListener("lab-capture-update", ({ detail }) => {
  captureSnapshot = detail.snapshot;
  captureMessage = detail.message;
  renderRoomCapture();
});

function updateChartMetric() {
  const { units } = chartMetrics[chartMetric.value] ?? chartMetrics.wait;
  get("chart-axis").textContent = `Elapsed simulation time · ${units}`;
  renderChart();
}

function renderSimulation(result) {
  simulationResult = result;
  get("simulation-status").textContent = result.title;
  get("scenario-duration").textContent = `${result.duration_s} s benchmark`;
  get("scenario-duration").hidden = false;
  get("fixed-polls").textContent = result.fixed.completed_polls;
  get("adaptive-polls").textContent = result.adaptive.completed_polls;
  get("backpressure-cycles").textContent = result.adaptive.backpressure_cycles;
  get("simulation-finding").textContent = describeComparison(result);
  renderSimulationRows();
  get("simulation-output").hidden = false;
  updateChartMetric();
}

function describeComparison({ fixed, adaptive }) {
  const backoff = adaptive.steps.filter((step) => step.mode === "backpressure");
  if (backoff.length) {
    const longest = Math.max(...backoff.map((step) => step.next_interval_s));
    return `Slow replies triggered adaptive backoff. The longest wait was ${number.format(longest)} s.`;
  }
  if (fixed.steps.some((step) => step.reset_detected) && adaptive.steps.some((step) => step.reset_detected)) {
    return "Both strategies skipped a rate calculation at the counter reset and used the reset sample as the new baseline.";
  }
  const surge = adaptive.steps.find((step) => step.mode === "surge");
  if (surge) {
    const change = adaptive.completed_polls - fixed.completed_polls;
    return `Adaptive polling shortened its wait to ${number.format(surge.next_interval_s)} s during the burst and took ${number.format(change)} more samples.`;
  }
  return "The workload kept both strategies on the same polling schedule.";
}

function renderSimulationRows() {
  if (!simulationResult) return;
  const { fixed, adaptive } = simulationResult;
  const steps = Object.entries({ fixed, adaptive })
    .filter(([strategy]) => !stepFilter.value || stepFilter.value === strategy)
    .flatMap(([strategy, run]) => run.steps.map((step) => ({ ...step, strategy })))
    .sort((a, b) => a.sample_at_s - b.sample_at_s);
  get("simulation-rows").replaceChildren(...steps.map((step) => {
    const row = document.createElement("tr");
    const state = element("td", step.reset_detected ? "Counter reset" : modes[step.mode], "step-state");
    state.dataset.state = step.reset_detected ? "reset" : step.mode;
    row.append(
      element("td", `${number.format(step.sample_at_s)} s`, "mono"),
      element("td", displayName(step.strategy)),
      element("td", `${step.rtt_ms} ms`),
      element("td", step.packet_rate == null ? "—" : number.format(step.packet_rate), "mono"),
      element("td", `${step.next_interval_s} s`, "mono"),
      state,
    );
    return row;
  }));
}

async function loadScenarios() {
  scenarioCatalogLoaded = true;
  get("simulation-error").hidden = true;
  get("retry-scenarios").hidden = true;
  get("simulation-status").textContent = "Loading scenarios…";
  try {
    const { scenarios } = await request("/api/simulations", { signal: AbortSignal.timeout(6000) });
    get("scenarios").replaceChildren(...scenarios.map(({ id, title }) => new Option(title, id)));
    get("scenarios").disabled = false;
    get("run-simulation").disabled = false;
    simulationForm.requestSubmit();
  } catch {
    get("simulation-status").textContent = "Scenarios unavailable.";
    get("simulation-error").textContent = "Could not load the workload list. Check the console connection and retry.";
    get("simulation-error").hidden = false;
    get("retry-scenarios").hidden = false;
  }
}

simulationForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  const selected = new FormData(simulationForm).get("scenario");
  simulationResult = undefined;
  for (const control of simulationForm.elements) control.disabled = true;
  get("simulation-status").textContent = "Running simulation…";
  get("simulation-error").hidden = true;
  get("simulation-output").hidden = true;
  get("scenario-duration").hidden = true;
  try {
    const result = await request(`/api/simulations/${encodeURIComponent(selected)}`, { signal: AbortSignal.timeout(6000) });
    renderSimulation(result);
  } catch {
    get("simulation-status").textContent = "Simulation unavailable.";
    get("simulation-error").textContent = "The simulation could not be loaded. Try running it again.";
    get("simulation-error").hidden = false;
  } finally {
    for (const control of simulationForm.elements) control.disabled = false;
  }
});
get("scenarios").addEventListener("change", () => simulationForm.requestSubmit());
get("retry-scenarios").addEventListener("click", loadScenarios);
stepFilter.addEventListener("change", renderSimulationRows);
chartMetric.addEventListener("change", updateChartMetric);
new ResizeObserver(renderChart).observe(chartFrame);
matchMedia("(prefers-color-scheme: dark)").addEventListener("change", renderChart);

function renderResults(results = {}) {
  get("results").replaceChildren(...Object.entries(models).map(([key, model]) => {
    const row = document.createElement("li");
    const result = results[key];
    const haiku = model.provider === "haiku";
    let status = modelsLoading ? "Loading…" : (model.ready ? "Ready" : "Unavailable");
    let detail = result?.rationale ?? model.message;
    if (result) {
      status = result.demo_score != null
        ? `${result.demo_score}/100`
        : (labels[result.label] ?? displayName(result.label));
      if (result.confidence != null) detail = `Model confidence ${percent.format(result.confidence)}`;
      if (result.anomaly_score != null) {
        const score = number.format(result.anomaly_score.toPrecision(4));
        detail = `Anomaly score ${score}`;
      }
    } else if (!detail && Object.keys(results).length > 0) {
      status = "No result";
    }
    const verdict = element("span", status, "result-label");
    if (result) verdict.dataset.label = result.label;
    row.append(element("strong", haiku ? haikuMetrics[key] : model.name), verdict);
    if (detail) row.append(element("small", detail));
    if (result?.demo_score != null) {
      const name = `${haikuMetrics[key]} score ${result.demo_score} out of 100`;
      const meter = element("meter", "", "confidence-meter");
      meter.max = 100;
      meter.value = result.demo_score;
      meter.setAttribute("aria-label", name);
      row.append(meter);
    }
    if (result?.confidence != null) {
      const meter = element("meter", "", "confidence-meter");
      meter.max = 1;
      meter.value = result.confidence;
      meter.setAttribute("aria-hidden", "true");
      row.append(meter);
    }
    return row;
  }));
}

async function refreshHealth() {
  if (refreshingHealth) return;
  refreshingHealth = true;
  try {
    const options = preview ? undefined : { signal: AbortSignal.timeout(4500) };
    const health = await request("/api/health", options);
    online = true;
    models = health.models;
    const haiku = Object.values(models).some(model => model.provider === "haiku");
    get("results-title").textContent = haiku ? "Traffic assessment" : "Model results";
    get("simulation-storage").hidden = !health.simulation_storage || Boolean(preview);
    modelsLoading = health.models_loading;
  } catch {
    online = false;
    models = {};
    modelsLoading = false;
  } finally {
    refreshingHealth = false;
  }
  const status = get("service-status");
  status.textContent = preview ? "Sample preview" : (online ? "Backend online" : "Backend offline");
  status.dataset.state = preview ? "preview" : (online ? "ready" : "offline");
  clearCheck();
  clearTimeout(healthPoll);
  if (modelsLoading) healthPoll = setTimeout(refreshHealth, 1000);
}

function scheduleOverview(delay = 5000) {
  clearTimeout(overviewTimer);
  if (!preview && !document.hidden && !get("overview-page").hidden) {
    overviewTimer = setTimeout(refresh, delay);
  }
}

async function refresh() {
  if (refreshingOverview) return;
  refreshingOverview = true;
  get("refresh").disabled = true;
  try {
    const options = preview ? undefined : { signal: AbortSignal.timeout(4500) };
    overviewData = await request("/api/overview", options);
    overviewError = "";
    if (!online && !preview) refreshHealth();
  } catch {
    const hasData = overviewData?.audit_store === "ready";
    if (!overviewError && !preview) refreshHealth();
    overviewError = hasData ? "Update failed. Showing the last successful read." : "The incident store is unavailable.";
  } finally {
    refreshingOverview = false;
    get("refresh").disabled = false;
    scheduleOverview();
  }
  renderOverview(overviewData, overviewError);
}

function canCheck() {
  if (!online || modelsLoading || !Object.values(models).some((model) => model.ready)) return false;
  if (!preview) return true;
  const measurements = flowMeasurements();
  return hasRecordedCheck && Object.entries(example).every(([key, value]) => measurements[key] === value);
}

function clearCheck() {
  if (checking) return;
  get("submit-check").disabled = !canCheck();
  get("form-error").hidden = true;
  let message = "Send a custom burst to compare model predictions.";
  if (modelsLoading) message = "Flow checks will be available when the models finish loading.";
  else if (!online) message = "Start the local backend to check a flow.";
  else if (preview && !hasRecordedCheck) message = "This preview has no recorded predictions.";
  else if (preview && !canCheck()) message = "Select Use example to load the measurements for the recorded predictions.";
  else if (preview) message = "Check the example flow to view its recorded predictions.";
  else if (!canCheck()) message = "No model is ready. Check the model details below.";
  else if (Object.values(models).some(model => model.provider === "haiku")) {
    message = "Send a burst to compare three model-inspired assessments.";
  }
  get("result-message").textContent = message;
  renderResults();
}

form.addEventListener("input", clearCheck);
get("fill-example").addEventListener("click", () => {
  for (const key of ["packet_count", "avg_packet_size", "flow_duration_sec"]) {
    form.elements.namedItem(key).value = example[key];
  }
  clearCheck();
});

function flowMeasurements() {
  const packetCount = form.elements.namedItem("packet_count").valueAsNumber;
  const packetSize = form.elements.namedItem("avg_packet_size").valueAsNumber;
  const duration = form.elements.namedItem("flow_duration_sec").valueAsNumber;
  const byteCount = packetCount * packetSize;
  return {
    packet_count: packetCount,
    avg_packet_size: packetSize,
    flow_duration_sec: duration,
    byte_count: byteCount,
    packet_rate: packetCount / duration,
    byte_rate: byteCount / duration,
  };
}


function syncSaveButton() {
  get("save-simulation").disabled = savingBurst || !latestBurst || latestBurst.id === savedBurstId;
}

get("save-simulation").addEventListener("click", async () => {
  if (get("save-simulation").disabled) return;
  const burst = latestBurst;
  savingBurst = true;
  syncSaveButton();
  get("simulation-save-status").textContent = "Saving burst to S3…";
  try {
    const receipt = await request("/api/simulation-records", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(burst),
    });
    if (receipt.cloudwatch_logged !== false) savedBurstId = burst.id;
    if (latestBurst !== burst) return;
    const link = get("simulation-s3-link");
    link.href = receipt.console_url;
    link.hidden = false;
    get("simulation-json-text").textContent = receipt.json;
    get("simulation-json").hidden = false;
    get("simulation-json").open = true;
    const logStatus = receipt.cloudwatch_logged === true
      ? " · CloudWatch event recorded"
      : (receipt.cloudwatch_logged === false ? " · CloudWatch failed. Click Save to retry." : "");
    get("simulation-save-status").textContent = `Saved to s3://${receipt.bucket}/${receipt.key}${logStatus}`;
  } catch (error) {
    if (latestBurst === burst) get("simulation-save-status").textContent = error.message;
  } finally {
    savingBurst = false;
    syncSaveButton();
  }
});

form.addEventListener("submit", async (event) => {
  event.preventDefault();
  if (checking || !canCheck() || !form.reportValidity()) return;
  const features = flowMeasurements();
  const overloaded = get("auto-quarantine").checked && features.packet_rate > 10;
  const destination = overloaded ? "quarantine" : get("room-target").value;
  changeTraffic(() => {
    const admitted = roomTraffic.enqueue(features.packet_count, destination);
    const target = destination === "quarantine" ? "quarantine host" : "protected server";
    const reason = overloaded ? "Offered rate exceeds 10 packets/s. " : "";
    get("burst-route").textContent = `${reason}${number.format(admitted)} queued for the ${target}. ${number.format(features.packet_count - admitted)} dropped at the gateway.`;
  });
  if (!get("simulation-storage").hidden) {
    latestBurst = { id: crypto.randomUUID(), destination, measurements: features };
    get("simulation-s3-link").hidden = true;
    get("simulation-json").hidden = true;
    get("simulation-save-status").textContent = "";
    syncSaveButton();
  }
  checking = true;
  for (const control of form.elements) control.disabled = true;
  get("form-error").hidden = true;
  get("result-message").textContent = "Checking flow…";
  renderResults();
  try {
    const { results } = await request("/api/flow-check", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(features),
    });
    const simulated = Object.values(results).some(result => result.rationale);
    get("result-message").textContent = simulated
      ? "Three model-inspired assessments of the simulated burst."
      : (preview ? "Recorded predictions for the example flow." : "Flow check complete.");
    renderResults(results);
  } catch (error) {
    get("result-message").textContent = "Flow check unavailable.";
    get("form-error").textContent = error instanceof SyntaxError || error instanceof TypeError
      ? "Could not reach the local backend."
      : error.message;
    get("form-error").hidden = false;
  } finally {
    checking = false;
    for (const control of form.elements) control.disabled = false;
    get("submit-check").disabled = !canCheck();
  }
});

get("refresh").addEventListener("click", refresh);
get("audit-demo").addEventListener("click", () => {
  simulatedAudit = simulatedAudit ? undefined : createAuditDemo();
  selectedBucket = -1;
  renderOverviewAudit(overviewData, overviewError);
});
incidentFilter.addEventListener("change", () => renderIncidents(overviewData, overviewError));
document.querySelector(".skip-link").addEventListener("click", (event) => {
  event.preventDefault();
  get("content").focus();
});
window.addEventListener("hashchange", changePage);
window.addEventListener("DOMContentLoaded", () => {
  const services = get("lab-services");
  if (services.dataset.initialized) return;
  for (const card of services.children) {
    card.dataset.state = "unavailable";
    card.querySelector("span").textContent = "Unavailable";
  }
  const message = get("capture-message");
  message.dataset.state = "error";
  message.textContent = "The Live lab script could not load. Restart the console backend and reload this page.";
});
document.addEventListener("visibilitychange", () => {
  syncRoomClock();
  scheduleOverview(0);
});
changePage();
refreshHealth();
refresh();
