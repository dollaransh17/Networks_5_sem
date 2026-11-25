(() => {
  const packetClock = new Intl.DateTimeFormat(undefined, { hour: "2-digit", minute: "2-digit", second: "2-digit", fractionalSecondDigits: 3, hour12: false });
  const rateNumber = new Intl.NumberFormat(undefined, { maximumFractionDigits: 2 });
  const get = (id) => document.getElementById(id);
  const number = new Intl.NumberFormat();
  const preview = Boolean(globalThis.sdnConsolePreview);
  let labData;
  let captureData;
  let paused = false;
  let verifying = false;

  function element(tag, value, className) {
    const node = document.createElement(tag);
    node.textContent = value;
    if (className) node.className = className;
    return node;
  }

  function renderLab(status, stale = false) {
    for (const card of get("lab-services").children) {
      const check = status?.[card.dataset.service];
      const state = check?.state ?? "unavailable";
      card.dataset.state = stale && check?.checked_at != null ? "stale" : state;
      const label = { observed: "Observed", pending: "Unverified", unavailable: "Unavailable" }[state];
      card.querySelector("span").textContent = card.dataset.state === "stale" ? "Stale" : (
        state === "pending" && check.checked_at == null ? "Checking" : label
      );
      card.querySelector("p").textContent = check?.detail ?? (preview
        ? "Service checks are available in the connected lab console."
        : "Could not read service status from this backend.");
    }
    const checkedAt = status?.ryu?.checked_at;
    const time = get("lab-checked-at");
    time.hidden = checkedAt == null;
    if (checkedAt != null) {
      const checked = new Date(checkedAt * 1000);
      time.dateTime = checked.toISOString();
      time.textContent = `${stale ? "Last service check" : "Services checked"} ${checked.toLocaleTimeString()}`;
    }
  }

  function syncVerification() {
    const intervals = captureData?.intervals.slice(-10);
    get("capture-ai-check").disabled = verifying || captureData?.state !== "live" ||
      captureData.ai_verification !== true || !intervals?.some(interval => interval.packets > 0);
  }

  get("capture-ai-check").addEventListener("click", async () => {
    const status = get("capture-ai-status");
    const requestedAt = new Date();
    verifying = true;
    syncVerification();
    get("capture-ai-result").hidden = true;
    status.textContent = "Checking the latest capture…";
    try {
      const response = await fetch("/api/verify-capture", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: "{}",
        signal: AbortSignal.timeout(25000),
      });
      const data = await response.json();
      if (!response.ok) throw new Error(data.error);
      const { packet_count, byte_count, window_seconds, packets_per_second } = data.measurements;
      get("capture-ai-measurements").textContent =
        `${number.format(packet_count)} packets · ${number.format(byte_count)} bytes · ${rateNumber.format(window_seconds)} s · ${rateNumber.format(packets_per_second)} pkt/s`;
      get("capture-ai-summary").replaceChildren(...data.summary.split(/\r?\n/).filter(Boolean)
        .map(line => element("p", line)));
      get("capture-ai-result").hidden = false;
      status.textContent = `Snapshot requested at ${packetClock.format(requestedAt)}.`;
    } catch (error) {
      status.textContent = error.message || "Could not verify the capture.";
    } finally {
      verifying = false;
      syncVerification();
    }
  });

  function renderCapture() {
    syncVerification();
    const live = get("capture-ai-live");
    const recent = captureData?.intervals.slice(-10) ?? [];
    if (recent.length) {
      const packets = recent.reduce((total, interval) => total + interval.packets, 0);
      const duration = recent.reduce((total, interval) => total + interval.elapsed, 0);
      const label = captureData.state === "live" ? "Live window" : "Last displayed window";
      live.textContent = `${label} · ${number.format(packets)} packets · ${rateNumber.format(duration)} s · ${rateNumber.format(packets / duration)} pkt/s · through ${packetClock.format(new Date(recent.at(-1).at * 1000))}`;
    } else {
      live.textContent = "Waiting for capture intervals.";
    }
    const { state, interface: link, intervals, rows } = captureData ?? { state: "error", intervals: [], rows: [] };
    const status = {
      disabled: "Start the console with the Linux lab collector to view packet headers and rates.",
      waiting: "Waiting for the collector’s first report.",
      live: "Receiving live capture reports.",
      stale: "Collector reports have paused. Showing the last observations.",
      stopped: "Collector disconnected. Showing any retained observations.",
      error: "Could not read the capture feed from this backend.",
      upgrade: "Restart the console backend to load the new lab and capture endpoints.",
      preview: "The standalone preview has no live packet source.",
      paused: "Display paused. The collector continues to receive packets.",
      resuming: "Refreshing the packet display…",
    }[state];
    const message = get("capture-message");
    if (message.textContent !== status) message.textContent = status;
    message.dataset.state = state;
    window.dispatchEvent(new CustomEvent("lab-capture-update", { detail: { snapshot: captureData, message: status } }));
    get("capture-path").dataset.livePort = state === "live" ? link ?? "" : "";
    get("capture-interface").hidden = !link;
    get("capture-interface").textContent = link ?? "";
    get("capture-content").hidden = !intervals.length;
    get("capture-pause").hidden = !intervals.length;
    get("overview-capture-status").textContent = status;
    get("overview-capture-figure").hidden = !intervals.length;
    if (!intervals.length) return;
    get("overview-capture-range").textContent =
      `${link} · packets/s · ${packetClock.format(intervals[0].at * 1000)} – ${packetClock.format(intervals.at(-1).at * 1000)}`;

    const latest = intervals.at(-1);
    get("capture-rate").textContent = rateNumber.format(latest.packets / latest.elapsed);
    get("capture-throughput").textContent = rateNumber.format(latest.bytes * 8 / latest.elapsed / 1e6);
    const hasDrops = intervals.every((interval) => interval.kernel_dropped != null);
    get("capture-drops").textContent = hasDrops ? number.format(intervals.reduce((sum, interval) => sum + interval.kernel_dropped, 0)) : "—";
    const omitted = intervals.reduce((sum, interval) => sum + interval.headers_omitted, 0);
    get("capture-omitted").textContent = omitted ? `${number.format(omitted)} headers omitted in the chart window` : "";
    get("capture-range").textContent = `${packetClock.format(intervals[0].at * 1000)} – ${packetClock.format(latest.at * 1000)}`;
    function endpoint(address, port) {
      if (port == null) return address;
      return address.includes(":") ? `[${address}]:${port}` : `${address}:${port}`;
    }
    get("capture-rows").replaceChildren(...rows.map((packet) => {
      const row = element("tr", "");
      row.append(
        element("td", packetClock.format(packet.at * 1000), "mono"),
        element("td", endpoint(packet.source, packet.source_port), "mono"),
        element("td", endpoint(packet.destination, packet.destination_port), "mono"),
        element("td", packet.protocol),
        element("td", number.format(packet.bytes), "mono"),
      );
      return row;
    }));
    get("capture-empty").hidden = rows.length > 0;
    get("capture-table").hidden = !rows.length;
    drawCapture();
  }

  function drawCapture() {
    drawCaptureChart(get("capture-chart"));
    drawCaptureChart(get("overview-capture-chart"));
  }

  function drawCaptureChart(canvas) {
    const intervals = captureData?.intervals;
    const { clientWidth: width, clientHeight: height } = canvas;
    if (!intervals?.length || !width || !height) return;
    const ctx = canvas.getContext("2d");
    if (!ctx) return;
    const scale = Math.min(window.devicePixelRatio || 1, 2);
    canvas.width = Math.round(width * scale);
    canvas.height = Math.round(height * scale);
    ctx.scale(scale, scale);

    const rates = intervals.map(({ packets, elapsed }) => packets / elapsed);
    const top = Math.max(1, Math.ceil(Math.max(...rates)));
    const first = intervals[0].offset_s - intervals[0].elapsed;
    const span = intervals.at(-1).offset_s - first;
    const left = 64;
    const bottom = height - 12;
    const x = (at) => left + (at - first) / span * (width - left - 12);
    const y = (rate) => bottom - rate / top * (bottom - 12);
    const style = getComputedStyle(canvas);
    ctx.font = "12px ui-monospace, monospace";
    ctx.fillStyle = style.getPropertyValue("--secondary").trim();
    ctx.strokeStyle = style.getPropertyValue("--rule").trim();
    ctx.textAlign = "right";
    ctx.textBaseline = "middle";
    for (const level of [0, top / 2, top]) {
      ctx.beginPath();
      ctx.moveTo(left, y(level));
      ctx.lineTo(width - 12, y(level));
      ctx.stroke();
      ctx.fillText(rateNumber.format(level), left - 8, y(level));
    }
    ctx.strokeStyle = style.getPropertyValue("--primary").trim();
    ctx.lineWidth = 2.5;
    ctx.beginPath();
    for (const [index, interval] of intervals.entries()) {
      const start = x(interval.offset_s - interval.elapsed);
      const end = x(interval.offset_s);
      const level = y(rates[index]);
      if (index > 0 && !interval.gap) ctx.lineTo(start, level);
      else ctx.moveTo(start, level);
      ctx.lineTo(end, level);
    }
    ctx.stroke();
  }

  function poll(path, interval, accepts, onData, onError) {
    let timer;
    let pending;

    async function refresh() {
      timer = undefined;
      const controller = new AbortController();
      pending = controller;
      const deadline = setTimeout(() => controller.abort(), 4300);
      try {
        const response = await fetch(path, { signal: controller.signal });
        if (!response.ok) throw Object.assign(new Error("Request failed"), { status: response.status });
        const data = await response.json();
        if (pending === controller) onData(data);
      } catch (error) {
        if (pending === controller) onError(error);
      } finally {
        clearTimeout(deadline);
        if (pending === controller) {
          pending = undefined;
          if (accepts()) timer = setTimeout(refresh, interval);
        }
      }
    }

    return () => {
      if (accepts()) {
        if (timer === undefined && !pending) timer = setTimeout(refresh, 0);
      } else {
        clearTimeout(timer);
        timer = undefined;
        const controller = pending;
        pending = undefined;
        controller?.abort();
      }
    };
  }

  function setCapture(data) {
    captureData = data;
    renderCapture();
    const status = get("capture-ai-status");
    if (!verifying && status.textContent.startsWith("Waiting") && !get("capture-ai-check").disabled) {
      status.textContent = "Ready to verify the latest capture.";
    }
  }

  const visible = () => !preview && location.hash === "#live-lab" && !document.hidden;
  const overviewVisible = () => !preview && !document.hidden && !get("overview-page").hidden;
  const captureVisible = () => visible() || overviewVisible();
  const syncLab = poll("/api/lab", 5000, visible, (status) => {
    labData = status;
    renderLab(labData);
  }, () => renderLab(labData?.ryu?.checked_at != null ? labData : undefined, true));
  const syncCapture = poll("/api/packets", 1000, () => overviewVisible() || (visible() && !paused), setCapture, (error) => {
    const retained = captureData?.intervals.length;
    setCapture(retained ? { ...captureData, state: "stale" }
      : { state: error.status === 404 ? "upgrade" : "error", intervals: [], rows: [] });
  });

  function updateVisibility() {
    if (captureData?.state === "live" && !captureVisible()) {
      setCapture({ ...captureData, state: "stale" });
    }
    if (paused && visible() && captureData?.state === "live") {
      setCapture({ ...captureData, state: "paused" });
    }
    syncLab();
    syncCapture();
  }

  get("capture-pause").addEventListener("click", () => {
    paused = !paused;
    get("capture-pause").textContent = paused ? "Resume display" : "Pause display";
    setCapture({ ...captureData, state: paused ? "paused" : "resuming" });
    syncCapture();
  });
  window.addEventListener("hashchange", updateVisibility);
  document.addEventListener("visibilitychange", updateVisibility);
  const captureResize = new ResizeObserver(drawCapture);
  captureResize.observe(get("capture-chart"));
  captureResize.observe(get("overview-capture-chart"));
  matchMedia("(prefers-color-scheme: dark)").addEventListener("change", drawCapture);
  if (preview) {
    renderLab();
    setCapture({ state: "preview", intervals: [], rows: [] });
  }
  updateVisibility();
  get("lab-services").dataset.initialized = "true";
})();
