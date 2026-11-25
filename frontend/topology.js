(() => {
  const nodes = [
    ["Client", "The lab client originates traffic. The gateway is its first hop."],
    ["Gateway", "The gateway applies access rules before permitted traffic reaches the inspection layer."],
    ["Suricata", "The inspection layer evaluates traffic and writes EVE alerts for the listener."],
    ["Open vSwitch", "The OpenFlow 1.3 switch forwards traffic. Ryu polls its counters for behavioral analysis."],
    ["Protected server", "The protected host receives traffic forwarded by Open vSwitch through the virtual interface s1-eth2."],
  ];
  const stage = document.getElementById("topology-stage");
  const mode = document.getElementById("topology-mode");
  const diagramNodes = Array.from(stage.querySelectorAll(".topology-diagram i"));
  const buttons = Array.from(document.querySelectorAll("[data-node]"));
  const title = document.getElementById("node-title");
  const description = document.getElementById("node-description");
  const pathDetail = [title.textContent, description.textContent];
  const motion = matchMedia("(prefers-reduced-motion: reduce)");
  const xPositions = [-8, -4, 0, 4, 8];
  const deviceColors = [[73, 115, 163], [155, 105, 58], [123, 85, 156], [52, 126, 117], [88, 127, 65]];
  const devices = xPositions.map((_, index) => deviceParts(index));
  let angle = -.22;
  let elevation = .46;
  let active = -1;
  let drag;
  let draw = drawDiagram;
  let pick = pickDiagram;
  let localScene;

  function deviceParts(index) {
    const parts = [];
    function box(width, height, depth, x, y, z, tone = "body", yaw = 0) {
      parts.push({ width, height, depth, x, y, z, tone, yaw });
    }
    box(2.68, .18, 2.4, 0, .1, 0, "platform");
    box(2.46, .06, 2.18, 0, .21, 0, "panel");
    box(1.72, .045, .025, 0, .22, 1.21, "accent");
    if (index === 0) {
      box(1.72, 1.08, .28, 0, 1.12, 0);
      box(1.51, .86, .035, 0, 1.14, .15, "panel");
      box(.82, .05, .03, -.22, 1.34, .178, "accent");
      box(.57, .05, .03, -.345, 1.16, .178, "accent");
      box(.33, .05, .03, -.465, .98, .178, "accent");
      box(.24, .46, .24, 0, .43, 0);
      box(.85, .07, .61, 0, .28, 0);
      box(1.22, .07, .38, 0, .28, .75);
    } else if (index === 1 || index === 3) {
      const layers = index === 1 ? 2 : 1;
      for (let level = 0; level < layers; level++) {
        const y = .54 + level * .48;
        box(2.06, .39, 1.2, 0, y, 0);
        box(1.88, .26, .035, 0, y, .61, "panel");
        for (let port = 0; port < 7; port++) {
          box(.13, .088, .035, -.71 + port * .208, y, .64, "accent");
        }
        box(.07, .08, .035, .8, y, .64, "accent");
      }
    } else {
      const sensor = index === 2;
      box(1.42, sensor ? 1.43 : 1.94, 1.18, 0, sensor ? .97 : 1.23, 0);
      const bays = sensor ? 3 : 5;
      for (let slot = 0; slot < bays; slot++) {
        const y = .48 + slot * .31;
        box(1.24, .225, .045, 0, y, .61, "panel");
        box(.065, .065, .03, .46, y, .65, "accent");
        for (let vent = 0; vent < 6; vent++) {
          box(.034, .095, .025, -.45 + vent * .115, y, .65, "accent");
        }
      }
    }
    return parts;
  }

  function drawDiagram() {
    stage.style.setProperty("--diagram-orbit", `${Math.sin(angle) * 41}deg`);
    stage.style.setProperty("--diagram-elevation", `${elevation * 56}deg`);
  }

  function pickDiagram(event) {
    return diagramNodes.indexOf(document.elementFromPoint(event.clientX, event.clientY));
  }

  function selectNode(index) {
    active = active === index ? -1 : index;
    const [name, detail] = nodes[active] ?? pathDetail;
    title.textContent = name;
    description.textContent = detail;
    buttons.forEach((item, slot) => item.setAttribute("aria-pressed", String(slot === active)));
    stage.dataset.active = active;
    draw();
  }

  document.getElementById("topology-rotate").addEventListener("click", () => {
    angle += Math.PI / 8;
    draw();
  });
  document.getElementById("topology-reset").addEventListener("click", () => {
    angle = -.22;
    elevation = .46;
    draw();
  });
  stage.addEventListener("pointerdown", (event) => {
    if (event.button !== 0 || drag) return;
    stage.setPointerCapture(event.pointerId);
    drag = { id: event.pointerId, x: event.clientX, y: event.clientY, moved: false };
  });
  stage.addEventListener("pointermove", (event) => {
    if (drag?.id !== event.pointerId) return;
    const dx = event.clientX - drag.x;
    const dy = event.clientY - drag.y;
    if (!drag.moved && Math.hypot(dx, dy) < 5) return;
    angle -= dx * .012;
    elevation = Math.min(.98, Math.max(.1, elevation + dy * .008));
    drag = { id: event.pointerId, x: event.clientX, y: event.clientY, moved: true };
    draw();
  });
  stage.addEventListener("pointerup", (event) => {
    if (drag?.id !== event.pointerId || drag.moved) return;
    const index = pick(event);
    if (index >= 0) selectNode(index);
  });
  stage.addEventListener("lostpointercapture", (event) => {
    if (drag?.id === event.pointerId) drag = null;
  });
  drawDiagram();

  for (const [index, button] of buttons.entries()) {
    button.addEventListener("click", () => selectNode(index));
  }

  const library = location.protocol === "file:"
    ? "https://cdn.jsdelivr.net/npm/three@0.180.0/build/three.module.min.js"
    : "./vendor/three/three.module.min.js";

  showLocalScene();
  import(library).then(mount).catch(showLocalScene);

  function showLocalScene() {
    localScene ??= mountCanvas();
    if (localScene) localScene.show();
    else {
      draw = drawDiagram;
      pick = pickDiagram;
      stage.classList.remove("has-3d");
      mode.textContent = "Diagram view";
      draw();
    }
  }

  function mountCanvas() {
    const canvas = document.createElement("canvas");
    const ctx = canvas.getContext("2d");
    if (!ctx) return null;
    canvas.setAttribute("aria-hidden", "true");
    stage.append(canvas);

    const faces = [
      [[0, 3, 2, 1], .62], [[4, 5, 6, 7], .94], [[3, 7, 6, 2], 1.25],
      [[0, 1, 5, 4], .55], [[1, 2, 6, 5], .72], [[0, 4, 7, 3], .82],
    ];
    const solids = devices.flatMap((parts, index) => parts.map((part) => {
      const { width, height, depth, x, y, z, tone, yaw } = part;
      const corners = [
        [-1, -1, -1], [1, -1, -1], [1, 1, -1], [-1, 1, -1],
        [-1, -1, 1], [1, -1, 1], [1, 1, 1], [-1, 1, 1],
      ].map(([i, j, k]) => {
        const side = i * width / 2;
        const front = k * depth / 2;
        return [xPositions[index] + x + side * Math.cos(yaw) + front * Math.sin(yaw),
          y + j * height / 2, z - side * Math.sin(yaw) + front * Math.cos(yaw)];
      });
      return { index, tone, corners };
    }));

    let surfaces = [];
    let shown = false;
    let visible = true;
    let frame = 0;

    function trace(points) {
      ctx.beginPath();
      ctx.moveTo(points[0][0], points[0][1]);
      for (const point of points.slice(1)) ctx.lineTo(point[0], point[1]);
    }

    function render(timestamp = performance.now()) {
      const { clientWidth: width, clientHeight: height } = stage;
      if (!width || !height) return;
      const ratio = Math.min(devicePixelRatio || 1, 2);
      const pixels = [Math.round(width * ratio), Math.round(height * ratio)];
      if (canvas.width !== pixels[0]) canvas.width = pixels[0];
      if (canvas.height !== pixels[1]) canvas.height = pixels[1];
      ctx.setTransform(ratio, 0, 0, ratio, 0, 0);
      ctx.clearRect(0, 0, width, height);

      const orbitCos = Math.cos(angle);
      const orbitSin = Math.sin(angle);
      const tiltSin = Math.sin(elevation);
      const tiltCos = Math.cos(elevation);
      const verticalSpan = 4.2 + Math.abs(orbitSin) * tiltSin * 16;
      const scale = Math.min(width / 22, height / verticalSpan);
      function project([x, y, z]) {
        const alongView = x * orbitSin + z * orbitCos;
        const above = y - .45;
        return [width / 2 + (x * orbitCos - z * orbitSin) * scale,
          height * .52 - (above * tiltCos - alongView * tiltSin) * scale,
          above * tiltSin + alongView * tiltCos];
      }

      ctx.lineWidth = 1;
      ctx.strokeStyle = "rgba(185,161,134,.13)";
      ctx.beginPath();
      for (let n = -15; n <= 15; n++) {
        const near = project([n, -.06, -15]);
        const far = project([n, -.06, 15]);
        const left = project([-15, -.06, n]);
        const right = project([15, -.06, n]);
        ctx.moveTo(near[0], near[1]);
        ctx.lineTo(far[0], far[1]);
        ctx.moveTo(left[0], left[1]);
        ctx.lineTo(right[0], right[1]);
      }
      ctx.stroke();
      ctx.strokeStyle = "rgba(255,170,93,.63)";
      ctx.lineWidth = 1.5;
      trace([project([-8, .28, 0]), project([8, .28, 0])]);
      ctx.stroke();

      surfaces = [];
      for (const { index, tone, corners } of solids) {
        const projected = corners.map(project);
        for (const [indices, shade] of faces) {
          const points = indices.map((vertex) => projected[vertex]);
          const [a, b, c] = points;
          if ((b[0] - a[0]) * (c[1] - a[1]) >= (b[1] - a[1]) * (c[0] - a[0])) continue;
          const depth = points.reduce((total, point) => total + point[2], 0) / points.length;
          surfaces.push({ points, depth, index, tone, shade });
        }
      }
      for (let index = 0; index < 4; index++) {
        const progress = ((motion.matches ? 0 : timestamp) / 2100 + index) % 4;
        const point = project([-8 + progress * 4, .34, 0]);
        surfaces.push({ points: [point], depth: point[2], tone: "packet" });
      }

      for (const { points, tone, shade, index } of surfaces.sort((a, b) => a.depth - b.depth)) {
        if (tone === "packet") {
          ctx.beginPath();
          ctx.fillStyle = "#ffaa5d";
          ctx.arc(points[0][0], points[0][1], Math.max(1.5, scale * .11), 0, Math.PI * 2);
          ctx.fill();
          continue;
        }
        trace(points);
        ctx.closePath();
        if (tone === "accent") ctx.fillStyle = "#b6ded8";
        else if (tone === "panel") ctx.fillStyle = "#151b20";
        else {
          const color = tone === "platform" && active === index ? [208, 136, 71] : deviceColors[index];
          ctx.fillStyle = `rgb(${color.map((value) => Math.round(value * shade)).join(",")})`;
        }
        ctx.fill();
        if (tone === "platform" || tone === "body") {
          ctx.strokeStyle = "rgba(235,226,210,.37)";
          ctx.lineWidth = .8;
          ctx.stroke();
        }
      }
    }

    function pickCanvas(event) {
      const { left, top } = canvas.getBoundingClientRect();
      const x = event.clientX - left;
      const y = event.clientY - top;
      for (let face = surfaces.length - 1; face >= 0; face--) {
        const { points, index } = surfaces[face];
        if (index == null) continue;
        // Visible box faces have consistent winding in screen space.
        const inside = points.every(([ax, ay], vertex) => {
          const [bx, by] = points[(vertex + 1) % points.length];
          return (bx - ax) * (y - ay) <= (by - ay) * (x - ax);
        });
        if (inside) return index;
      }
      return -1;
    }

    function refresh() {
      if (!shown || !visible || document.hidden) {
        if (frame) cancelAnimationFrame(frame);
        frame = 0;
        return;
      }
      render();
      if (!frame && !motion.matches) frame = requestAnimationFrame(animate);
    }

    function animate(timestamp) {
      frame = 0;
      render(timestamp);
      if (shown && visible && !document.hidden && !motion.matches) frame = requestAnimationFrame(animate);
    }

    new ResizeObserver(refresh).observe(stage);
    new IntersectionObserver(([entry]) => {
      visible = entry.isIntersecting;
      refresh();
    }).observe(stage);
    motion.addEventListener("change", refresh);
    document.addEventListener("visibilitychange", refresh);
    return {
      show() {
        shown = true;
        canvas.hidden = false;
        draw = render;
        pick = pickCanvas;
        stage.classList.add("has-3d");
        mode.textContent = "3D view";
        refresh();
      },
      hide() {
        shown = false;
        canvas.hidden = true;
        refresh();
      },
    };
  }

  function mount(THREE) {
    const renderer = new THREE.WebGLRenderer({ alpha: true, antialias: true });
    const scene = new THREE.Scene();
    const camera = new THREE.OrthographicCamera();
    const raycaster = new THREE.Raycaster();
    const pointer = new THREE.Vector2();
    const accent = 0x8db7f0;
    const material = new THREE.MeshStandardMaterial({
      color: 0x1f4e8c, metalness: .32, roughness: .42, emissive: 0x1f4e8c, emissiveIntensity: .16,
    });
    const pale = new THREE.MeshBasicMaterial({ color: 0xb6ded8 });
    const inset = new THREE.MeshBasicMaterial({ color: 0x151b20 });
    const edgeMaterial = new THREE.LineBasicMaterial({ color: 0xeee2d2, transparent: true, opacity: .34 });

    renderer.setPixelRatio(Math.min(devicePixelRatio || 1, 2));
    renderer.domElement.setAttribute("aria-hidden", "true");
    scene.add(new THREE.HemisphereLight(0xe8ecf2, 0x1a2029, 2.5));
    const light = new THREE.DirectionalLight(accent, 2.5);
    light.position.set(3, 9, 5);
    scene.add(light);

    function box(parent, { width, height, depth, x, y, z, tone, yaw }, body) {
      const geometry = new THREE.BoxGeometry(width, height, depth);
      const fill = tone === "platform" ? body.clone() : tone === "accent" ? pale : tone === "panel" ? inset : body;
      const mesh = new THREE.Mesh(geometry, fill);
      mesh.position.set(x, y, z);
      mesh.rotation.y = yaw;
      if (tone === "body" || tone === "platform") mesh.add(new THREE.LineSegments(new THREE.EdgesGeometry(geometry), edgeMaterial));
      parent.add(mesh);
      return mesh;
    }

    const platforms = xPositions.map((x, index) => {
      const device = new THREE.Group();
      device.position.x = x;
      scene.add(device);
      const body = material.clone();
      body.color.setRGB(...deviceColors[index].map((channel) => channel / 255), THREE.SRGBColorSpace);
      body.emissive.copy(body.color);
      const [base] = devices[index].map((part) => box(device, part, body));
      return base;
    });

    const groups = platforms.map((platform) => platform.parent);
    function pickDevice(event) {
      const bounds = stage.getBoundingClientRect();
      pointer.set((event.clientX - bounds.left) / bounds.width * 2 - 1, 1 - (event.clientY - bounds.top) / bounds.height * 2);
      raycaster.setFromCamera(pointer, camera);
      const hit = raycaster.intersectObjects(groups, true).find(({ object }) => object.isMesh);
      return hit ? groups.indexOf(hit.object.parent) : -1;
    }

    const grid = new THREE.GridHelper(30, 30, 0x5d4939, 0x302721);
    grid.position.y = -.06;
    scene.add(grid);
    const points = xPositions.map((x) => new THREE.Vector3(x, .28, 0));
    const pathMaterial = new THREE.LineBasicMaterial({ color: 0xffaa5d, transparent: true, opacity: .65 });
    const line = new THREE.Line(new THREE.BufferGeometry().setFromPoints(points), pathMaterial);
    scene.add(line);
    const packetMaterial = new THREE.MeshBasicMaterial({ color: 0xffaa5d });
    const packets = Array.from({ length: 4 }, () => {
      const dot = new THREE.Mesh(new THREE.SphereGeometry(.11, 10, 10), packetMaterial);
      dot.position.y = .34;
      scene.add(dot);
      return dot;
    });

    let visible = true;
    let contextLost = false;
    let requestId = 0;
    function renderScene(timestamp = performance.now()) {
      if (!stage.clientWidth || !stage.clientHeight) return;
      const radius = 28;
      camera.position.set(Math.sin(angle) * radius, Math.sin(elevation) * radius, Math.cos(angle) * radius);
      camera.lookAt(0, .45, 0);
      platforms.forEach((base, index) => {
        base.material.emissiveIntensity = active === index ? 1.45 : .16;
      });
      packets.forEach((packet, index) => {
        const progress = ((motion.matches ? 0 : timestamp) / 2100 + index) % 4;
        packet.position.x = -8 + progress * 4;
      });
      renderer.render(scene, camera);
    }
    draw = renderScene;

    function resize() {
      const width = stage.clientWidth;
      const height = stage.clientHeight;
      if (!width || !height) return;
      const halfWidth = 11;
      const halfHeight = halfWidth * height / width;
      Object.assign(camera, { left: -halfWidth, right: halfWidth, top: halfHeight, bottom: -halfHeight, near: .1, far: 80 });
      camera.updateProjectionMatrix();
      renderer.setSize(width, height, false);
      draw();
    }

    function animate(now) {
      requestId = 0;
      if (!contextLost && visible && !motion.matches && !document.hidden) {
        draw(now);
        requestId = requestAnimationFrame(animate);
      }
    }

    function resume() {
      if (!requestId && !contextLost && visible && !motion.matches && !document.hidden) {
        requestId = requestAnimationFrame(animate);
      } else {
        draw();
      }
    }

    localScene?.hide();
    stage.append(renderer.domElement);
    stage.classList.add("has-3d");
    mode.textContent = "3D view";
    pick = pickDevice;
    renderer.domElement.addEventListener("webglcontextlost", (event) => {
      event.preventDefault();
      contextLost = true;
      renderer.domElement.hidden = true;
      showLocalScene();
    });
    renderer.domElement.addEventListener("webglcontextrestored", () => {
      contextLost = false;
      localScene?.hide();
      renderer.domElement.hidden = false;
      draw = renderScene;
      pick = pickDevice;
      stage.classList.add("has-3d");
      mode.textContent = "3D view";
      resume();
    });
    new ResizeObserver(resize).observe(stage);
    new IntersectionObserver(([entry]) => {
      visible = entry.isIntersecting;
      if (visible) resume();
    }).observe(stage);
    motion.addEventListener("change", resume);
    document.addEventListener("visibilitychange", resume);
    resize();
    resume();
  }
})();

// Cable geometry and rack positions use the floor's local 3D space.
function createServerRoom() {
  const world = document.getElementById("room-world");
  const viewport = document.getElementById("room-viewport");
  const inspector = document.getElementById("room-device");
  const target = document.getElementById("room-target");
  const detail = document.getElementById("room-device-detail");
  const devices = [
    { id: "gateway", name: "Gateway", tag: "GW", x: 98, y: 245, w: 86, d: 52, h: 45, bays: 2,
      detail: "The gateway queues incoming packets and sends up to ten per second onto the inspection link." },
    { id: "sensor", name: "Suricata", tag: "IPS", x: 254, y: 210, w: 72, d: 72, h: 89, bays: 5,
      detail: "The sensor sits between the gateway and switch on the inspection path." },
    { id: "switch", name: "Open vSwitch", tag: "S1", x: 426, y: 226, w: 100, d: 62, h: 46, bays: 2,
      detail: "The switch forwards each simulated packet to its assigned server port." },
    { id: "server", name: "Protected server", tag: "SRV", x: 644, y: 120, w: 84, d: 74, h: 140, bays: 8,
      detail: "The protected server connects to port s1-eth2." },
    { id: "quarantine", name: "Quarantine host", tag: "QUAR", x: 653, y: 327, w: 78, d: 64, h: 105, bays: 6,
      detail: "The quarantine host connects to port s1-eth3." },
  ];
  const points = Object.fromEntries(devices.map(node => [node.id, [node.x, node.y]]));
  const trunk = [points.gateway, [164,245], [199,210], points.sensor, [340,210], [356,226], points.switch];
  const branches = {
    server: [points.switch, [499,226], [577,148], [577,133], [590,120], points.server],
    quarantine: [points.switch, [489,226], [534,271], [572,271], [628,327], points.quarantine],
  };

  function add(parent, className, text) {
    const el = document.createElement("div");
    el.className = className;
    if (text) el.textContent = text;
    parent.append(el);
    return el;
  }

  const monitoredCables = [];
  function makeCable(points, destination, port) {
    return points.slice(1).map(([x, y], index) => {
      const [ax, ay] = points[index];
      const length = Math.hypot(x - ax, y - ay);
      const cable = add(world, "room-cable");
      cable.dataset.branch = destination;
      if (port) monitoredCables.push({ cable, port });
      cable.style.width = length + "px";
      cable.style.transform = `translate3d(${ax}px,${ay}px,2px) rotateZ(${Math.atan2(y-ay,x-ax)}rad)`;
      return { x: ax, y: ay, dx: x - ax, dy: y - ay, length };
    });
  }
  const sensorIndex = trunk.indexOf(points.sensor);
  const common = makeCable(trunk.slice(0, sensorIndex + 1), "trunk")
    .concat(makeCable(trunk.slice(sensorIndex), "trunk", "s1-eth1"));
  const paths = Object.fromEntries(Object.entries(branches).map(([id, coords]) => {
    const parts = common.concat(makeCable(coords, id, id === "server" ? "s1-eth2" : "s1-eth3"));
    return [id, { parts, length: parts.reduce((sum, part) => sum + part.length, 0) }];
  }));

  const chassis = new Map();
  for (const node of devices) {
    const rack = add(world, "room-rack");
    chassis.set(node.id, rack);
    rack.dataset.device = node.id;
    rack.style.left = node.x - node.w / 2 + "px";
    rack.style.top = node.y - node.d / 2 + "px";
    for (const key of ["w", "d", "h"]) rack.style.setProperty("--" + key, node[key] + "px");
    add(rack, "rack-pad");
    const front = add(rack, "rack-face rack-front");
    add(front, "rack-nameplate", node.tag);
    const slots = add(front, "rack-slots");
    for (let bay = 0; bay < node.bays; bay++) add(slots, "rack-bay");
    add(rack, "rack-face rack-side rack-right");
    add(rack, "rack-face rack-side rack-left");
    add(rack, "rack-face rack-back");
    add(rack, "rack-face rack-roof");
    const label = add(rack, "rack-floor-label", node.tag);
    label.style.top = node.d + 10 + "px";
    inspector.add(new Option(node.name, node.id));
  }
  const dots = [];
  let yaw = -19;
  let pitch = 54;
  let pointer;
  let travelled = false;
  let lastInterval;
  const motion = matchMedia("(prefers-reduced-motion: reduce)");

  function camera() {
    const width = viewport.clientWidth;
    if (!width) return;
    // Fit the floor and the tallest cabinet throughout the supported orbit.
    const radians = yaw * Math.PI / 180;
    const across = 800 * Math.abs(Math.cos(radians)) + 410 * Math.abs(Math.sin(radians));
    const deep = 800 * Math.abs(Math.sin(radians)) + 410 * Math.abs(Math.cos(radians));
    const tilt = pitch * Math.PI / 180;
    const high = deep * Math.cos(tilt) + 150 * Math.sin(tilt);
    const scale = Math.min((width - 20) / across, (viewport.clientHeight - 26) / high);
    world.style.transform = `translate(-50%, -50%) scale(${scale}) rotateX(${pitch}deg) rotateZ(${yaw}deg)`;
  }

  function inspect(id) {
    inspector.value = id;
    for (const [key, rack] of chassis) rack.classList.toggle("inspected", key === id);
    const device = devices.find(device => device.id === id);
    detail.textContent = device.detail;
  }

  function draw(traffic) {
    if (world.dataset.source === "capture") return;
    const packets = traffic.inFlight;
    const animated = motion.matches ? 0 : packets.length;
    while (dots.length < animated) dots.push(add(world, "room-packet"));
    const activeTargets = new Set();
    for (const packet of packets) activeTargets.add(packet.target);
    for (const id of ["server", "quarantine"]) chassis.get(id).classList.toggle("receiving", activeTargets.has(id));
    for (let i = 0; i < dots.length; i++) {
      const dot = dots[i];
      dot.hidden = i >= animated;
      if (dot.hidden) continue;
      const packet = packets[i];
      if (dot.dataset.target !== packet.target) dot.dataset.target = packet.target;
      const path = paths[packet.target];
      const progress = (traffic.now - packet.start) / (packet.end - packet.start);
      let distance = progress * path.length;
      for (const part of path.parts) {
        if (distance <= part.length) {
          const t = distance / part.length;
          dot.style.transform = `translate3d(${part.x + part.dx * t}px,${part.y + part.dy * t}px,7px)`;
          break;
        }
        distance -= part.length;
      }
    }
  }

  function switchTarget() {
    world.dataset.target = target.value;
    inspect(target.value);
  }
  function setSource(source) {
    world.dataset.source = source;
    lastInterval = undefined;
    if (source === "capture") {
      for (const dot of dots) dot.hidden = true;
      for (const rack of chassis.values()) rack.classList.remove("receiving");
      inspect("switch");
    } else {
      for (const { cable } of monitoredCables) cable.classList.remove("observed");
      switchTarget();
    }
  }
  function showCapture(data) {
    const port = data?.state === "live" ? data.interface : null;
    const interval = data?.intervals?.at(-1);
    const stamp = port && interval ? [port, interval.sequence, interval.at, interval.offset_s].join("/") : null;
    for (const { cable, port: cablePort } of monitoredCables) {
      cable.classList.toggle("observed", cablePort === port);
      // Pulse the observed link once for each new nonempty collector interval.
      if (cablePort === port && stamp && stamp !== lastInterval && interval.packets && !motion.matches) {
        cable.animate([{ filter: "brightness(2)" }, { filter: "brightness(1)" }], 450);
      }
    }
    lastInterval = stamp;
  }
  target.addEventListener("change", switchTarget);
  inspector.addEventListener("change", () => inspect(inspector.value));
  world.addEventListener("click", event => {
    const rack = event.target.closest(".room-rack");
    if (!travelled && rack) {
      inspector.value = rack.dataset.device;
      inspector.dispatchEvent(new Event("change"));
    }
  });
  function orbit(command) {
    if (command === "reset") { yaw = -19; pitch = 54; }
    else yaw += command === "left" ? -18 : 18;
    camera();
  }
  for (const button of viewport.querySelectorAll("[data-camera]")) {
    button.addEventListener("click", () => orbit(button.dataset.camera));
  }
  viewport.addEventListener("pointerdown", event => {
    if (event.button !== 0 || event.target.closest("button") || pointer) return;
    travelled = false;
    pointer = { id: event.pointerId, x: event.clientX, y: event.clientY, yaw, pitch };
  });
  viewport.addEventListener("pointermove", event => {
    if (event.pointerId !== pointer?.id) return;
    const dx = event.clientX - pointer.x;
    const dy = event.clientY - pointer.y;
    if (!travelled && Math.hypot(dx, dy) < 5) return;
    if (!travelled) viewport.setPointerCapture(event.pointerId);
    travelled = true;
    yaw = pointer.yaw + dx * .28;
    pitch = Math.max(28, Math.min(72, pointer.pitch - dy * .25));
    camera();
  });
  function release(event) { if (event.pointerId === pointer?.id) pointer = null; }
  viewport.addEventListener("pointerup", release);
  viewport.addEventListener("pointercancel", release);
  viewport.addEventListener("lostpointercapture", release);
  viewport.addEventListener("pointerleave", event => { if (!travelled) release(event); });
  new ResizeObserver(camera).observe(viewport);
  setSource("simulation");
  camera();
  return { draw, setSource, showCapture };
}
