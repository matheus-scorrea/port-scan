const form = document.querySelector("#scan-form");
const hostInput = document.querySelector("#host");
const extraInput = document.querySelector("#extra");
const extraWrap = document.querySelector("#extra-wrap");
const timeoutInput = document.querySelector("#timeout");
const submitButton = document.querySelector("#submit");
const stopButton = document.querySelector("#stop");
const statusNode = document.querySelector("#status");
const resultsNode = document.querySelector("#results");

let pollTimer = null;
let currentId = null;

form.addEventListener("change", updateMode);
form.addEventListener("submit", startScan);
stopButton.addEventListener("click", stopScan);
updateMode();

function selectedMode() {
  return form.querySelector("input[name=mode]:checked").value;
}

function updateMode() {
  const mode = selectedMode();
  const showExtra = mode !== "all";
  extraWrap.classList.toggle("hidden", !showExtra);
  extraInput.required = mode === "custom";
}

async function startScan(event) {
  event.preventDefault();
  clearPoll();
  setBusy(true, "");
  resultsNode.replaceChildren();

  try {
    const response = await fetch("/api/scan", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        host: hostInput.value.trim(),
        mode: selectedMode(),
        extra_ports: extraInput.value.trim(),
        timeout: Number(timeoutInput.value),
      }),
    });
    const data = await response.json();
    if (response.status === 409 && data.id) {
      currentId = data.id;
      setBusy(true, "Mapeamento em andamento.");
      schedulePoll();
      return;
    }
    if (!response.ok) {
      setBusy(false, data.error || "Falha ao mapear.", true);
      return;
    }
    currentId = data.id;
    render(data);
    schedulePoll();
  } catch {
    setBusy(false, "Sem resposta do app.", true);
  }
}

async function poll() {
  if (!currentId) return;
  try {
    const response = await fetch(`/api/scan/${currentId}`);
    const data = await response.json();
    if (!response.ok) {
      setBusy(false, data.error || "Falha ao acompanhar.", true);
      return;
    }
    render(data);
    if (data.status === "running") {
      schedulePoll();
      return;
    }
    clearPoll();
    setBusy(false, finishMessage(data), data.status === "error");
  } catch {
    schedulePoll();
  }
}

async function stopScan() {
  if (!currentId) return;
  stopButton.disabled = true;
  await fetch(`/api/scan/${currentId}/cancel`, { method: "POST" });
  poll();
}

function schedulePoll() {
  clearPoll();
  pollTimer = setTimeout(poll, 400);
}

function clearPoll() {
  if (pollTimer) clearTimeout(pollTimer);
  pollTimer = null;
}

function setBusy(busy, message, isError = false) {
  submitButton.disabled = busy;
  submitButton.textContent = busy ? "Mapeando…" : "Mapear";
  stopButton.hidden = !busy;
  stopButton.disabled = !busy;
  statusNode.textContent = message || "";
  statusNode.classList.toggle("error", Boolean(isError));
}

function finishMessage(data) {
  if (data.status === "error") return data.error || "O mapeamento parou.";
  if (data.status === "cancelled") return "Interrompido.";
  return "";
}

function render(data) {
  resultsNode.replaceChildren();
  if (data.status === "running") resultsNode.append(renderProgress(data));
  if (!data.tested && data.status === "running") return;

  const detail = document.createElement("p");
  detail.className = "meta-line";
  detail.textContent = summaryDetail(data);
  resultsNode.append(detail);

  for (const item of data.interfaces) resultsNode.append(renderHit(item));
  const others = data.open_ports.filter((item) => !item.web);
  if (others.length) resultsNode.append(renderTable(others));
  else if (!data.open_ports.length && data.status !== "running") {
    const empty = document.createElement("p");
    empty.className = "quiet";
    empty.textContent = "Nenhuma porta aberta.";
    resultsNode.append(empty);
  }
}

function summaryDetail(data) {
  const seconds = (data.elapsed_ms / 1000).toFixed(1).replace(".", ",");
  const open = data.open_ports.length === 1 ? "1 aberta" : `${formatInt(data.open_ports.length)} abertas`;
  const where = data.address && data.address !== data.host ? `${data.host} (${data.address})` : data.host;
  return `${where} · ${formatInt(data.tested)}/${formatInt(data.total)} · ${open} · ${seconds} s`;
}

function renderProgress(data) {
  const block = document.createElement("div");
  block.className = "progress-block";
  const track = document.createElement("div");
  track.className = "progress";
  track.setAttribute("aria-hidden", "true");
  const bar = document.createElement("span");
  const percent = data.total ? Math.min(100, (data.tested / data.total) * 100) : 0;
  bar.style.width = `${data.phase === "web" ? 100 : percent}%`;
  track.append(bar);
  const text = document.createElement("p");
  const open = formatInt(data.open_ports.length);
  text.textContent = data.phase === "web"
    ? `${open} abertas`
    : `${formatInt(data.tested)}/${formatInt(data.total)} · ${open} abertas${formatRemaining(data.remaining_ms)}`;
  block.append(track, text);
  return block;
}

function renderTable(ports) {
  const wrap = document.createElement("div");
  wrap.className = "quiet table-wrap";
  const table = document.createElement("table");
  const head = document.createElement("tr");
  for (const label of ["Porta", "Resposta"]) {
    const cell = document.createElement("th");
    cell.textContent = label;
    head.append(cell);
  }
  table.append(head);
  for (const item of ports) {
    const row = document.createElement("tr");
    const port = document.createElement("td");
    port.textContent = String(item.port);
    const about = document.createElement("td");
    about.textContent = describe(item);
    if (item.web) row.className = "web";
    row.append(port, about);
    table.append(row);
  }
  wrap.append(table);
  return wrap;
}

function describe(item) {
  if (item.web) {
    const scheme = (item.scheme || "http").toUpperCase();
    const bits = [item.status ? `${scheme} ${item.status}` : scheme];
    if (item.title) bits.push(item.title);
    if (item.login) bits.push("login");
    return bits.join(" · ");
  }
  return item.detail || "aberta";
}

function renderHit(item) {
  const card = document.createElement("article");
  card.className = "hit";
  const top = document.createElement("div");
  top.className = "hit-top";
  const port = document.createElement("strong");
  port.className = "port";
  port.textContent = String(item.port);
  top.append(port, badge((item.scheme || "WEB").toUpperCase()));
  if (item.status) top.append(badge(`HTTP ${item.status}`));
  if (item.login) {
    const login = badge("Login");
    login.classList.add("warn");
    top.append(login);
  }
  card.append(top);

  if (item.title) {
    const title = document.createElement("p");
    title.className = "title";
    title.textContent = item.title;
    card.append(title);
  }

  const bits = [];
  if (item.server) bits.push(`Servidor: ${item.server}`);
  if (item.location) bits.push(`Redireciona para ${item.location}`);
  if (bits.length) {
    const meta = document.createElement("p");
    meta.className = "meta";
    meta.textContent = bits.join(" · ");
    card.append(meta);
  }

  if (item.url) {
    const links = document.createElement("div");
    links.className = "hit-links";
    const open = document.createElement("a");
    open.href = item.url;
    open.target = "_blank";
    open.rel = "noopener noreferrer";
    open.textContent = "Abrir";
    links.append(open);
    card.append(links);
  }
  return card;
}

function badge(text) {
  const node = document.createElement("span");
  node.className = "badge";
  node.textContent = text;
  return node;
}

function formatInt(value) {
  return String(value).replace(/\B(?=(\d{3})+(?!\d))/g, ".");
}

function formatRemaining(ms) {
  if (ms == null) return "";
  const seconds = Math.round(ms / 1000);
  if (seconds < 8) return "";
  if (seconds < 60) return ` · ${seconds} s`;
  const minutes = Math.max(1, Math.round(seconds / 60));
  return ` · ${minutes} min`;
}
