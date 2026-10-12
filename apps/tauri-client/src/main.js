import { invoke } from "@tauri-apps/api/core";
import { getCurrentWindow } from "@tauri-apps/api/window";
import "./style.css";

const $ = (id) => document.getElementById(id);
const appWindow = getCurrentWindow();
const connectButton = $("connect");
const disconnectButton = $("disconnect");
const routeList = $("route-list");
let settingsSaveTimer;

const statusText = {
  idle: "Offline",
  working: "Working",
  connected: "Online",
  error: "Error",
};

function setStatus(kind, title, detail) {
  document.querySelectorAll("[data-status-dot]").forEach((dot) => {
    dot.className = `${dot.classList.contains("mini-dot") ? "mini-dot" : "status-dot"} ${kind}`;
  });
  $("header-status-text").textContent = statusText[kind] ?? "Offline";
  $("home-status-title").textContent = title;
  $("home-status-detail").textContent = detail;
  $("connection-status-title").textContent = title;
  $("connection-status-detail").textContent = detail;
}

function showPage(pageName) {
  document.querySelectorAll("[data-page]").forEach((button) => {
    const active = button.dataset.page === pageName;
    button.classList.toggle("is-active", active);
    if (active) {
      button.setAttribute("aria-current", "page");
    } else {
      button.removeAttribute("aria-current");
    }
  });

  document.querySelectorAll("[data-view]").forEach((page) => {
    const active = page.dataset.view === pageName;
    page.classList.toggle("is-active", active);
    page.hidden = !active;
  });
}

function renderRoutes() {
  const routes = $("routes").value
    .split(/\r?\n/)
    .map((route) => route.trim())
    .filter(Boolean);

  routeList.replaceChildren();
  if (routes.length === 0) {
    const empty = document.createElement("li");
    empty.className = "empty-state";
    empty.textContent = "No destination networks entered.";
    routeList.append(empty);
    return;
  }

  routes.forEach((route) => {
    const item = document.createElement("li");
    item.className = "route-item";
    item.innerHTML = `<span class="route-icon" aria-hidden="true"><svg viewBox="0 0 24 24"><path d="M5 13L9 17L19 7" /></svg></span><code></code>`;
    item.querySelector("code").textContent = route;
    routeList.append(item);
  });
}

function currentSettings() {
  const port = Number($("port").value);
  return {
    server: $("server").value,
    port: Number.isInteger(port) && port >= 0 && port <= 65535 ? port : 0,
    passphrase: $("passphrase").value,
    routes: $("routes").value,
  };
}

function saveSettingsSoon() {
  window.clearTimeout(settingsSaveTimer);
  settingsSaveTimer = window.setTimeout(() => {
    invoke("save_settings", currentSettings()).catch(() => undefined);
  }, 250);
}

async function loadSavedSettings() {
  try {
    const settings = await invoke("load_settings");
    $("server").value = settings.server ?? "";
    $("port").value = settings.port ?? 4433;
    $("passphrase").value = settings.passphrase ?? "";
    $("routes").value = settings.routes ?? "";
    renderRoutes();
  } catch {
    // Keep the built-in defaults if the saved settings cannot be read.
  }
}

document.querySelectorAll("[data-page]").forEach((button) => {
  button.addEventListener("click", () => showPage(button.dataset.page));
});

$("routes").addEventListener("input", renderRoutes);
renderRoutes();

["server", "port", "passphrase", "routes"].forEach((id) => {
  $(id).addEventListener("input", saveSettingsSoon);
});

void loadSavedSettings();

$("drag-region").addEventListener("pointerdown", (event) => {
  if (event.button === 0) {
    appWindow.startDragging().catch(() => undefined);
  }
});

$("minimize").addEventListener("click", () => {
  invoke("window_control", { control: "minimize" }).catch(() => undefined);
});

$("close").addEventListener("click", async () => {
  window.clearTimeout(settingsSaveTimer);
  await invoke("save_settings", currentSettings()).catch(() => undefined);
  await invoke("window_control", { control: "close" }).catch(() => undefined);
});

connectButton.addEventListener("click", async () => {
  connectButton.disabled = true;
  setStatus("working", "Connecting…", "Authenticating and configuring selected routes.");
  window.clearTimeout(settingsSaveTimer);
  invoke("save_settings", currentSettings()).catch(() => undefined);
  try {
    const assigned = await invoke("connect", {
      server: $("server").value.trim(),
      port: Number($("port").value),
      passphrase: $("passphrase").value,
      routes: $("routes").value,
    });
    disconnectButton.disabled = false;
    setStatus("connected", "Connected", `Tunnel address: ${assigned}`);
    showPage("home");
  } catch (error) {
    connectButton.disabled = false;
    setStatus("error", "Connection failed", String(error));
  }
});

disconnectButton.addEventListener("click", async () => {
  disconnectButton.disabled = true;
  setStatus("working", "Disconnecting…", "Removing selected routes.");
  try {
    await invoke("disconnect");
    connectButton.disabled = false;
    setStatus("idle", "Not connected", "Routes stay on your normal connection.");
  } catch (error) {
    disconnectButton.disabled = false;
    setStatus("error", "Disconnect failed", String(error));
  }
});
