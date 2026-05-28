import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import "./style.css";

const state = {
  running: false,
  config: {
    autoStart: false,
    proxy: "127.0.0.1:2080",
    targets: [],
    watch: true,
    restoreOnExit: true,
  },
  logs: [],
  logFilter: "",
};

document.querySelector("#app").innerHTML = `
  <main class="shell">
    <section class="hero">
      <div>
        <p class="eyebrow">Ghost Proxifier</p>
        <h1>进程级透明代理控制台</h1>
        <p>使用 Tauri 管理注入、代理、开机启动、日志监控和退出恢复。</p>
      </div>
      <div class="status-card">
        <span id="status-dot" class="dot"></span>
        <strong id="status-text">未运行</strong>
        <small id="runtime-hint">配置会自动保存并在下次启动恢复</small>
      </div>
    </section>

    <section class="grid">
      <article class="panel">
        <h2>代理设置</h2>
        <label>上游 HTTP CONNECT 代理</label>
        <input id="proxy" placeholder="127.0.0.1:2080" />

        <div class="switch-row">
          <div>
            <strong>开机启动</strong>
            <span>写入当前用户 HKCU Run 项</span>
          </div>
          <label class="switch"><input id="autoStart" type="checkbox"><i></i></label>
        </div>
        <div class="switch-row">
          <div>
            <strong>持续监控新进程</strong>
            <span>等同于 ghost-proxifier --watch</span>
          </div>
          <label class="switch"><input id="watch" type="checkbox"><i></i></label>
        </div>
        <div class="switch-row">
          <div>
            <strong>退出时恢复进程状态</strong>
            <span>关闭 UI 时卸载已注入 DLL</span>
          </div>
          <label class="switch"><input id="restoreOnExit" type="checkbox"><i></i></label>
        </div>
      </article>

      <article class="panel">
        <div class="panel-title">
          <h2>目标进程</h2>
          <small>支持进程名或 PID</small>
        </div>
        <div class="target-input">
          <input id="targetInput" placeholder="chrome / chrome.exe / 12345" />
          <button id="addTarget">添加</button>
        </div>
        <ul id="targets" class="targets"></ul>
        <div class="actions">
          <button id="start" class="primary">启动代理</button>
          <button id="stop">停止</button>
          <button id="restore">立即恢复</button>
          <button id="save">保存配置</button>
        </div>
      </article>
    </section>

    <section class="panel logs-panel">
      <div class="panel-title">
        <div>
          <h2>实时日志</h2>
          <small>可输入进程名、PID 或任意关键字过滤</small>
        </div>
        <div class="log-tools">
          <input id="logFilter" placeholder="过滤：chrome / 3188 / DNS" />
          <button id="clearLogs">清空</button>
        </div>
      </div>
      <pre id="logs" class="logs"></pre>
    </section>
  </main>
`;

const $ = (id) => document.getElementById(id);

function readForm() {
  state.config.proxy = $("proxy").value.trim();
  state.config.autoStart = $("autoStart").checked;
  state.config.watch = $("watch").checked;
  state.config.restoreOnExit = $("restoreOnExit").checked;
  return structuredClone(state.config);
}

function render() {
  $("proxy").value = state.config.proxy ?? "";
  $("autoStart").checked = !!state.config.autoStart;
  $("watch").checked = !!state.config.watch;
  $("restoreOnExit").checked = !!state.config.restoreOnExit;
  $("status-text").textContent = state.running ? "代理运行中" : "未运行";
  $("status-dot").classList.toggle("running", state.running);
  $("start").disabled = state.running;
  $("stop").disabled = !state.running;

  $("targets").innerHTML = "";
  for (const [index, target] of state.config.targets.entries()) {
    const li = document.createElement("li");
    li.innerHTML = `<span>${escapeHtml(target)}</span><button data-index="${index}">删除</button>`;
    li.querySelector("button").onclick = () => {
      state.config.targets.splice(index, 1);
      render();
    };
    $("targets").appendChild(li);
  }
  renderLogs();
}

function renderLogs() {
  const filter = state.logFilter.trim().toLowerCase();
  const lines = filter
    ? state.logs.filter((line) => line.toLowerCase().includes(filter))
    : state.logs;
  const box = $("logs");
  box.textContent = lines.slice(-1000).join("\n");
  box.scrollTop = box.scrollHeight;
}

function addLog(line) {
  state.logs.push(`[${new Date().toLocaleTimeString()}] ${line}`);
  if (state.logs.length > 2000) state.logs.splice(0, state.logs.length - 2000);
  renderLogs();
}

function escapeHtml(value) {
  return String(value).replace(/[&<>"']/g, (m) => ({
    "&": "&amp;",
    "<": "&lt;",
    ">": "&gt;",
    '"': "&quot;",
    "'": "&#039;",
  }[m]));
}

async function call(name, args = {}, okMessage) {
  try {
    const result = await invoke(name, args);
    if (okMessage) addLog(okMessage);
    return result;
  } catch (err) {
    addLog(`❌ ${err}`);
    throw err;
  }
}

$("addTarget").onclick = () => {
  const value = $("targetInput").value.trim();
  if (!value) return;
  if (!state.config.targets.includes(value)) state.config.targets.push(value);
  $("targetInput").value = "";
  render();
};

$("targetInput").onkeydown = (event) => {
  if (event.key === "Enter") $("addTarget").click();
};

$("save").onclick = async () => {
  const cfg = readForm();
  const saved = await call("save_config", { config: cfg }, "配置已保存");
  state.config = saved;
  render();
};

$("autoStart").onchange = async () => {
  await call("set_auto_start", { enabled: $("autoStart").checked }, "开机启动设置已更新");
  state.config.autoStart = $("autoStart").checked;
};

$("start").onclick = async () => {
  await call("start_proxy", { config: readForm() }, "已启动 ghost-proxifier");
  state.running = true;
  render();
};

$("stop").onclick = async () => {
  await call("stop_proxy", {}, "已停止并按配置恢复进程状态");
  state.running = false;
  render();
};

$("restore").onclick = async () => {
  const out = await call("restore_processes", {}, "恢复命令执行完成");
  if (out?.trim()) addLog(out.trim());
};

$("clearLogs").onclick = () => {
  state.logs = [];
  renderLogs();
};

$("logFilter").oninput = () => {
  state.logFilter = $("logFilter").value;
  renderLogs();
};

listen("ghost-log", (event) => addLog(event.payload));

(async function init() {
  const status = await call("get_status");
  state.running = status.running;
  state.config = status.config;
  state.logs = status.logs ?? [];
  render();
})();
