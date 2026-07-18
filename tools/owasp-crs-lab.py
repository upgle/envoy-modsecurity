#!/usr/bin/env python3

import argparse
import http.client
import json
import os
from pathlib import Path
import re
import secrets
import subprocess
import tempfile
import threading
import time
import uuid
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


STARTUP_TIMEOUT_SECONDS = 60
REQUEST_TIMEOUT_SECONDS = 10
ACCESS_LOG_TIMEOUT_SECONDS = 2
MAX_API_BYTES = 2 * 1024 * 1024
MAX_REQUEST_BODY_BYTES = 1024 * 1024
MAX_RESPONSE_BODY_BYTES = 1024 * 1024
EXPECTED_CRS_RULE_FILE_COUNT = 27
LISTENER_NAME = "owasp_crs_lab_listener"
HEADER_NAME_PATTERN = re.compile(r"^[!#$%&'*+.^_`|~0-9A-Za-z-]+$")
DISALLOWED_REQUEST_HEADERS = {
    "connection",
    "content-length",
    "host",
    "proxy-connection",
    "transfer-encoding",
    "upgrade",
    "x-owasp-lab-id",
}
ALLOWED_METHODS = {"DELETE", "GET", "HEAD", "OPTIONS", "PATCH", "POST", "PUT"}


HTML_PAGE = r"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>OWASP CRS · Envoy Lab</title>
  <style>
    :root {
      color-scheme: light;
      --bg: #f6f8fa;
      --panel: #ffffff;
      --panel-2: #f3f4f6;
      --input: #ffffff;
      --line: #d8dee4;
      --line-strong: #b8c0ca;
      --text: #1f2328;
      --muted: #59636e;
      --faint: #6e7781;
      --blue: #0969da;
      --amber: #9a6700;
      --red: #cf222e;
      --green: #1a7f37;
    }
    * { box-sizing: border-box; }
    html, body { height: 100%; }
    body {
      margin: 0;
      font-family: Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
      color: var(--text);
      background: var(--bg);
      font-size: 13px;
    }
    button, input, select, textarea { font: inherit; }
    button { color: inherit; }
    main.app {
      width: 100%;
      height: 100%;
      margin: 0;
      padding: 0;
      display: grid;
      grid-template-rows: 50px minmax(0, 1fr) 27px;
      overflow: hidden;
    }
    header.appbar {
      margin: 0;
      padding: 0 14px;
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 20px;
      border-bottom: 1px solid var(--line);
      background: var(--panel);
    }
    .brand { display: flex; min-width: 0; align-items: baseline; gap: 10px; }
    .brand h1 { margin: 0; font-size: 14px; line-height: 1; letter-spacing: .015em; }
    .brand span { color: var(--faint); font-size: 12px; }
    .runtime-status { display: flex; min-width: 0; align-items: center; color: var(--muted); }
    .status-item {
      display: inline-flex;
      align-items: center;
      min-width: 0;
      padding: 0 10px;
      border-left: 1px solid var(--line);
      white-space: nowrap;
      font: 11px/1.2 ui-monospace, SFMono-Regular, Menlo, monospace;
    }
    .status-item:first-child { border-left: 0; }
    .status-dot { width: 7px; height: 7px; margin-right: 7px; border-radius: 50%; background: var(--amber); }
    .status-dot.ready { background: var(--green); }
    .workspace {
      min-height: 0;
      display: grid;
      grid-template-columns: 168px minmax(360px, .86fr) minmax(500px, 1.14fr);
      background: var(--panel);
    }
    .history {
      min-width: 0;
      border-right: 1px solid var(--line);
      background: var(--bg);
      overflow: auto;
    }
    .rail-head, .panel-head {
      height: 41px;
      padding: 0 12px;
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 10px;
      border-bottom: 1px solid var(--line);
    }
    .rail-head h2, .panel-head h2 { margin: 0; font-size: 11px; line-height: 1; letter-spacing: .075em; text-transform: uppercase; }
    .rail-count, .request-id { color: var(--faint); font: 10px/1 ui-monospace, SFMono-Regular, Menlo, monospace; }
    .history-list { padding: 6px; }
    .history-empty { padding: 14px 8px; color: var(--faint); font-size: 12px; line-height: 1.5; }
    .history-entry {
      width: 100%;
      padding: 8px 7px;
      display: grid;
      grid-template-columns: 34px minmax(0, 1fr) 28px;
      gap: 6px;
      align-items: center;
      border: 0;
      border-bottom: 1px solid var(--line);
      background: transparent;
      text-align: left;
      cursor: pointer;
    }
    .history-entry:hover { background: var(--panel-2); }
    .history-method, .history-code { color: var(--faint); font: 10px/1.2 ui-monospace, SFMono-Regular, Menlo, monospace; }
    .history-path { overflow: hidden; color: var(--muted); text-overflow: ellipsis; white-space: nowrap; font: 11px/1.2 ui-monospace, SFMono-Regular, Menlo, monospace; }
    .history-code.blocked { color: var(--red); }
    .history-code.allowed { color: var(--green); }
    .panel {
      min-width: 0;
      min-height: 0;
      display: flex;
      flex-direction: column;
      border: 0;
      border-radius: 0;
      background: var(--panel);
      box-shadow: none;
      overflow: hidden;
    }
    .request-panel { border-right: 1px solid var(--line); }
    .panel-body { min-height: 0; padding: 12px; overflow: auto; }
    .scenario-line { display: grid; grid-template-columns: 82px minmax(0, 1fr); align-items: center; margin-bottom: 12px; }
    .scenario-line label { margin: 0; }
    label { display: block; margin: 0 0 6px; color: var(--muted); font-size: 11px; font-weight: 600; letter-spacing: 0; text-transform: none; }
    input, select, textarea {
      width: 100%;
      padding: 8px 9px;
      color: var(--text);
      background: var(--input);
      border: 1px solid var(--line-strong);
      border-radius: 4px;
      outline: none;
      font: 12px/1.45 ui-monospace, SFMono-Regular, Menlo, monospace;
    }
    input:focus, select:focus, textarea:focus { border-color: var(--blue); box-shadow: 0 0 0 1px var(--blue); }
    textarea { min-height: 118px; resize: vertical; }
    #body { min-height: 150px; }
    .request-line { display: grid; grid-template-columns: 92px 1fr; gap: 7px; }
    .field { margin-bottom: 12px; }
    .send {
      width: 100%;
      padding: 9px 12px;
      border: 1px solid var(--blue);
      border-radius: 4px;
      color: #ffffff;
      background: var(--blue);
      font-weight: 700;
      cursor: pointer;
    }
    .send:hover { background: #0758b8; }
    .send:disabled { cursor: wait; opacity: .6; }
    .request-note { margin: 12px 0 0; color: var(--faint); font-size: 11px; line-height: 1.45; }
    .decision-strip {
      min-height: 43px;
      display: flex;
      align-items: center;
      border-bottom: 1px solid var(--line);
      background: var(--input);
    }
    .decision-primary { min-width: 104px; padding: 0 12px; font: 700 12px/1 ui-monospace, SFMono-Regular, Menlo, monospace; }
    .decision-primary.blocked { color: var(--red); }
    .decision-primary.allowed { color: var(--green); }
    .decision-primary.error { color: var(--amber); }
    .result-stat { padding: 0 12px; border-left: 1px solid var(--line); color: var(--muted); font: 11px/1 ui-monospace, SFMono-Regular, Menlo, monospace; }
    .result-content { min-height: 0; flex: 1; overflow: auto; }
    .result-section { border-bottom: 1px solid var(--line); }
    .result-section-head { height: 34px; padding: 0 12px; display: flex; align-items: center; justify-content: space-between; gap: 10px; border-bottom: 1px solid var(--line); background: var(--bg); }
    .result-section-head h3 { margin: 0; font-size: 10px; line-height: 1; letter-spacing: .065em; text-transform: uppercase; }
    .result-section-body { padding: 12px; }
    .scoreline { display: flex; flex-wrap: wrap; margin-bottom: 12px; border: 1px solid var(--line); background: var(--input); }
    .score-item { min-width: 132px; padding: 8px 10px; border-right: 1px solid var(--line); }
    .score-item:last-child { border-right: 0; }
    .score-label { display: block; margin-bottom: 5px; color: var(--faint); font-size: 10px; text-transform: uppercase; letter-spacing: .055em; }
    .score-value { font: 600 12px/1 ui-monospace, SFMono-Regular, Menlo, monospace; }
    .rules-table { width: 100%; border-collapse: collapse; border: 1px solid var(--line); font: 11px/1.35 ui-monospace, SFMono-Regular, Menlo, monospace; }
    .rules-table th { padding: 7px 9px; border-bottom: 1px solid var(--line-strong); color: var(--faint); background: var(--input); font-size: 10px; font-weight: 600; text-align: left; text-transform: uppercase; letter-spacing: .055em; }
    .rules-table td { padding: 8px 9px; border-bottom: 1px solid var(--line); color: var(--muted); }
    .rules-table tr:last-child td { border-bottom: 0; }
    .rule-id { color: var(--text); }
    .rule-disruptive { color: var(--red); }
    .rules-empty { padding: 18px 12px; border: 1px solid var(--line); color: var(--faint); line-height: 1.5; }
    pre { min-height: 0; max-height: none; overflow: auto; margin: 0; padding: 12px; border: 1px solid var(--line); border-radius: 0; background: var(--bg); color: #24292f; font: 11px/1.55 ui-monospace, SFMono-Regular, Menlo, monospace; white-space: pre-wrap; overflow-wrap: anywhere; }
    #response { min-height: 136px; max-height: 230px; }
    .raw-details { border-bottom: 1px solid var(--line); }
    .raw-details summary { padding: 10px 12px; color: var(--muted); background: var(--bg); cursor: pointer; font-size: 10px; font-weight: 600; letter-spacing: .065em; text-transform: uppercase; }
    .raw-details[open] summary { border-bottom: 1px solid var(--line); }
    .raw-details pre { min-height: 160px; max-height: 300px; margin: 12px; }
    .empty { color: var(--muted); }
    .statusbar { padding: 0 10px; display: flex; align-items: center; justify-content: space-between; gap: 12px; border-top: 1px solid var(--line); color: var(--faint); background: var(--bg); font: 10px/1 ui-monospace, SFMono-Regular, Menlo, monospace; }
    .statusbar kbd { padding: 1px 4px; border: 1px solid var(--line-strong); border-radius: 3px; color: var(--muted); background: var(--panel); font: inherit; }
    @media (max-width: 1020px) {
      .workspace { grid-template-columns: 132px minmax(330px, .9fr) minmax(420px, 1.1fr); }
      .status-item.local-only { display: none; }
    }
    @media (max-width: 800px) {
      html, body { height: auto; min-height: 100%; }
      main.app { min-height: 100vh; height: auto; grid-template-rows: auto auto 27px; overflow: visible; }
      header.appbar { min-height: 50px; display: flex; flex-wrap: wrap; padding: 8px 12px; }
      .brand span, .status-item.crs-status { display: none; }
      .workspace { display: block; }
      .history { display: none; }
      .panel { min-height: 520px; border-right: 0; border-bottom: 1px solid var(--line); }
      .result-panel { min-height: 600px; }
    }
    @media (max-width: 480px) {
      .request-line, .scenario-line { grid-template-columns: 1fr; gap: 6px; }
      .runtime-status .status-item { padding: 0 0 0 8px; }
      .result-stat { padding: 0 7px; }
      .decision-primary { min-width: 88px; padding: 0 8px; }
      .statusbar span:last-child { display: none; }
    }
  </style>
</head>
<body>
  <main class="app">
    <header class="appbar">
      <div class="brand">
        <h1>CRS Lab</h1>
        <span>Envoy / ModSecurity request inspector</span>
      </div>
      <div class="runtime-status">
        <span class="status-item"><i class="status-dot" id="health-dot"></i><span id="health">connecting</span></span>
        <span class="status-item crs-status" id="crs">CRS</span>
        <span class="status-item local-only">loopback only</span>
      </div>
    </header>

    <div class="workspace">
      <aside class="history" aria-label="Run history">
        <div class="rail-head"><h2>Runs</h2><span class="rail-count" id="history-count">0</span></div>
        <div class="history-list" id="history-list">
          <div class="history-empty">Completed requests appear here for quick replay.</div>
        </div>
      </aside>

      <section class="panel request-panel">
        <div class="panel-head"><h2>Request</h2><span class="request-id">PL1 / blocking</span></div>
        <div class="panel-body">
          <div class="scenario-line">
            <label for="preset-select">Test case</label>
            <select id="preset-select">
              <option value="clean">Clean request</option>
              <option value="sqli">SQL injection</option>
              <option value="xss">Cross-site scripting</option>
              <option value="lfi">Path traversal</option>
              <option value="rce">Command injection</option>
              <option value="json">JSON SQL injection</option>
              <option value="scanner">Scanner user agent</option>
              <option value="custom">Custom request</option>
            </select>
          </div>

          <div class="field">
            <label for="path">Method and path</label>
            <div class="request-line">
              <select id="method" aria-label="HTTP method">
                <option>GET</option><option>POST</option><option>PUT</option><option>PATCH</option><option>DELETE</option><option>OPTIONS</option>
              </select>
              <input id="path" value="/search?q=hello" spellcheck="false">
            </div>
          </div>
          <div class="field">
            <label for="headers">Headers · one per line</label>
            <textarea id="headers" spellcheck="false">Accept: application/json</textarea>
          </div>
          <div class="field">
            <label for="body">Body</label>
            <textarea id="body" spellcheck="false" placeholder="Optional request body"></textarea>
          </div>
          <button class="send" id="send">Run inspection</button>
          <p class="request-note">Requests are sent only to the lab's loopback Envoy listener. Response body inspection is disabled for this profile.</p>
        </div>
      </section>

      <section class="panel result-panel">
        <div class="panel-head"><h2>Inspection</h2><span class="request-id" id="request-id">no request</span></div>
        <div class="decision-strip" aria-live="polite">
          <strong class="decision-primary" id="decision">NOT RUN</strong>
          <span class="result-stat" id="status-code">HTTP —</span>
          <span class="result-stat" id="latency">— ms</span>
          <span class="result-stat" id="upstream">upstream —</span>
        </div>
        <div class="result-content">
          <section class="result-section" aria-labelledby="rules-heading">
            <div class="result-section-head"><h3 id="rules-heading">Rule matches</h3></div>
            <div class="result-section-body">
              <div class="scoreline">
                <div class="score-item"><span class="score-label">Inbound score</span><span class="score-value" id="inbound-score">—</span></div>
                <div class="score-item"><span class="score-label">Block threshold</span><span class="score-value" id="score-threshold">—</span></div>
                <div class="score-item"><span class="score-label">Phase</span><span class="score-value" id="event-phase">—</span></div>
              </div>
              <table class="rules-table" id="rules-table" hidden>
                <thead><tr><th>Rule ID</th><th>Phase</th><th>Action</th></tr></thead>
                <tbody id="rules-body"></tbody>
              </table>
              <div class="rules-empty" id="rules-empty">Run a test case or compose a request to inspect CRS output.</div>
            </div>
          </section>
          <section class="result-section" aria-labelledby="response-heading">
            <div class="result-section-head"><h3 id="response-heading">HTTP response</h3></div>
            <div class="result-section-body"><pre id="response" class="empty">No response yet.</pre></div>
          </section>
          <details class="raw-details">
            <summary>Raw security event</summary>
            <pre id="event" class="empty">No security event yet.</pre>
          </details>
        </div>
      </section>
    </div>
    <footer class="statusbar">
      <span id="response-detail">Ready</span>
      <span><kbd>⌘</kbd> + <kbd>Enter</kbd> run inspection</span>
    </footer>
  </main>

  <script>
    const token = "__LAB_TOKEN__";
    const presets = {
      clean: { method: "GET", path: "/search?q=hello", headers: "Accept: application/json", body: "" },
      sqli: { method: "GET", path: "/search?q=1%27%20OR%20%271%27%3D%271", headers: "Accept: application/json", body: "" },
      xss: { method: "GET", path: "/search?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E", headers: "Accept: text/html", body: "" },
      lfi: { method: "GET", path: "/download?file=..%2F..%2F..%2F..%2Fetc%2Fpasswd", headers: "Accept: application/json", body: "" },
      rce: { method: "GET", path: "/run?cmd=cat%20%2Fetc%2Fpasswd", headers: "Accept: application/json", body: "" },
      json: { method: "POST", path: "/api/login", headers: "Content-Type: application/json\nAccept: application/json", body: "{\n  \"username\": \"admin' OR '1'='1\",\n  \"password\": \"demo\"\n}" },
      scanner: { method: "GET", path: "/", headers: "User-Agent: sqlmap/1.8\nAccept: application/json", body: "" }
    };
    const runHistory = [];

    function applyPreset(name) {
      const preset = presets[name];
      document.getElementById("preset-select").value = name;
      document.getElementById("method").value = preset.method;
      document.getElementById("path").value = preset.path;
      document.getElementById("headers").value = preset.headers;
      document.getElementById("body").value = preset.body;
    }

    function parseHeaders(value) {
      const headers = {};
      value.split(/\r?\n/).forEach((line) => {
        if (!line.trim()) return;
        const separator = line.indexOf(":");
        if (separator < 1) throw new Error(`Invalid header line: ${line}`);
        headers[line.slice(0, separator).trim()] = line.slice(separator + 1).trim();
      });
      return headers;
    }

    function text(id, value) { document.getElementById(id).textContent = value; }

    function renderRules(event) {
      const table = document.getElementById("rules-table");
      const body = document.getElementById("rules-body");
      const empty = document.getElementById("rules-empty");
      body.replaceChildren();
      text("inbound-score", event?.blocking_inbound_anomaly_score ?? "—");
      text("score-threshold", event?.inbound_anomaly_score_threshold ?? "—");
      text("event-phase", event?.phase || "—");

      const rules = Array.isArray(event?.rules) ? event.rules : [];
      table.hidden = rules.length === 0;
      empty.hidden = rules.length !== 0;
      if (rules.length === 0) {
        empty.textContent = event
          ? "The filter emitted a security event without bounded rule records."
          : "No ModSecurity security event was emitted for this request.";
        return;
      }

      rules.forEach((rule) => {
        const row = document.createElement("tr");
        const id = document.createElement("td");
        const phase = document.createElement("td");
        const action = document.createElement("td");
        id.className = "rule-id";
        id.textContent = rule.id || "—";
        phase.textContent = rule.phase ?? "—";
        action.textContent = rule.disruptive ? "disruptive" : "log";
        if (rule.disruptive) action.className = "rule-disruptive";
        row.append(id, phase, action);
        body.append(row);
      });
    }

    function renderHistory() {
      const list = document.getElementById("history-list");
      list.replaceChildren();
      text("history-count", String(runHistory.length));
      runHistory.forEach((entry) => {
        const button = document.createElement("button");
        button.className = "history-entry";
        button.title = `${entry.payload.method} ${entry.payload.path}`;

        const method = document.createElement("span");
        method.className = "history-method";
        method.textContent = entry.payload.method;
        const path = document.createElement("span");
        path.className = "history-path";
        path.textContent = entry.payload.path;
        const code = document.createElement("span");
        code.className = `history-code ${entry.blocked ? "blocked" : "allowed"}`;
        code.textContent = String(entry.result.response.status);
        button.append(method, path, code);
        button.addEventListener("click", () => {
          document.getElementById("preset-select").value = "custom";
          document.getElementById("method").value = entry.payload.method;
          document.getElementById("path").value = entry.payload.path;
          document.getElementById("headers").value = entry.headersText;
          document.getElementById("body").value = entry.payload.body;
          renderResult(entry.result);
        });
        list.append(button);
      });
    }

    function addHistory(result, payload, headersText) {
      const event = result.security_event;
      const blocked = event?.outcome === "blocked" || result.response.status >= 400;
      runHistory.unshift({ result, payload, headersText, blocked });
      if (runHistory.length > 12) runHistory.pop();
      renderHistory();
    }

    function renderResult(result) {
      const event = result.security_event;
      const blocked = event?.outcome === "blocked" || result.response.status >= 400;
      const decision = event?.outcome?.toUpperCase() || (blocked ? "BLOCKED" : "ALLOWED");
      const decisionNode = document.getElementById("decision");
      decisionNode.textContent = decision;
      decisionNode.className = `decision-primary ${blocked ? "blocked" : "allowed"}`;
      text("status-code", `HTTP ${result.response.status}`);
      text("latency", `${result.response.elapsed_ms} ms`);
      text("request-id", result.request_id.slice(0, 12));
      text("upstream", result.upstream_reached ? "upstream reached" : "upstream bypassed");
      text("response-detail", result.response.detail || result.response.reason || "Request complete");
      renderRules(event);

      const eventNode = document.getElementById("event");
      if (event) {
        eventNode.textContent = JSON.stringify(event, null, 2);
        eventNode.className = "";
      } else {
        eventNode.textContent = "No ModSecurity security event was emitted for this clean request.";
        eventNode.className = "empty";
      }

      const headers = result.response.headers.map(([name, value]) => `${name}: ${value}`).join("\n");
      const responseNode = document.getElementById("response");
      responseNode.textContent = `${headers}\n\n${result.response.body}${result.response.truncated ? "\n\n[response truncated]" : ""}`;
      responseNode.className = "";
    }

    async function sendRequest() {
      const button = document.getElementById("send");
      button.disabled = true;
      button.textContent = "Inspecting…";
      try {
        const headersText = document.getElementById("headers").value;
        const payload = {
          method: document.getElementById("method").value,
          path: document.getElementById("path").value,
          headers: parseHeaders(headersText),
          body: document.getElementById("body").value
        };
        const response = await fetch("/api/test", {
          method: "POST",
          headers: { "content-type": "application/json", "x-owasp-lab-token": token },
          body: JSON.stringify(payload)
        });
        const result = await response.json();
        if (!response.ok) throw new Error(result.error || `HTTP ${response.status}`);
        renderResult(result);
        addHistory(result, payload, headersText);
      } catch (error) {
        const decisionNode = document.getElementById("decision");
        decisionNode.textContent = "ERROR";
        decisionNode.className = "decision-primary error";
        const empty = document.getElementById("rules-empty");
        document.getElementById("rules-table").hidden = true;
        empty.hidden = false;
        empty.textContent = error.message;
        text("response-detail", "Inspection failed");
      } finally {
        button.disabled = false;
        button.textContent = "Run inspection";
      }
    }

    document.getElementById("preset-select").addEventListener("change", (event) => {
      if (presets[event.target.value]) applyPreset(event.target.value);
    });
    ["method", "path", "headers", "body"].forEach((id) => {
      document.getElementById(id).addEventListener("input", () => {
        document.getElementById("preset-select").value = "custom";
      });
    });
    document.getElementById("send").addEventListener("click", sendRequest);
    document.addEventListener("keydown", (event) => {
      if ((event.metaKey || event.ctrlKey) && event.key === "Enter") {
        event.preventDefault();
        sendRequest();
      }
    });
    fetch("/api/status").then((response) => response.json()).then((status) => {
      text("health", status.envoy_ready ? "Envoy ready" : "Envoy unavailable");
      document.getElementById("health-dot").classList.toggle("ready", status.envoy_ready);
      text("crs", `CRS ${status.crs_version} / ${status.rule_files} files`);
    }).catch(() => text("health", "status unavailable"));
  </script>
</body>
</html>
"""


BOOTSTRAP_TEMPLATE = """admin:
  address:
    socket_address:
      address: 127.0.0.1
      port_value: 0

static_resources:
  listeners:
    - name: owasp_crs_lab_listener
      address:
        socket_address:
          address: 127.0.0.1
          port_value: 0
      filter_chains:
        - filters:
            - name: envoy.filters.network.http_connection_manager
              typed_config:
                \"@type\": type.googleapis.com/envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager
                stat_prefix: owasp_crs_lab_http
                access_log:
                  - name: envoy.access_loggers.stdout
                    typed_config:
                      \"@type\": type.googleapis.com/envoy.extensions.access_loggers.stream.v3.StdoutAccessLog
                      log_format:
                        json_format:
                          request_id: \"%REQ(X-OWASP-LAB-ID)%\"
                          method: \"%REQ(:METHOD)%\"
                          path: \"%REQ(:PATH)%\"
                          response_code: \"%RESPONSE_CODE%\"
                          response_code_details: \"%RESPONSE_CODE_DETAILS%\"
                          duration_ms: \"%DURATION%\"
                          modsecurity: \"%DYNAMIC_METADATA(envoy.filters.http.modsecurity)%\"
                route_config:
                  name: owasp_crs_lab_routes
                  virtual_hosts:
                    - name: owasp_crs_lab_service
                      domains: [\"*\"]
                      routes:
                        - match:
                            prefix: \"/\"
                          route:
                            cluster: owasp_crs_lab_upstream
                http_filters:
                  - name: envoy.filters.http.modsecurity
                    typed_config:
                      \"@type\": type.googleapis.com/envoy_modsecurity.extensions.filters.http.modsecurity.v3.ModSecurity
                      rules:
                        - filename: __CRS_ROOT_CONFIG__
                      request_body:
                        max_bytes:
                          value: 1048576
                      failure_mode_allow: false
                      stat_prefix: owasp_crs_lab
                      max_active_body_bytes:
                        value: 8388608
                  - name: envoy.filters.http.router
                    typed_config:
                      \"@type\": type.googleapis.com/envoy.extensions.filters.http.router.v3.Router

  clusters:
    - name: owasp_crs_lab_upstream
      connect_timeout: 1s
      type: STATIC
      load_assignment:
        cluster_name: owasp_crs_lab_upstream
        endpoints:
          - lb_endpoints:
              - endpoint:
                  address:
                    socket_address:
                      address: 127.0.0.1
                      port_value: __UPSTREAM_PORT__
"""


class UserInputError(ValueError):
    pass


def parse_args():
    repository_root = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(
        description="Run a loopback-only web lab against the pinned OWASP CRS and custom Envoy."
    )
    parser.add_argument(
        "--envoy-binary",
        default=repository_root / "bazel-bin" / "envoy-modsecurity",
        type=Path,
    )
    parser.add_argument("--ui-port", default=8080, type=int)
    parser.add_argument("--open-browser", action="store_true")
    parser.add_argument("--work-directory", type=Path)
    parser.add_argument("--log-level", default="warning")
    args = parser.parse_args()
    if not 0 <= args.ui_port <= 65535:
        parser.error("--ui-port must be between 0 and 65535")
    return args


def seclang_path(path):
    value = str(Path(path).resolve())
    if any(character.isspace() for character in value) or "#" in value:
        raise ValueError(f"path cannot be represented safely in SecLang: {value!r}")
    return value


def write_crs_config(repository_root, work_directory):
    rules_directory = repository_root / "third_party" / "coreruleset" / "rules"
    rule_files = sorted(rules_directory.glob("*.conf"))
    if len(rule_files) != EXPECTED_CRS_RULE_FILE_COUNT:
        raise RuntimeError(
            f"expected {EXPECTED_CRS_RULE_FILE_COUNT} pinned CRS rule files, "
            f"found {len(rule_files)}"
        )

    crs_setup = repository_root / "third_party" / "coreruleset" / "crs-setup.conf.example"
    unicode_mapping = repository_root / "third_party" / "modsecurity" / "unicode.mapping"
    includes = "\n".join(f"Include {seclang_path(path)}" for path in rule_files)
    config = f"""# Generated local-only OWASP CRS lab configuration.
SecRuleEngine On
SecRequestBodyAccess On
SecRequestBodyLimit {MAX_REQUEST_BODY_BYTES}
SecRequestBodyNoFilesLimit {MAX_REQUEST_BODY_BYTES}
SecRequestBodyLimitAction Reject
SecRequestBodyJsonDepthLimit 64
SecArgumentsLimit 1000

SecRule REQUEST_HEADERS:Content-Type \"^(?:application(?:/soap\\+|/)|text/)xml\" \\
    \"id:200000,phase:1,t:none,t:lowercase,pass,nolog,ctl:requestBodyProcessor=XML\"
SecRule REQUEST_HEADERS:Content-Type \"^application/(?:[a-z0-9.-]+\\+)?json(?:\\s*;|$)\" \\
    \"id:200001,phase:1,t:none,t:lowercase,pass,nolog,ctl:requestBodyProcessor=JSON\"

SecResponseBodyAccess Off
SecAuditEngine Off
SecDebugLogLevel 0
SecStatusEngine Off
SecXmlExternalEntity Off
SecUnicodeMapFile {seclang_path(unicode_mapping)} 20127

Include {seclang_path(crs_setup)}
{includes}
"""
    config_path = work_directory / "owasp-crs-lab.conf"
    temporary_path = work_directory / f".owasp-crs-lab-{uuid.uuid4().hex}.tmp"
    temporary_path.write_text(config, encoding="utf-8")
    temporary_path.chmod(0o444)
    temporary_path.replace(config_path)
    return config_path, len(rule_files)


def write_bootstrap(work_directory, crs_config_path, upstream_port):
    config = BOOTSTRAP_TEMPLATE.replace(
        "__CRS_ROOT_CONFIG__", seclang_path(crs_config_path)
    ).replace("__UPSTREAM_PORT__", str(upstream_port))
    config_path = work_directory / "bootstrap.yaml"
    config_path.write_text(config, encoding="utf-8")
    return config_path


class EchoUpstream(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self):
        super().__init__(("127.0.0.1", 0), EchoUpstreamHandler)


class EchoUpstreamHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_DELETE(self):
        self._respond()

    def do_GET(self):
        self._respond()

    def do_HEAD(self):
        self._respond(send_body=False)

    def do_OPTIONS(self):
        self._respond()

    def do_PATCH(self):
        self._respond()

    def do_POST(self):
        self._respond()

    def do_PUT(self):
        self._respond()

    def _respond(self, send_body=True):
        length = int(self.headers.get("content-length", "0"))
        request_body = self.rfile.read(length) if length else b""
        response = {
            "message": "request reached the local upstream",
            "method": self.command,
            "path": self.path,
            "content_type": self.headers.get("content-type"),
            "body": request_body.decode("utf-8", errors="replace"),
        }
        response_body = json.dumps(response, indent=2).encode("utf-8")
        self.send_response(200)
        self.send_header("content-type", "application/json; charset=utf-8")
        self.send_header("x-owasp-lab-upstream", "reached")
        self.send_header("content-length", str(len(response_body) if send_body else 0))
        self.end_headers()
        if send_body:
            self.wfile.write(response_body)

    def log_message(self, _format, *_args):
        pass


class LabRuntime:
    def __init__(self, args):
        self.args = args
        self.repository_root = Path(__file__).resolve().parents[1]
        self.token = secrets.token_hex(24)
        self.rule_file_count = 0
        self.envoy = None
        self.envoy_log = None
        self.upstream = None
        self.upstream_thread = None
        self.ui_server = None
        self._temporary_directory = None

    def start(self):
        envoy_binary = self.args.envoy_binary.resolve()
        if not envoy_binary.is_file() or not os.access(envoy_binary, os.X_OK):
            raise RuntimeError(f"custom Envoy binary is not executable: {envoy_binary}")
        self.envoy_binary = envoy_binary

        if self.args.work_directory:
            self.work_directory = self.args.work_directory.resolve()
            self.work_directory.mkdir(parents=True, exist_ok=True)
        else:
            self._temporary_directory = tempfile.TemporaryDirectory(
                prefix="envoy-modsecurity-crs-lab-"
            )
            self.work_directory = Path(self._temporary_directory.name)

        self.upstream = EchoUpstream()
        self.upstream_thread = threading.Thread(
            target=self.upstream.serve_forever, daemon=True
        )
        self.upstream_thread.start()

        crs_config, self.rule_file_count = write_crs_config(
            self.repository_root, self.work_directory
        )
        self.bootstrap_path = write_bootstrap(
            self.work_directory, crs_config, self.upstream.server_port
        )
        self.admin_address_path = self.work_directory / "admin-address.txt"
        self.envoy_log_path = self.work_directory / "envoy.log"

        validation = subprocess.run(
            [str(self.envoy_binary), "--mode", "validate", "-c", str(self.bootstrap_path)],
            capture_output=True,
            check=False,
            text=True,
            timeout=STARTUP_TIMEOUT_SECONDS,
        )
        if validation.returncode != 0:
            raise RuntimeError(
                "custom Envoy rejected the generated lab bootstrap:\n"
                f"stdout:\n{validation.stdout}\nstderr:\n{validation.stderr}"
            )

        self.envoy_log = self.envoy_log_path.open("w", encoding="utf-8")
        self.envoy = subprocess.Popen(
            [
                str(self.envoy_binary),
                "-c",
                str(self.bootstrap_path),
                "--admin-address-path",
                str(self.admin_address_path),
                "--concurrency",
                "1",
                "--disable-hot-restart",
                "--log-level",
                self.args.log_level,
                "--file-flush-interval-msec",
                "10",
            ],
            stdout=self.envoy_log,
            stderr=subprocess.STDOUT,
            text=True,
        )
        self.admin_host, self.admin_port = self._wait_for_admin()
        self.envoy_port = self._discover_listener_port()
        self.ui_server = LabHttpServer(("127.0.0.1", self.args.ui_port), self)

    @property
    def ui_url(self):
        return f"http://127.0.0.1:{self.ui_server.server_port}/"

    def serve(self):
        print(f"OWASP CRS web lab: {self.ui_url}", flush=True)
        print(f"Envoy listener: http://127.0.0.1:{self.envoy_port}", flush=True)
        print(f"Generated files and logs: {self.work_directory}", flush=True)
        print("Press Ctrl+C to stop.", flush=True)
        if self.args.open_browser:
            webbrowser.open(self.ui_url)
        self.ui_server.serve_forever(poll_interval=0.2)

    def stop(self):
        if self.ui_server is not None:
            self.ui_server.server_close()
            self.ui_server = None
        if self.envoy is not None and self.envoy.poll() is None:
            self.envoy.terminate()
            try:
                self.envoy.wait(timeout=10)
            except subprocess.TimeoutExpired:
                self.envoy.kill()
                self.envoy.wait(timeout=5)
        if self.envoy_log is not None and not self.envoy_log.closed:
            self.envoy_log.close()
        if self.upstream is not None:
            self.upstream.shutdown()
            self.upstream.server_close()
        if self.upstream_thread is not None:
            self.upstream_thread.join(timeout=5)
        if self._temporary_directory is not None:
            self._temporary_directory.cleanup()

    def execute_request(self, payload):
        if self.envoy is None or self.envoy.poll() is not None:
            raise RuntimeError("custom Envoy is not running")
        method, path, headers, body = validate_request(payload)
        request_id = uuid.uuid4().hex
        headers["host"] = "lab.local"
        headers["x-owasp-lab-id"] = request_id
        headers.setdefault("user-agent", "envoy-modsecurity-owasp-lab/1.0")
        headers.setdefault("accept", "application/json")
        if body and "content-type" not in headers:
            headers["content-type"] = "text/plain; charset=utf-8"

        connection = http.client.HTTPConnection(
            "127.0.0.1", self.envoy_port, timeout=REQUEST_TIMEOUT_SECONDS
        )
        started = time.monotonic()
        try:
            connection.request(method, path, body=body, headers=headers)
            response = connection.getresponse()
            response_body = response.read(MAX_RESPONSE_BODY_BYTES + 1)
            elapsed_ms = round((time.monotonic() - started) * 1000, 1)
            truncated = len(response_body) > MAX_RESPONSE_BODY_BYTES
            if truncated:
                response_body = response_body[:MAX_RESPONSE_BODY_BYTES]
            response_headers = list(response.getheaders())
            upstream_reached = response.getheader("x-owasp-lab-upstream") == "reached"
            status = response.status
            reason = response.reason
        finally:
            connection.close()

        access_entry = self._wait_for_access_entry(request_id)
        security_event = None
        detail = None
        if access_entry:
            candidate = access_entry.get("modsecurity")
            if isinstance(candidate, dict) and candidate:
                security_event = candidate
            detail = access_entry.get("response_code_details")

        return {
            "request_id": request_id,
            "upstream_reached": upstream_reached,
            "security_event": security_event,
            "response": {
                "status": status,
                "reason": reason,
                "detail": detail,
                "elapsed_ms": elapsed_ms,
                "headers": response_headers,
                "body": response_body.decode("utf-8", errors="replace"),
                "truncated": truncated,
            },
        }

    def _wait_for_access_entry(self, request_id):
        deadline = time.monotonic() + ACCESS_LOG_TIMEOUT_SECONDS
        while time.monotonic() < deadline:
            if self.envoy is not None and self.envoy.poll() is not None:
                raise RuntimeError(
                    f"custom Envoy exited with {self.envoy.returncode}:\n{self._envoy_logs()}"
                )
            for line in reversed(self._envoy_logs().splitlines()):
                try:
                    entry = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if isinstance(entry, dict) and entry.get("request_id") == request_id:
                    return entry
            time.sleep(0.02)
        return None

    def _envoy_logs(self):
        if not self.envoy_log_path.exists():
            return ""
        return self.envoy_log_path.read_text(encoding="utf-8", errors="replace")

    def _wait_for_admin(self):
        deadline = time.monotonic() + STARTUP_TIMEOUT_SECONDS
        last_error = None
        while time.monotonic() < deadline:
            if self.envoy.poll() is not None:
                raise RuntimeError(
                    f"custom Envoy exited with {self.envoy.returncode}:\n{self._envoy_logs()}"
                )
            if self.admin_address_path.exists():
                address = self.admin_address_path.read_text(encoding="utf-8").strip()
                if address:
                    try:
                        host, port = address.rsplit(":", 1)
                        host = host.strip("[]")
                        status, _body = self._admin_request(host, int(port), "/ready")
                        if status == 200:
                            return host, int(port)
                    except (ConnectionError, OSError, ValueError, http.client.HTTPException) as error:
                        last_error = error
            time.sleep(0.05)
        raise RuntimeError(
            f"custom Envoy admin did not become ready: {last_error}\n{self._envoy_logs()}"
        )

    @staticmethod
    def _admin_request(host, port, path):
        connection = http.client.HTTPConnection(host, port, timeout=REQUEST_TIMEOUT_SECONDS)
        try:
            connection.request("GET", path)
            response = connection.getresponse()
            return response.status, response.read()
        finally:
            connection.close()

    def _discover_listener_port(self):
        status, body = self._admin_request(
            self.admin_host, self.admin_port, "/listeners?format=json"
        )
        if status != 200:
            raise RuntimeError(f"listener discovery failed with HTTP {status}: {body!r}")
        for listener in json.loads(body)["listener_statuses"]:
            if listener["name"] == LISTENER_NAME:
                return int(listener["local_address"]["socket_address"]["port_value"])
        raise RuntimeError(f"{LISTENER_NAME} was not reported by the Envoy admin API")


def validate_request(payload):
    if not isinstance(payload, dict):
        raise UserInputError("request payload must be a JSON object")
    method = payload.get("method", "GET")
    path = payload.get("path", "/")
    raw_headers = payload.get("headers", {})
    body = payload.get("body", "")

    if not isinstance(method, str) or method.upper() not in ALLOWED_METHODS:
        raise UserInputError(f"method must be one of {sorted(ALLOWED_METHODS)}")
    method = method.upper()
    if (
        not isinstance(path, str)
        or not path.startswith("/")
        or path.startswith("//")
        or len(path) > 4096
        or "\r" in path
        or "\n" in path
    ):
        raise UserInputError("path must be a local origin-form path of at most 4096 characters")
    if not isinstance(raw_headers, dict) or len(raw_headers) > 32:
        raise UserInputError("headers must be an object with at most 32 entries")
    if not isinstance(body, str):
        raise UserInputError("body must be a string")
    body_bytes = body.encode("utf-8")
    if len(body_bytes) > MAX_REQUEST_BODY_BYTES:
        raise UserInputError(f"body exceeds the {MAX_REQUEST_BODY_BYTES}-byte lab limit")

    headers = {}
    for raw_name, raw_value in raw_headers.items():
        if not isinstance(raw_name, str) or not HEADER_NAME_PATTERN.fullmatch(raw_name):
            raise UserInputError(f"invalid header name: {raw_name!r}")
        if not isinstance(raw_value, str) or "\r" in raw_value or "\n" in raw_value:
            raise UserInputError(f"invalid value for header {raw_name!r}")
        name = raw_name.lower()
        if name in DISALLOWED_REQUEST_HEADERS:
            raise UserInputError(f"header is managed by the lab and cannot be set: {raw_name}")
        if len(raw_value) > 8192:
            raise UserInputError(f"header value is too long: {raw_name}")
        headers[name] = raw_value
    return method, path, headers, body_bytes


class LabHttpServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, server_address, runtime):
        self.runtime = runtime
        super().__init__(server_address, LabRequestHandler)


class LabRequestHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self):
        if self.path == "/":
            page = HTML_PAGE.replace("__LAB_TOKEN__", self.server.runtime.token)
            self._send_bytes(200, page.encode("utf-8"), "text/html; charset=utf-8")
            return
        if self.path == "/api/status":
            runtime = self.server.runtime
            self._send_json(
                200,
                {
                    "envoy_ready": runtime.envoy is not None and runtime.envoy.poll() is None,
                    "crs_version": "4.28.0",
                    "rule_files": runtime.rule_file_count,
                },
            )
            return
        if self.path == "/favicon.ico":
            self._send_bytes(204, b"", "image/x-icon")
            return
        self._send_json(404, {"error": "not found"})

    def do_POST(self):
        if self.path != "/api/test":
            self._send_json(404, {"error": "not found"})
            return
        if not secrets.compare_digest(
            self.headers.get("x-owasp-lab-token", ""), self.server.runtime.token
        ):
            self._send_json(403, {"error": "invalid lab token"})
            return
        try:
            length = int(self.headers.get("content-length", "0"))
        except ValueError:
            self._send_json(400, {"error": "invalid content length"})
            return
        if length <= 0 or length > MAX_API_BYTES:
            self._send_json(413, {"error": "request payload is empty or too large"})
            return
        try:
            payload = json.loads(self.rfile.read(length))
            result = self.server.runtime.execute_request(payload)
        except (json.JSONDecodeError, UnicodeDecodeError) as error:
            self._send_json(400, {"error": f"invalid JSON: {error}"})
            return
        except UserInputError as error:
            self._send_json(400, {"error": str(error)})
            return
        except (ConnectionError, OSError, RuntimeError, http.client.HTTPException) as error:
            self._send_json(502, {"error": str(error)})
            return
        self._send_json(200, result)

    def _send_json(self, status, payload):
        self._send_bytes(
            status,
            json.dumps(payload, ensure_ascii=False).encode("utf-8"),
            "application/json; charset=utf-8",
        )

    def _send_bytes(self, status, body, content_type):
        self.send_response(status)
        self.send_header("content-type", content_type)
        self.send_header("content-length", str(len(body)))
        self.send_header("cache-control", "no-store")
        self.send_header("content-security-policy", "default-src 'self'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'")
        self.send_header("x-content-type-options", "nosniff")
        self.send_header("x-frame-options", "DENY")
        self.end_headers()
        if body:
            self.wfile.write(body)

    def log_message(self, _format, *_args):
        pass


def main():
    args = parse_args()
    runtime = LabRuntime(args)
    try:
        runtime.start()
        runtime.serve()
    except KeyboardInterrupt:
        print("\nStopping OWASP CRS web lab.", flush=True)
    finally:
        runtime.stop()


if __name__ == "__main__":
    main()
