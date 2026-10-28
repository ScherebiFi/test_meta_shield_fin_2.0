(() => {
  const $ = (selector) => document.querySelector(selector);
  const toastNode = $("#toast");
  let toastTimer;

  function showLogin() {
    $("#login-screen").classList.remove("hidden");
    $("#logout").classList.add("hidden");
  }

  function hideLogin(operator) {
    $("#login-screen").classList.add("hidden");
    $("#logout").classList.remove("hidden");
    $("#operator-name").textContent = `${operator.email} · ${operator.role}`;
  }

  async function api(path, options = {}) {
    const response = await fetch(path, {
      ...options,
      headers: { "Content-Type": "application/json", ...(options.headers || {}) },
    });
    const contentType = response.headers.get("content-type") || "";
    const body = contentType.includes("application/json") ? await response.json() : await response.text();
    if (!response.ok) {
      const message = typeof body === "object" ? body.detail || response.statusText : body;
      if (response.status === 401 && path !== "/api/auth/login") showLogin();
      throw new Error(message);
    }
    return body;
  }

  function notify(message, error = false) {
    toastNode.textContent = message;
    toastNode.classList.toggle("error", error);
    toastNode.classList.add("visible");
    clearTimeout(toastTimer);
    toastTimer = setTimeout(() => toastNode.classList.remove("visible"), 3800);
  }

  function cell(row, value, className = "") {
    const node = document.createElement("td");
    node.textContent = value ?? "—";
    if (className) node.className = className;
    row.append(node);
    return node;
  }

  function tag(status) {
    const span = document.createElement("span");
    span.className = "tag " + ({
      BLOCKED: "tag-danger", CHALLENGE_REQUIRED: "tag-warning",
      APPROVED: "tag-success", ACTIVE: "tag-success", VETOED: "tag-neutral",
      PENDING: "tag-warning", VERIFIED: "tag-success", PENDING_PROVIDER: "tag-neutral",
      SENT: "tag-success",
    }[status] || "tag-neutral");
    span.textContent = status || "INCONNU";
    return span;
  }

  function renderTransactions(items) {
    const body = $("#transactions-body");
    body.replaceChildren();
    $("#transaction-empty").classList.toggle("hidden", items.length > 0);
    for (const item of items) {
      const row = document.createElement("tr");
      cell(row, item.id);
      cell(row, item.customer_id);
      cell(row, `${Number(item.amount).toLocaleString("fr-FR", { minimumFractionDigits: 2 })} ${item.currency}`);
      cell(row, Number(item.velocity_score).toFixed(2));
      const score = cell(row, Number(item.risk_score).toFixed(2), "score");
      if (item.risk_score >= .72) score.classList.add("critical");
      cell(row, item.proxy_type);
      const status = document.createElement("td");
      status.append(tag(item.status));
      row.append(status);
      const actions = document.createElement("td");
      actions.className = "table-actions";
      if (item.status !== "APPROVED" && item.status !== "BLOCKED") {
        for (const [action, label, style] of [
          ["APPROVE", "✔ Valider", "button-success"],
          ["CHALLENGE", "🔒 2FA", "button-light"],
          ["BLOCK", "✖ Bloquer", "button-danger"],
        ]) {
          const button = document.createElement("button");
          button.className = `button ${style}`;
          button.textContent = label;
          button.dataset.action = action;
          button.dataset.transactionId = item.id;
          actions.append(button);
        }
      } else {
        actions.textContent = "Décision enregistrée";
      }
      row.append(actions);
      body.append(row);
    }
    const select = $("#challenge-transaction");
    if (select) {
      const selected = select.value;
      select.replaceChildren();
      for (const item of items) {
        const option = document.createElement("option");
        option.value = item.id;
        option.textContent = `${item.id} · ${item.customer_id}`;
        select.append(option);
      }
      if (items.some((item) => item.id === selected)) select.value = selected;
    }
  }

  async function loadTransactions() {
    renderTransactions(await api("/api/transactions"));
  }

  async function loadStatus() {
    const status = await api("/api/system/status");
    $("#stat-analyzed").textContent = status.transactions_analyzed.toLocaleString("fr-FR");
    $("#stat-alerts").textContent = status.critical_alerts.toLocaleString("fr-FR");
    $("#stat-challenges").textContent = status.active_challenges.toLocaleString("fr-FR");
    $("#failsafe-label").textContent = status.failsafe_enabled ? "ON" : "OFF";
    $("#failsafe-toggle").setAttribute("aria-pressed", String(status.failsafe_enabled));
    $("#baseline-description").textContent = status.baseline_model.trained
      ? `Isolation Forest entraîné sur ${status.baseline_model.baseline_transactions} transactions approuvées.`
      : `Isolation Forest en collecte: ${status.baseline_model.baseline_transactions}/100 transactions légitimes.`;
    const pill = $("#cloud-status");
    const configured = status.cloud === "configured";
    pill.classList.toggle("online", configured);
    pill.classList.toggle("offline", !configured);
    pill.lastChild.textContent = configured ? " Groq configuré" : " Mode local";
    $("#llm-description").textContent = configured
      ? "Groq configuré; les appels cloud sont réservés aux agrégats opt-in."
      : "Aucune clé Groq détectée. Le moteur de détection reste local.";
    const learning = status.feedback_model;
    $("#learning-description").textContent = learning.trained
      ? `Modèle entraîné sur ${learning.labels} décisions humaines. F1 CV: ${learning.metrics.cross_validated_f1.toFixed(2)}.`
      : `${learning.labels} décision(s) recueillie(s); entraînement après 10 exemples par classe.`;
  }

  async function loadAudit() {
    const entries = await api("/api/audit");
    const body = $("#audit-body");
    body.replaceChildren();
    for (const item of entries) {
      const row = document.createElement("tr");
      cell(row, new Date(item.created_at).toLocaleString("fr-FR"));
      cell(row, item.actor);
      cell(row, item.action);
      cell(row, item.entity_id);
      cell(row, item.entry_hash.slice(0, 16) + "…");
      body.append(row);
    }
  }

  async function loadAML() {
    const data = await api("/api/aml/case");
    $("#aml-case-id").textContent = `${data.case_id} · ${data.high_risk_transactions.length} transaction(s) à examiner`;
    $("#aml-report").textContent = data.high_risk_transactions.length
      ? `${data.high_risk_transactions.length} transaction(s) présentent un score de risque élevé. Ce score ne constitue pas une preuve d'infraction. Toute décision ou déclaration doit être validée par un analyste conformité.`
      : "Aucune transaction à risque élevé dans l'échantillon courant.";
    const graph = await api("/api/aml/graph");
    const graphStatus = $("#graph-status");
    graphStatus.textContent = graph.connected ? "Connecté" : "Non configuré";
    graphStatus.className = `tag ${graph.connected ? "tag-success" : "tag-neutral"}`;
    $("#graph-message").textContent = graph.message;
  }

  function connectLive() {
    const protocol = location.protocol === "https:" ? "wss:" : "ws:";
    const socket = new WebSocket(`${protocol}//${location.host}/ws/live-soc`);
    socket.onopen = () => { socket.send("ready"); };
    socket.onmessage = async () => {
      try { await Promise.all([loadTransactions(), loadStatus(), loadAudit()]); }
      catch (error) { notify(`Actualisation temps réel impossible: ${error.message}`, true); }
    };
    socket.onclose = () => setTimeout(connectLive, 2500);
    socket.onerror = () => socket.close();
  }

  document.querySelectorAll(".nav-tab").forEach((button) => {
    button.addEventListener("click", () => {
      document.querySelectorAll(".nav-tab").forEach((tab) => tab.classList.toggle("active", tab === button));
      document.querySelectorAll(".panel").forEach((panel) => panel.classList.toggle("active", panel.id === `panel-${button.dataset.tab}`));
    });
  });

  $("#refresh-transactions").addEventListener("click", () => loadTransactions().catch((error) => notify(error.message, true)));
  $("#login-form").addEventListener("submit", async (event) => {
    event.preventDefault();
    const button = event.currentTarget.querySelector("button");
    const errorBox = $("#login-error");
    button.disabled = true;
    errorBox.classList.add("hidden");
    try {
      const operator = await api("/api/auth/login", {
        method: "POST",
        body: JSON.stringify({
          email: $("#login-email").value,
          password: $("#login-password").value,
        }),
      });
      hideLogin(operator);
      await Promise.all([loadTransactions(), loadStatus(), loadAudit(), loadAML()]);
      connectLive();
    } catch (error) {
      errorBox.textContent = error.message;
      errorBox.classList.remove("hidden");
    } finally { button.disabled = false; }
  });
  $("#logout").addEventListener("click", async () => {
    try {
      await api("/api/auth/logout", { method: "POST" });
      showLogin();
      notify("Session fermée.");
    } catch (error) { notify(error.message, true); }
  });
  $("#search-form").addEventListener("submit", async (event) => {
    event.preventDefault();
    try {
      const data = await api("/api/registry/search", {
        method: "POST",
        body: JSON.stringify({ query: $("#search-query").value }),
      });
      $("#search-explanation").textContent = `${data.notice}\nFiltre appliqué: ${data.sql}`;
      $("#search-explanation").classList.remove("hidden");
      const body = $("#search-results");
      body.replaceChildren();
      for (const item of data.results) {
        const row = document.createElement("tr");
        cell(row, item.id);
        cell(row, item.customer_id);
        cell(row, Number(item.risk_score).toFixed(2));
        const status = document.createElement("td");
        status.append(tag(item.status));
        row.append(status);
        cell(row, item.proof_hash.slice(0, 18) + "…");
        body.append(row);
      }
      notify(`${data.results.length} résultat(s).`);
    } catch (error) { notify(error.message, true); }
  });
  $("#verify-audit").addEventListener("click", async () => {
    try {
      const result = await api("/api/audit/integrity");
      const note = $("#audit-integrity");
      note.textContent = result.valid
        ? `Journal valide — ${result.checked} entrée(s) vérifiée(s).`
        : `Intégrité compromise à l'entrée ${result.failed_entry_id}.`;
      note.classList.remove("hidden");
      note.classList.toggle("error", !result.valid);
    } catch (error) { notify(error.message, true); }
  });
  $("#zk-form").addEventListener("submit", async (event) => {
    event.preventDefault();
    const form = event.currentTarget;
    const button = form.querySelector("button");
    button.disabled = true;
    try {
      const proof = JSON.parse($("#zk-proof").value);
      const publicSignals = JSON.parse($("#zk-signals").value);
      if (!proof || Array.isArray(proof) || typeof proof !== "object" || !Array.isArray(publicSignals)) {
        throw new Error("La preuve doit être un objet JSON et les signaux publics un tableau JSON.");
      }
      const result = await api("/api/zk/verify", {
        method: "POST",
        body: JSON.stringify({ proof, public_signals: publicSignals }),
      });
      const note = $("#zk-result");
      note.textContent = result.valid ? "Preuve Groth16 valide." : `Preuve invalide : ${result.message}`;
      note.classList.remove("hidden");
      notify(result.valid ? "Preuve valide." : "La preuve n'est pas valide.", !result.valid);
    } catch (error) {
      notify(error.message, true);
    } finally { button.disabled = false; }
  });
  $("#failsafe-toggle").addEventListener("click", async () => {
    const active = $("#failsafe-label").textContent === "ON";
    if (!window.confirm(active
      ? "Confirmer la désactivation du mode Fail-safe ?"
      : "Confirmer le mode d'urgence ? Le seuil local sera durci.")) return;
    try {
      await api("/api/system/failsafe-toggle", { method: "POST", body: JSON.stringify({ enabled: !active }) });
      await Promise.all([loadStatus(), loadTransactions()]);
      notify(active ? "Mode Fail-safe désactivé." : "Mode Fail-safe activé; seuil local renforcé.");
    } catch (error) { notify(error.message, true); }
  });
  $("#analyze-aml").addEventListener("click", async () => {
    const button = $("#analyze-aml");
    button.disabled = true;
    try {
      const result = await api("/api/aml/deep-analyze", { method: "POST" });
      $("#aml-report").textContent = `${result.report}\n\nSource: ${result.provider}`;
      notify("Analyse terminée; revue humaine requise.");
      await loadAudit();
    } catch (error) { notify(error.message, true); }
    finally { button.disabled = false; }
  });
  $("#export-aml").addEventListener("click", () => setTimeout(() => loadAudit().catch(() => {}), 800));

  window.ShieldFin = { api, notify, loadTransactions, loadStatus, loadAudit, loadAML, tag, cell };
  api("/api/auth/me")
    .then(async (operator) => {
      hideLogin(operator);
      const results = await Promise.allSettled([
        loadTransactions(), loadStatus(), loadAudit(), loadAML(),
      ]);
      for (const result of results) {
        if (result.status === "rejected") notify(`Erreur de chargement: ${result.reason.message}`, true);
      }
      connectLive();
    })
    .catch(() => showLogin());
})();