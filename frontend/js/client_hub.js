(() => {
  const { api, notify, loadAudit, tag, cell } = window.ShieldFin;
  const $ = (selector) => document.querySelector(selector);

  async function loadChallenges() {
    const challenges = await api("/api/client-hub/challenges");
    const body = $("#challenges-body");
    body.replaceChildren();
    for (const challenge of challenges) {
      const row = document.createElement("tr");
      cell(row, challenge.id);
      cell(row, challenge.transaction_id);
      cell(row, challenge.channel);
      const status = document.createElement("td");
      status.append(tag(challenge.status));
      row.append(status);
      body.append(row);
    }
  }

  async function loadRules() {
    const rules = await api("/api/self-healing/rules");
    const body = $("#rules-body");
    body.replaceChildren();
    for (const rule of rules) {
      const row = document.createElement("tr");
      cell(row, rule.id);
      cell(row, rule.origin);
      const status = document.createElement("td");
      status.append(tag(rule.status));
      row.append(status);
      const actions = document.createElement("td");
      if (rule.status === "ACTIVE") {
        const veto = document.createElement("button");
        veto.className = "button button-danger";
        veto.textContent = "🛑 Veto";
        veto.addEventListener("click", async () => {
          if (!window.confirm(`Veto humain de la règle ${rule.id} ?`)) return;
          veto.disabled = true;
          try {
            await api(`/api/self-healing/rules/${encodeURIComponent(rule.id)}/veto`, { method: "POST" });
            notify(`Règle ${rule.id} mise en veto.`);
            await Promise.all([loadRules(), loadAudit(), window.ShieldFin.loadStatus()]);
          } catch (error) { notify(error.message, true); veto.disabled = false; }
        });
        actions.append(veto);
      } else if (rule.status === "PENDING_REVIEW") {
        const approve = document.createElement("button");
        approve.className = "button button-success";
        approve.textContent = "Approuver";
        approve.addEventListener("click", async () => {
          if (!window.confirm(`Appliquer le seuil proposé par ${rule.id} ?`)) return;
          approve.disabled = true;
          try {
            const result = await api(`/api/self-healing/rules/${encodeURIComponent(rule.id)}/approve`, { method: "POST" });
            notify(`Seuil de risque ${result.risk_threshold.toFixed(2)} activé.`);
            await Promise.all([loadRules(), loadAudit(), window.ShieldFin.loadStatus()]);
          } catch (error) { notify(error.message, true); approve.disabled = false; }
        });
        const veto = document.createElement("button");
        veto.className = "button button-danger";
        veto.textContent = "Veto";
        veto.addEventListener("click", async () => {
          if (!window.confirm(`Refuser la règle ${rule.id} ?`)) return;
          veto.disabled = true;
          try {
            await api(`/api/self-healing/rules/${encodeURIComponent(rule.id)}/veto`, { method: "POST" });
            notify(`Règle ${rule.id} refusée.`);
            await Promise.all([loadRules(), loadAudit(), window.ShieldFin.loadStatus()]);
          } catch (error) { notify(error.message, true); veto.disabled = false; }
        });
        actions.append(approve, veto);
      } else {
        actions.textContent = "—";
      }
      row.append(actions);
      body.append(row);
    }
  }

  $("#challenge-form").addEventListener("submit", async (event) => {
    event.preventDefault();
    const button = event.currentTarget.querySelector("button");
    button.disabled = true;
    try {
      const result = await api("/api/client-hub/send-challenge", {
        method: "POST",
        body: JSON.stringify({
          transaction_id: $("#challenge-transaction").value,
          channel: $("#challenge-channel").value,
        }),
      });
      $("#response-challenge-id").value = result.id;
      notify(`${result.delivery_note} Identifiant : ${result.id}`);
      await Promise.all([loadChallenges(), loadAudit()]);
    } catch (error) { notify(error.message, true); }
    finally { button.disabled = false; }
  });

  $("#contact-form").addEventListener("submit", async (event) => {
    event.preventDefault();
    const form = event.currentTarget;
    const button = form.querySelector("button");
    const body = { customer_id: $("#contact-customer-id").value.trim() };
    for (const [field, selector] of [
      ["phone", "#contact-phone"],
      ["telegram_chat_id", "#contact-telegram"],
      ["fcm_token", "#contact-fcm"],
    ]) {
      const value = $(selector).value.trim();
      if (value) body[field] = value;
    }
    button.disabled = true;
    try {
      await api("/api/client-hub/contacts", { method: "PUT", body: JSON.stringify(body) });
      notify("Coordonnées enregistrées chiffrées.");
      form.reset();
    } catch (error) { notify(error.message, true); }
    finally { button.disabled = false; }
  });

  $("#response-form").addEventListener("submit", async (event) => {
    event.preventDefault();
    const button = event.currentTarget.querySelector("button");
    button.disabled = true;
    try {
      const result = await api("/api/client-hub/respond", {
        method: "POST",
        body: JSON.stringify({
          challenge_id: $("#response-challenge-id").value.trim(),
          code: $("#response-code").value.trim(),
          biometric_score: Number($("#response-biometrics").value),
        }),
      });
      const resultBox = $("#challenge-result");
      resultBox.textContent = result.reason;
      resultBox.classList.remove("hidden");
      notify(result.reason, !result.valid);
      if (result.valid) $("#response-code").value = "";
      await Promise.all([loadChallenges(), loadAudit(), window.ShieldFin.loadTransactions(), window.ShieldFin.loadStatus()]);
    } catch (error) { notify(error.message, true); }
    finally { button.disabled = false; }
  });

  $("#refresh-challenges").addEventListener("click", () => loadChallenges().catch((error) => notify(error.message, true)));
  $("#refresh-rules").addEventListener("click", () => loadRules().catch((error) => notify(error.message, true)));
  $("#run-red-team").addEventListener("click", async (event) => {
    const button = event.currentTarget;
    button.disabled = true;
    $("#agent-feed").textContent += "\n[AGENT-5] Simulation locale en cours…";
    try {
      const result = await api("/api/self-healing/red-team-simulation", { method: "POST" });
      $("#agent-feed").textContent += `\n[RED-TEAM] ${result.flagged}/${result.profiles_tested} profils synthétiques signalés (${(result.detection_rate * 100).toFixed(1)}%).`;
      notify("Simulation terminée; aucun trafic réel n'a été émis.");
      await loadAudit();
    } catch (error) { notify(error.message, true); }
    finally { button.disabled = false; }
  });
  $("#federated-sync").addEventListener("click", async (event) => {
    const button = event.currentTarget;
    button.disabled = true;
    try {
      const result = await api("/api/federated/sync", { method: "POST" });
      $("#agent-feed").textContent += `\n[FEDERATED] ${result.message}`;
      notify(result.message);
      await loadAudit();
    } catch (error) { notify(error.message, true); }
    finally { button.disabled = false; }
  });

  window.loadChallenges = loadChallenges;
  Promise.all([loadChallenges(), loadRules()]).catch((error) => notify(error.message, true));
})();