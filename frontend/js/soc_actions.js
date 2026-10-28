(() => {
  const { api, notify, loadTransactions, loadStatus, loadAudit } = window.ShieldFin;
  document.querySelector("#transactions-body").addEventListener("click", async (event) => {
    const button = event.target.closest("button[data-action]");
    if (!button) return;
    button.disabled = true;
    try {
      const result = await api("/api/soc/action", {
        method: "POST",
        body: JSON.stringify({
          transaction_id: button.dataset.transactionId,
          action: button.dataset.action,
          channel: "FCM",
        }),
      });
      if (result.challenge) {
        document.querySelector("#response-challenge-id").value = result.challenge.id;
        notify(`Défi créé (${result.challenge.status}). ${result.challenge.delivery_note}`);
      } else {
        notify(`Transaction ${result.transaction.id}: ${result.transaction.status}.`);
      }
      await Promise.all([loadTransactions(), loadStatus(), loadAudit()]);
    } catch (error) {
      notify(error.message, true);
      button.disabled = false;
    }
  });
})();