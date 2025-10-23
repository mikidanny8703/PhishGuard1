document.addEventListener("DOMContentLoaded", () => {
  const year = document.getElementById("year");
  if (year) year.textContent = new Date().getFullYear();

  const form = document.getElementById("urlScanForm");
  const resultDiv = document.getElementById("scanResult");
  const firewallMsg = document.getElementById("firewallMessage");
  const input = document.getElementById("urlInput");

  form.addEventListener("submit", async (e) => {
    e.preventDefault();
    const url = input.value.trim();
    if (!url) return;

    resultDiv.classList.remove("hidden");
    firewallMsg.classList.add("hidden");
    resultDiv.textContent = "🔍 Scanning... Please wait...";

    try {
      const res = await fetch("/predict", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url })
      });

      const data = await res.json();
      const result = data.result;
      const honeypotStatus = data.honeypot;

      if (result === "Phishing") {
        resultDiv.innerHTML = `⚠️ <span class="text-red-600">${result}</span> URL detected.`;
        firewallMsg.classList.remove("hidden");
        firewallMsg.innerHTML = `🛡️ Honeypot Firewall Activated. Suspicious activity logged and blocked.`;
      } else {
        resultDiv.innerHTML = `✅ <span class="text-green-600">${result}</span> — This website is safe.`;
      }
    } catch (err) {
      console.error(err);
      resultDiv.textContent = "❌ Unable to connect to detection server.";
    }
  });
});
