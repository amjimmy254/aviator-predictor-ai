
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>GoalWise AI | Owner Dashboard</title>
<style>
body {
  margin: 0;
  background: #090b12;
  color: #f4f6fb;
  font-family: Arial, sans-serif;
  padding: 25px;
}
.container {
  max-width: 850px;
  margin: 40px auto;
}
.panel {
  background: #121622;
  border: 1px solid #293143;
  padding: 25px;
  border-radius: 15px;
  margin-top: 20px;
}
input {
  display: block;
  width: 100%;
  box-sizing: border-box;
  padding: 14px;
  margin: 12px 0;
  background: #090b12;
  color: white;
  border: 1px solid #293143;
  border-radius: 8px;
}
button {
  padding: 13px 20px;
  background: #ff405b;
  color: white;
  border: 0;
  border-radius: 8px;
  cursor: pointer;
  font-weight: bold;
}
.secondary {
  background: #293143;
}
.hidden {
  display: none;
}
.message {
  color: #9ca6ba;
  margin-top: 15px;
  line-height: 1.6;
}
table {
  width: 100%;
  border-collapse: collapse;
  margin-top: 20px;
  font-size: 13px;
}
td, th {
  padding: 12px;
  border-bottom: 1px solid #293143;
  text-align: left;
}
.tablewrap {
  overflow-x: auto;
}
h1 { color: #ff405b; }
</style>
</head>

<body>
<div class="container">

<h1>GOALWISE AI</h1>
<p>Private Owner Administration</p>

<div class="panel" id="loginPanel">
  <h2>Administrator Login</h2>

  <input id="email" type="email"
    placeholder="Administrator email"
    autocomplete="username">

  <input id="password" type="password"
    placeholder="Administrator password"
    autocomplete="current-password">

  <button id="loginButton" onclick="login()">
    Sign In
  </button>

  <div class="message" id="message"></div>
</div>

<div class="panel hidden" id="dashboard">
  <h2>Owner Dashboard</h2>

  <div id="overview" class="message">
    Loading...
  </div>

  <button class="secondary" onclick="logout()">
    Sign Out
  </button>
</div>

</div>

<script>
let token = null;

async function login() {
  const email = document.getElementById("email").value.trim();
  const password = document.getElementById("password").value;
  const msg = document.getElementById("message");
  const btn = document.getElementById("loginButton");

  if (!email || !password) {
    msg.textContent = "Enter your email and password.";
    return;
  }

  btn.disabled = true;
  msg.textContent = "Signing in...";

  try {
    const response = await fetch("/api/admin/login", {
      method: "POST",
      headers: {
        "Content-Type": "application/json"
      },
      body: JSON.stringify({ email, password })
    });

    const data = await response.json();

    if (!response.ok) {
      throw new Error(data.error || "Login failed.");
    }

    if (!data.token) {
      throw new Error("No authentication token received.");
    }

    token = data.token;

    await loadDashboard();

  } catch (error) {
    msg.textContent = error.message;
  } finally {
    btn.disabled = false;
  }
}

async function loadDashboard() {
  const response = await fetch("/api/admin/overview", {
    headers: {
      Authorization: "Bearer " + token
    }
  });

  const data = await response.json();

  if (!response.ok) {
    throw new Error(data.error || "Unable to load dashboard.");
  }

  document.getElementById("loginPanel").classList.add("hidden");
  document.getElementById("dashboard").classList.remove("hidden");

  const totals = data.totals || {};
  const transactions = data.recent || [];

  document.getElementById("overview").innerHTML = `
    <h3>Payment Overview</h3>
    <p><strong>Total collections:</strong> KSh ${Number(totals.grossCollected || 0).toLocaleString()}</p>
    <p><strong>Total transactions:</strong> ${Number(totals.transactions || 0)}</p>
    <p><strong>Pending payments:</strong> ${Number(totals.pendingPayments || 0)}</p>

    <h3>Recent Transactions</h3>

    <div class="tablewrap">
    <table>
      <thead>
        <tr>
          <th>Phone</th>
          <th>Amount</th>
          <th>Package</th>
          <th>Status</th>
          <th>Receipt</th>
        </tr>
      </thead>
      <tbody>
        ${transactions.map(x => `
          <tr>
            <td>${escapeHTML(x.phone)}</td>
            <td>KSh ${escapeHTML(x.amount)}</td>
            <td>${escapeHTML(x.package_code)}</td>
            <td>${escapeHTML(x.status)}</td>
            <td>${escapeHTML(x.mpesa_receipt || "-")}</td>
          </tr>
        `).join("")}
      </tbody>
    </table>
    </div>
  `;
}

function escapeHTML(value) {
  return String(value ?? "").replace(/[&<>"']/g, c => ({
    "&": "&amp;",
    "<": "&lt;",
    ">": "&gt;",
    '"': "&quot;",
    "'": "&#39;"
  })[c]);
}

function logout() {
  token = null;

  document.getElementById("loginPanel").classList.remove("hidden");
  document.getElementById("dashboard").classList.add("hidden");
  document.getElementById("password").value = "";
  document.getElementById("message").textContent = "You have signed out.";
  document.getElementById("overview").innerHTML = "";
}
</script>
</body>
</html>
