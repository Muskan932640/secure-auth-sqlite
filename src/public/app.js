
"use strict";

document.addEventListener("DOMContentLoaded", () => {
  const $ = (id) => document.getElementById(id);

  const registerTab = $("registerTab");
  const loginTab = $("loginTab");
  const authForm = $("authForm");
  const nameInput = $("name");
  const nameGroup = $("nameGroup");
  const emailInput = $("email");
  const passwordInput = $("password");
  const submitBtn = $("submitBtn");
  const message = $("message");
  const authSection = $("authSection");
  const accountSection = $("accountSection");
  const accountName = $("accountName");
  const accountEmail = $("accountEmail");
  const logoutBtn = $("logoutBtn");

  let mode = "register";
  let busy = false;

  function showMessage(text, type = "error") {
    message.textContent = text;
    message.className = `message visible ${type}`;
  }

  function clearMessage() {
    message.textContent = "";
    message.className = "message";
  }

  function setMode(newMode) {
    mode = newMode;
    const registering = mode === "register";

    registerTab.classList.toggle("active", registering);
    loginTab.classList.toggle("active", !registering);

    nameGroup.classList.toggle("hidden", !registering);
    nameInput.required = registering;

    passwordInput.autocomplete = registering
      ? "new-password"
      : "current-password";

    submitBtn.textContent = registering
      ? "Create Account"
      : "Login";

    clearMessage();
  }

  async function request(url, options = {}) {
    const response = await fetch(url, {
      ...options,
      credentials: "same-origin",
      headers: {
        "Content-Type": "application/json",
        ...(options.headers || {})
      }
    });

    const data = await response.json().catch(() => ({}));

    if (!response.ok) {
      throw new Error(
        data.message || data.error || `Request failed (${response.status})`
      );
    }

    return data;
  }

  function showAuth() {
    authSection.classList.remove("hidden");
    accountSection.classList.add("hidden");
  }

  function showAccount(user) {
    authSection.classList.add("hidden");
    accountSection.classList.remove("hidden");

    accountName.textContent = `Name: ${user.name || "User"}`;
    accountEmail.textContent = `Email: ${user.email || ""}`;
  }

  registerTab.addEventListener("click", () => setMode("register"));
  loginTab.addEventListener("click", () => setMode("login"));

  authForm.addEventListener("submit", async (event) => {
    event.preventDefault();

    if (busy) return;

    if (!authForm.reportValidity()) return;

    busy = true;
    submitBtn.disabled = true;
    submitBtn.textContent = "Please wait...";
    clearMessage();

    const payload = {
      email: emailInput.value.trim(),
      password: passwordInput.value
    };

    if (mode === "register") {
      payload.name = nameInput.value.trim();

      if (!payload.name) {
        showMessage("Please enter your full name.");
        busy = false;
        submitBtn.disabled = false;
        submitBtn.textContent = "Create Account";
        return;
      }
    }

    try {
      const data = await request(`/api/${mode}`, {
        method: "POST",
        body: JSON.stringify(payload)
      });

      if (mode === "register") {
        passwordInput.value = "";
        setMode("login");
        showMessage(
          data.message || "Registration successful. Please log in.",
          "success"
        );
      } else {
        await refreshAccount();

        if (!accountSection.classList.contains("hidden")) {
          showMessage(
            data.message || "Login successful.",
            "success"
          );
        } else {
          showMessage("Login response received, but account details were not returned.");
        }
      }
    } catch (error) {
      showMessage(error.message || "Unable to complete the request.");
    } finally {
      busy = false;
      submitBtn.disabled = false;
      submitBtn.textContent = mode === "register"
        ? "Create Account"
        : "Login";
    }
  });

  async function refreshAccount() {
    try {
      const data = await request("/api/me", { method: "GET" });
      const user = data.user || data;

      if (user && user.email) {
        showAccount(user);
      } else {
        showAuth();
      }
    } catch {
      showAuth();
    }
  }

  logoutBtn.addEventListener("click", async () => {
    if (busy) return;

    busy = true;
    logoutBtn.disabled = true;
    clearMessage();

    try {
      const data = await request("/api/logout", {
        method: "POST",
        body: JSON.stringify({})
      });

      authForm.reset();
      showAuth();
      setMode("login");
      showMessage(data.message || "Logged out successfully.", "success");
    } catch (error) {
      showMessage(error.message || "Logout failed.");
    } finally {
      busy = false;
      logoutBtn.disabled = false;
    }
  });

  setMode("register");
  refreshAccount();
});
