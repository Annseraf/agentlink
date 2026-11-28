"use strict";

const el = (id) => document.getElementById(id);
const panels = ["login", "overview", "people", "cloud", "guide", "account"];
let user;
let accessChange;

function notice(id, text = "") {
  el(id).textContent = text;
  el(id).hidden = !text;
}

function show(panel) {
  if (panel !== "cloud") el("cloud-pair").reset();
  for (const name of panels) el(name).hidden = name !== panel;
  el("navigation").hidden = !user || user.must_change;
  el("cloud-link").hidden = user?.role !== "admin";
  el("people-link").hidden = user?.role !== "admin";
  for (const button of el("navigation").querySelectorAll("[data-panel]")) {
    if (button.dataset.panel === panel) button.setAttribute("aria-current", "page");
    else button.removeAttribute("aria-current");
  }
  el(panel).querySelector("h1").focus();
}

async function api(path, data) {
  const response = await fetch(path, data === undefined ? undefined : {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(data),
  });
  if (!response.ok) {
    const body = await response.json().catch(() => ({}));
    const error = new Error(body.error || "AgentLink could not complete the request.");
    error.status = response.status;
    throw error;
  }
  return response.status === 204 ? undefined : response.json();
}

function report(error, target = "error") {
  if (error.status === 401 && user) {
    if (el("confirm").open) el("confirm").close();
    user = undefined;
    show("login");
    notice("error", "Your session ended. Sign in again.");
  } else {
    notice(target, error.message);
  }
}

async function loadSession() {
  try {
    user = await api("/api/session");
  } catch (error) {
    if (error.status !== 401) throw error;
    user = undefined;
    show("login");
    return;
  }
  el("identity").textContent = `Signed in as ${user.email} (${user.role}).`;
  el("account-note").textContent = user.must_change
    ? "Change your temporary password to continue."
    : "Changing your password signs out all sessions for this account.";
  show(user.must_change ? "account" : "overview");
}

function accessButton(person, action, title, description) {
  const button = document.createElement("button");
  button.type = "button";
  button.className = "quiet";
  button.textContent = title;
  button.setAttribute("aria-label", `${title} for ${person.email}`);
  button.addEventListener("click", () => {
    accessChange = { person, action };
    el("confirm-title").textContent = `${title} for ${person.email}?`;
    el("confirm-note").textContent = description;
    el("confirm-button").textContent = title;
    el("confirm-form").reset();
    notice("confirm-error");
    const needsPassword = action === "reset_password" || action === "enable";
    el("reset-field").hidden = !needsPassword;
    el("confirm-form").elements.password.required = needsPassword;
    el("confirm").showModal();
  });
  return button;
}

async function loadPeople() {
  const people = await api("/api/people");
  const rows = people.map((person) => {
    const row = document.createElement("article");
    row.className = "account-row";
    const heading = document.createElement("h2");
    heading.textContent = person.email;
    const details = document.createElement("p");
    const role = person.role === "admin" ? "Admin" : "Member";
    const state = person.active ? "Active" : "Access removed";
    details.textContent = `${role} · ${state}${person.active && person.must_change ? " · Password change required" : ""}`;
    row.append(heading, details);
    const actions = document.createElement("div");
    actions.className = "actions";
    if (person.active) {
      actions.append(
        accessButton(person, "revoke_sessions", "Revoke sessions", "Sign this person out everywhere. They can sign in again with their current password."),
        accessButton(person, "reset_password", "Reset password", "Sign this person out and replace their password. Give them the temporary password privately."),
        accessButton(person, "disable", "Remove access", "Sign this person out and block future sign-ins.")
      );
    } else {
      actions.append(accessButton(
        person, "enable", "Restore access",
        "Restore this person's role and sign-in access. Give them the new temporary password privately."
      ));
    }
    row.append(actions);
    return row;
  });
  el("accounts").replaceChildren(...rows);
}

function form(id, handler, errorTarget = "error") {
  el(id).addEventListener("submit", async (event) => {
    event.preventDefault();
    const form = event.currentTarget;
    const button = form.querySelector("button:not([type=button])");
    button.disabled = true;
    notice(errorTarget);
    notice("status");
    try {
      await handler(Object.fromEntries(new FormData(form)), form);
    } catch (error) {
      report(error, errorTarget);
    } finally {
      button.disabled = false;
    }
  });
}

let cloudOrigin;
async function loadCloud() {
  const { origin, state, hosted } = await api("/api/cloud");
  cloudOrigin = origin;
  el("cloud-status").textContent = `${origin || "Cloud origin is not configured"} · ${state} · Hosted features ${hosted ? "available" : "off"}`;
  const canPair = ["unpaired", "pairing denied", "revoked"].includes(state);
  el("cloud-pair").hidden = !origin || !canPair;
  el("cloud-help").hidden = state === "unpaired";
  el("cloud-disconnect").hidden = state === "unpaired";
}
form("cloud-pair", async ({ name, proof, consent }, form) => {
  try {
    await api("/api/cloud/pair", { origin: cloudOrigin, name, proof, consent: consent === "on" });
  } finally {
    form.reset();
  }
  await loadCloud();
});
el("cloud-refresh").addEventListener("click", () => loadCloud().catch(report));
el("cloud-disconnect").addEventListener("click", async () => {
  try {
    await api("/api/cloud/disconnect", {});
    await loadCloud();
  } catch (error) { report(error); }
});

form("login-form", async (data, form) => {
  try { await api("/api/session", data); }
  finally { form.elements.password.value = ""; }
  await loadSession();
});
form("password-form", async (data, form) => {
  await api("/api/account/password", data);
  form.reset();
  user = undefined;
  show("login");
  notice("status", "Password changed. Sign in with your new password.");
});
form("add-form", async (data, form) => {
  const person = await api("/api/people", data);
  form.reset();
  await loadPeople();
  notice("status", `${person.email} can sign in and change their temporary password. Share it privately.`);
}, "add-error");
form("confirm-form", async ({ password }) => {
  const { person, action } = accessChange;
  await api(`/api/people/${person.id}/access`, { action, password });
  el("confirm").close();
  if (person.id === user.id) {
    user = undefined;
    show("login");
    notice("status", "Your session ended.");
  } else {
    await loadPeople();
    el("people").querySelector("h1").focus();
    notice("status", `Access updated for ${person.email}.`);
  }
}, "confirm-error");

el("cancel").addEventListener("click", () => el("confirm").close());
el("confirm").addEventListener("close", () => el("confirm-form").reset());
el("sign-out").addEventListener("click", async () => {
  try {
    await api("/api/session/logout", {});
    el("password-form").reset();
    user = undefined;
    show("login");
    notice("status", "Signed out.");
  } catch (error) {
    report(error);
  }
});

for (const button of document.querySelectorAll("[data-panel]")) {
  button.addEventListener("click", async () => {
    notice("status");
    notice("error");
    try {
      if (button.dataset.panel === "cloud") await loadCloud();
      if (button.dataset.panel === "people") await loadPeople();
      show(button.dataset.panel);
    } catch (error) {
      report(error);
    }
  });
}

loadSession().catch(report).finally(() => notice("status"));
