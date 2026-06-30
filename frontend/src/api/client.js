/**
 * api.js - a thin wrapper around the backend's REST API.
 *
 * Every function here corresponds to one endpoint we already built and
 * tested with curl in the backend. Keeping all fetch() calls in one file
 * means components never construct URLs themselves - if an endpoint path
 * ever changes, there's exactly one place to update it.
 */

const BASE = "/api";

async function request(path, options = {}) {
  const res = await fetch(`${BASE}${path}`, {
    headers: { "Content-Type": "application/json", ...options.headers },
    ...options,
  });

  if (!res.ok) {
    let detail = `Request failed (${res.status})`;
    try {
      const body = await res.json();
      detail = body.detail || detail;
    } catch {
      // response wasn't JSON - keep the generic message
    }
    throw new Error(detail);
  }

  // Some endpoints (like /scan) return a small confirmation object;
  // all of them return JSON, so this is safe across the board.
  return res.json();
}

export const api = {
  // Projects
  listProjects: () => request("/projects"),
  getProject: (id) => request(`/projects/${id}`),
  createProject: (name, platform) =>
    request("/projects", { method: "POST", body: JSON.stringify({ name, platform }) }),

  // Scope
  listScope: (projectId) => request(`/projects/${projectId}/scope`),
  addScopeTarget: (projectId, target) =>
    request(`/projects/${projectId}/scope`, { method: "POST", body: JSON.stringify(target) }),

  // Scope intake (AI-assisted)
  parseScopeText: (platform, rawText) =>
    request("/scope/parse-text", {
      method: "POST",
      body: JSON.stringify({ platform, raw_text: rawText }),
    }),
  confirmScope: (payload) =>
    request("/scope/confirm", { method: "POST", body: JSON.stringify(payload) }),

  // Pipeline
  startScan: (projectId) => request(`/projects/${projectId}/scan`, { method: "POST" }),
  listPhaseRuns: (projectId) => request(`/projects/${projectId}/phase-runs`),

  // Findings
  listFindings: (projectId) => request(`/projects/${projectId}/findings`),

  // Triage
  triageFinding: (findingId) => request(`/findings/${findingId}/triage`, { method: "POST" }),
  triageAll: (projectId) => request(`/projects/${projectId}/triage-all`, { method: "POST" }),

  // Readiness
  getReadiness: (findingId) => request(`/findings/${findingId}/readiness`),

  // Outcomes
  logOutcome: (payload) => request("/outcomes", { method: "POST", body: JSON.stringify(payload) }),
  getSignatureStats: (signature) =>
    request(`/outcomes/signature-stats${signature ? `?signature=${encodeURIComponent(signature)}` : ""}`),

  // Health
  health: () => request("/health"),
};
