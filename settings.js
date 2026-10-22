/**
 * LOOK Settings — local UX preferences (no network).
 * Stored in localStorage; optional merge when an account is unlocked.
 */

const KEY = "look.settings.v1";

export const DEFAULTS = {
  chartWeeks: 4,
  showProducts: true,
  showCitations: true,
  tipDetail: "full", // full | brief
  autoExpandPlan: true,
  showMesh: true,
  reduceMotion: false,
  autoSaveAccount: false,
  scoreDecimals: 1, // 0 | 1
  compactPlan: false,
  showFoundation: true,
  showGraph: true,
  planTone: "coach" // coach | clinical
};

export function loadSettings() {
  try {
    const raw = JSON.parse(localStorage.getItem(KEY) || "null");
    if (!raw || typeof raw !== "object") return { ...DEFAULTS };
    return normalize({ ...DEFAULTS, ...raw });
  } catch (_) {
    return { ...DEFAULTS };
  }
}

export function saveSettings(partial) {
  const next = normalize({ ...loadSettings(), ...partial });
  localStorage.setItem(KEY, JSON.stringify(next));
  return next;
}

export function resetSettings() {
  localStorage.setItem(KEY, JSON.stringify({ ...DEFAULTS }));
  return { ...DEFAULTS };
}

function normalize(s) {
  const weeks = Number(s.chartWeeks);
  s.chartWeeks = weeks === 2 || weeks === 12 ? weeks : 4;
  s.showProducts = !!s.showProducts;
  s.showCitations = !!s.showCitations;
  s.tipDetail = s.tipDetail === "brief" ? "brief" : "full";
  s.autoExpandPlan = !!s.autoExpandPlan;
  s.showMesh = !!s.showMesh;
  s.reduceMotion = !!s.reduceMotion;
  s.autoSaveAccount = !!s.autoSaveAccount;
  s.scoreDecimals = Number(s.scoreDecimals) === 0 ? 0 : 1;
  s.compactPlan = !!s.compactPlan;
  s.showFoundation = !!s.showFoundation;
  s.showGraph = !!s.showGraph;
  s.planTone = s.planTone === "clinical" ? "clinical" : "coach";
  return s;
}

/** Apply document-level flags from settings. */
export function applyDocumentSettings(settings) {
  const s = settings || loadSettings();
  document.documentElement.dataset.tipDetail = s.tipDetail;
  document.documentElement.dataset.planTone = s.planTone;
  document.body.classList.toggle("hide-products", !s.showProducts);
  document.body.classList.toggle("hide-citations", !s.showCitations);
  document.body.classList.toggle("reduce-motion", s.reduceMotion);
  document.body.classList.toggle("hide-foundation", !s.showFoundation);
  document.body.classList.toggle("hide-graph", !s.showGraph);
  document.body.classList.toggle("compact-plan", s.compactPlan);
  return s;
}

export function formatScore(n, decimals) {
  const d = Number(decimals) === 0 ? 0 : 1;
  const factor = Math.pow(10, d);
  return (Math.round(Number(n) * factor) / factor).toFixed(d);
}
