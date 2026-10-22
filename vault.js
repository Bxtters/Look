/**
 * LOOK Account storage — on-device encrypted history.
 * UI calls this "Account". No network calls.
 * Passphrase → PBKDF2 key → AES-GCM. Face images are never stored.
 */

const DB_NAME = "look-vault-v1";
const STORE = "meta";
const HISTORY = "history";

function openDb() {
  return new Promise((resolve, reject) => {
    const req = indexedDB.open(DB_NAME, 1);
    req.onupgradeneeded = () => {
      const db = req.result;
      if (!db.objectStoreNames.contains(STORE)) db.createObjectStore(STORE);
      if (!db.objectStoreNames.contains(HISTORY)) {
        const hs = db.createObjectStore(HISTORY, { keyPath: "id", autoIncrement: true });
        hs.createIndex("at", "at");
      }
    };
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });
}

function idbGet(store, key) {
  return openDb().then(
    (db) =>
      new Promise((resolve, reject) => {
        const tx = db.transaction(store, "readonly");
        const r = tx.objectStore(store).get(key);
        r.onsuccess = () => resolve(r.result);
        r.onerror = () => reject(r.error);
      })
  );
}

function idbSet(store, key, value) {
  return openDb().then(
    (db) =>
      new Promise((resolve, reject) => {
        const tx = db.transaction(store, "readwrite");
        const os = tx.objectStore(store);
        const r = key === undefined ? os.put(value) : os.put(value, key);
        r.onsuccess = () => resolve(r.result);
        r.onerror = () => reject(r.error);
      })
  );
}

function idbAdd(store, value) {
  return openDb().then(
    (db) =>
      new Promise((resolve, reject) => {
        const tx = db.transaction(store, "readwrite");
        const r = tx.objectStore(store).add(value);
        r.onsuccess = () => resolve(r.result);
        r.onerror = () => reject(r.error);
      })
  );
}

function idbGetAll(store) {
  return openDb().then(
    (db) =>
      new Promise((resolve, reject) => {
        const tx = db.transaction(store, "readonly");
        const r = tx.objectStore(store).getAll();
        r.onsuccess = () => resolve(r.result || []);
        r.onerror = () => reject(r.error);
      })
  );
}

function bufToB64(buf) {
  const bytes = new Uint8Array(buf);
  let s = "";
  for (let i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
  return btoa(s);
}

function b64ToBuf(b64) {
  const s = atob(b64);
  const bytes = new Uint8Array(s.length);
  for (let i = 0; i < s.length; i++) bytes[i] = s.charCodeAt(i);
  return bytes.buffer;
}

async function deriveKey(passphrase, saltBuf) {
  const enc = new TextEncoder();
  const base = await crypto.subtle.importKey("raw", enc.encode(passphrase), "PBKDF2", false, [
    "deriveKey"
  ]);
  return crypto.subtle.deriveKey(
    { name: "PBKDF2", salt: saltBuf, iterations: 210000, hash: "SHA-256" },
    base,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"]
  );
}

async function encryptJson(key, obj) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const plain = new TextEncoder().encode(JSON.stringify(obj));
  const cipher = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, plain);
  return { iv: bufToB64(iv), data: bufToB64(cipher) };
}

async function decryptJson(key, payload) {
  const iv = new Uint8Array(b64ToBuf(payload.iv));
  const data = b64ToBuf(payload.data);
  const plain = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, data);
  return JSON.parse(new TextDecoder().decode(plain));
}

export async function vaultExists() {
  const meta = await idbGet(STORE, "account");
  return !!(meta && meta.salt);
}

/** Public metadata only (no secrets). Safe before unlock. */
export async function getVaultMeta() {
  const meta = await idbGet(STORE, "account");
  if (!meta || !meta.salt) return null;
  return { displayName: meta.displayName || "Account", createdAt: meta.createdAt || null };
}

export async function createVault(displayName, passphrase) {
  if (!displayName || displayName.trim().length < 1) throw new Error("Enter a display name.");
  if (!passphrase || passphrase.length < 8) throw new Error("Passphrase must be at least 8 characters.");
  if (await vaultExists()) throw new Error("An account already exists on this device. Unlock it instead.");
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const key = await deriveKey(passphrase, salt);
  const check = await encryptJson(key, { ok: true, created: Date.now() });
  await idbSet(STORE, "account", {
    displayName: displayName.trim().slice(0, 40),
    salt: bufToB64(salt),
    check,
    createdAt: Date.now()
  });
  return { displayName: displayName.trim().slice(0, 40), key };
}

export async function unlockVault(passphrase) {
  const meta = await idbGet(STORE, "account");
  if (!meta || !meta.salt) throw new Error("No account on this device yet.");
  const key = await deriveKey(passphrase, b64ToBuf(meta.salt));
  try {
    await decryptJson(key, meta.check);
  } catch (_) {
    throw new Error("Wrong passphrase.");
  }
  return { displayName: meta.displayName, key };
}

export async function saveScan(key, plan) {
  // Strip anything that could be image-like; store scores + plan text only
  const record = {
    score: plan.score,
    sym: plan.sym,
    prop: plan.prop,
    harm: plan.harm,
    smile: plan.smile,
    label: plan.label,
    summary: plan.summary,
    narrative: plan.narrative,
    focuses: plan.focuses,
    tips: plan.tips,
    days: plan.days,
    lift: plan.lift,
    at: Date.now()
  };
  const enc = await encryptJson(key, record);
  await idbAdd(HISTORY, { at: record.at, enc });
  return record;
}

export async function listScans(key) {
  const rows = await idbGetAll(HISTORY);
  const out = [];
  for (const row of rows) {
    try {
      const rec = await decryptJson(key, row.enc);
      out.push({ id: row.id, ...rec });
    } catch (_) {
      /* skip undecryptable */
    }
  }
  out.sort((a, b) => b.at - a.at);
  return out;
}

export async function exportEncryptedBackup() {
  const meta = await idbGet(STORE, "account");
  const rows = await idbGetAll(HISTORY);
  return {
    version: 1,
    exportedAt: Date.now(),
    notice: "LOOK Account encrypted backup — keep offline. Contains no face images.",
    account: meta,
    history: rows
  };
}

export async function clearVault() {
  const db = await openDb();
  return new Promise((resolve, reject) => {
    const tx = db.transaction([STORE, HISTORY], "readwrite");
    tx.objectStore(STORE).clear();
    tx.objectStore(HISTORY).clear();
    tx.oncomplete = () => resolve();
    tx.onerror = () => reject(tx.error);
  });
}
