/**
 * LOOK Account storage — on-device encrypted history + profile.
 * Providers: local passphrase, or Google Identity (key derived from Google sub).
 * Face scan images from LOOK are never stored or uploaded.
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

function defaultProfile(seed) {
  return {
    displayName: (seed && seed.displayName) || "Looker",
    bio: "",
    pronouns: "",
    goal: "",
    location: "",
    website: "",
    avatarDataUrl: (seed && seed.avatarDataUrl) || "",
    avatarRemoteUrl: (seed && seed.avatarRemoteUrl) || "",
    accent: "mint",
    updatedAt: Date.now()
  };
}

export async function vaultExists() {
  const meta = await idbGet(STORE, "account");
  return !!(meta && meta.salt);
}

/** Public metadata only (no secrets). Safe before unlock. */
export async function getVaultMeta() {
  const meta = await idbGet(STORE, "account");
  if (!meta || !meta.salt) return null;
  return {
    displayName: meta.displayName || "Account",
    createdAt: meta.createdAt || null,
    provider: meta.provider || "local",
    email: meta.email || "",
    avatarPublic: meta.avatarPublic || "",
    googleSub: meta.googleSub || null
  };
}

async function writeAccountMeta(partial) {
  const meta = (await idbGet(STORE, "account")) || {};
  const next = { ...meta, ...partial };
  await idbSet(STORE, "account", next);
  return next;
}

export async function createVault(displayName, passphrase, profileExtras) {
  if (!displayName || displayName.trim().length < 1) throw new Error("Enter a display name.");
  if (!passphrase || passphrase.length < 8) throw new Error("Passphrase must be at least 8 characters.");
  if (await vaultExists()) throw new Error("An account already exists on this device. Log in instead.");
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const key = await deriveKey(passphrase, salt);
  const profile = defaultProfile({
    displayName: displayName.trim().slice(0, 40),
    ...(profileExtras || {})
  });
  const check = await encryptJson(key, { ok: true, created: Date.now() });
  const profileEnc = await encryptJson(key, profile);
  await idbSet(STORE, "account", {
    displayName: profile.displayName,
    salt: bufToB64(salt),
    check,
    profileEnc,
    avatarPublic: profile.avatarDataUrl || profile.avatarRemoteUrl || "",
    provider: "local",
    email: "",
    createdAt: Date.now()
  });
  return { displayName: profile.displayName, key, profile, provider: "local" };
}

export async function unlockVault(passphrase) {
  const meta = await idbGet(STORE, "account");
  if (!meta || !meta.salt) throw new Error("No account on this device yet.");
  if (meta.provider === "google") {
    throw new Error("This account uses Google. Tap Continue with Google to log in.");
  }
  const key = await deriveKey(passphrase, b64ToBuf(meta.salt));
  try {
    await decryptJson(key, meta.check);
  } catch (_) {
    throw new Error("Wrong passphrase.");
  }
  const profile = meta.profileEnc
    ? await decryptJson(key, meta.profileEnc)
    : defaultProfile({ displayName: meta.displayName });
  return {
    displayName: profile.displayName || meta.displayName,
    key,
    profile,
    provider: meta.provider || "local",
    email: meta.email || ""
  };
}

/** Create or unlock using Google subject id (from verified GIS credential). */
export async function loginWithGoogleIdentity(identity) {
  if (!identity || !identity.sub) throw new Error("Google sign-in did not return a user id.");
  const material = "look-google-v1:" + identity.sub;
  const exists = await vaultExists();
  const meta = exists ? await idbGet(STORE, "account") : null;

  if (exists && meta) {
    if (meta.provider !== "google" || meta.googleSub !== identity.sub) {
      throw new Error(
        "This device already has a different LOOK account. Export a backup, then clear account data to switch."
      );
    }
    const key = await deriveKey(material, b64ToBuf(meta.salt));
    try {
      await decryptJson(key, meta.check);
    } catch (_) {
      throw new Error("Could not unlock Google account on this device.");
    }
    let profile = meta.profileEnc
      ? await decryptJson(key, meta.profileEnc)
      : defaultProfile({
          displayName: identity.name || meta.displayName,
          avatarRemoteUrl: identity.picture || ""
        });
    // Refresh remote avatar / email hints without wiping custom avatar
    if (identity.picture && !profile.avatarDataUrl) profile.avatarRemoteUrl = identity.picture;
    if (identity.name && !profile.displayName) profile.displayName = identity.name;
    await writeAccountMeta({
      displayName: profile.displayName,
      email: identity.email || meta.email || "",
      avatarPublic: profile.avatarDataUrl || profile.avatarRemoteUrl || meta.avatarPublic || "",
      profileEnc: await encryptJson(key, profile)
    });
    return {
      displayName: profile.displayName,
      key,
      profile,
      provider: "google",
      email: identity.email || meta.email || ""
    };
  }

  const salt = crypto.getRandomValues(new Uint8Array(16));
  const key = await deriveKey(material, salt);
  const profile = defaultProfile({
    displayName: (identity.name || "Looker").slice(0, 40),
    avatarRemoteUrl: identity.picture || ""
  });
  const check = await encryptJson(key, { ok: true, created: Date.now(), provider: "google" });
  const profileEnc = await encryptJson(key, profile);
  await idbSet(STORE, "account", {
    displayName: profile.displayName,
    salt: bufToB64(salt),
    check,
    profileEnc,
    avatarPublic: profile.avatarRemoteUrl || "",
    provider: "google",
    googleSub: identity.sub,
    email: identity.email || "",
    createdAt: Date.now()
  });
  return {
    displayName: profile.displayName,
    key,
    profile,
    provider: "google",
    email: identity.email || ""
  };
}

export async function saveProfile(key, profile) {
  const clean = {
    ...defaultProfile(),
    ...profile,
    displayName: String(profile.displayName || "Looker").trim().slice(0, 40),
    bio: String(profile.bio || "").slice(0, 280),
    pronouns: String(profile.pronouns || "").slice(0, 40),
    goal: String(profile.goal || "").slice(0, 120),
    location: String(profile.location || "").slice(0, 80),
    website: String(profile.website || "").slice(0, 120),
    avatarDataUrl: profile.avatarDataUrl || "",
    avatarRemoteUrl: profile.avatarRemoteUrl || "",
    accent: profile.accent === "amber" || profile.accent === "foam" ? profile.accent : "mint",
    updatedAt: Date.now()
  };
  // Keep avatars reasonable for IndexedDB
  if (clean.avatarDataUrl && clean.avatarDataUrl.length > 900000) {
    throw new Error("Profile photo is too large. Try a smaller image.");
  }
  const profileEnc = await encryptJson(key, clean);
  await writeAccountMeta({
    displayName: clean.displayName,
    avatarPublic: clean.avatarDataUrl || clean.avatarRemoteUrl || "",
    profileEnc
  });
  return clean;
}

export async function saveScan(key, plan) {
  const record = {
    score: plan.score,
    sym: plan.sym,
    prop: plan.prop,
    harm: plan.harm,
    smile: plan.smile,
    label: plan.label,
    tier: plan.tier,
    tierLabel: plan.tierLabel,
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
    version: 2,
    exportedAt: Date.now(),
    notice: "LOOK Account encrypted backup — keep offline. Contains no LOOK face scans.",
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

/** Decode GIS credential JWT payload (browser-side; identity still comes from Google). */
export function decodeGoogleCredential(credential) {
  if (!credential || typeof credential !== "string") throw new Error("Missing Google credential.");
  const parts = credential.split(".");
  if (parts.length < 2) throw new Error("Invalid Google credential.");
  const json = atob(parts[1].replace(/-/g, "+").replace(/_/g, "/"));
  const payload = JSON.parse(json);
  if (!payload.sub) throw new Error("Google credential missing subject.");
  return {
    sub: payload.sub,
    email: payload.email || "",
    name: payload.name || payload.given_name || "",
    picture: payload.picture || "",
    emailVerified: !!payload.email_verified
  };
}
