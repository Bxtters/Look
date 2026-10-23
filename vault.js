/**
 * LOOK multi-account storage — on-device encrypted history + profile.
 * Many accounts per device; Google users get a per-device vault keyed by Google sub
 * so the same Google identity can sign in on multiple devices independently.
 * Face scan images from LOOK are never stored or uploaded.
 */

const DB_NAME = "look-vault-v2";
const ACCOUNTS = "accounts";
const HISTORY = "history";
const LEGACY_DB = "look-vault-v1";

function openDb() {
  return new Promise((resolve, reject) => {
    const req = indexedDB.open(DB_NAME, 1);
    req.onupgradeneeded = () => {
      const db = req.result;
      if (!db.objectStoreNames.contains(ACCOUNTS)) {
        const as = db.createObjectStore(ACCOUNTS, { keyPath: "id" });
        as.createIndex("googleSub", "googleSub", { unique: false });
        as.createIndex("displayName", "displayName", { unique: false });
      }
      if (!db.objectStoreNames.contains(HISTORY)) {
        const hs = db.createObjectStore(HISTORY, { keyPath: "id", autoIncrement: true });
        hs.createIndex("at", "at");
        hs.createIndex("accountId", "accountId");
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

function idbDelete(store, key) {
  return openDb().then(
    (db) =>
      new Promise((resolve, reject) => {
        const tx = db.transaction(store, "readwrite");
        const r = tx.objectStore(store).delete(key);
        r.onsuccess = () => resolve();
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

function newId() {
  if (crypto.randomUUID) return crypto.randomUUID();
  const b = crypto.getRandomValues(new Uint8Array(16));
  return Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");
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

function publicMeta(acc) {
  if (!acc) return null;
  return {
    id: acc.id,
    displayName: acc.displayName || "Account",
    createdAt: acc.createdAt || null,
    provider: acc.provider || "local",
    email: acc.email || "",
    avatarPublic: acc.avatarPublic || "",
    googleSub: acc.googleSub || null
  };
}

let migrated = false;

async function migrateFromV1() {
  if (migrated) return;
  migrated = true;
  const existing = await idbGetAll(ACCOUNTS);
  if (existing.length) return;

  await new Promise((resolve) => {
    const req = indexedDB.open(LEGACY_DB, 1);
    req.onerror = () => resolve();
    req.onupgradeneeded = () => {
      /* ignore create */
    };
    req.onsuccess = () => {
      const old = req.result;
      if (!old.objectStoreNames.contains("meta")) {
        old.close();
        resolve();
        return;
      }
      const tx = old.transaction(
        old.objectStoreNames.contains("history") ? ["meta", "history"] : ["meta"],
        "readonly"
      );
      const metaReq = tx.objectStore("meta").get("account");
      metaReq.onsuccess = async () => {
        const meta = metaReq.result;
        let rows = [];
        if (old.objectStoreNames.contains("history")) {
          rows = await new Promise((res) => {
            const hr = tx.objectStore("history").getAll();
            hr.onsuccess = () => res(hr.result || []);
            hr.onerror = () => res([]);
          });
        }
        old.close();
        if (!meta || !meta.salt) {
          resolve();
          return;
        }
        const id = newId();
        const account = {
          id,
          displayName: meta.displayName || "Account",
          salt: meta.salt,
          check: meta.check,
          profileEnc: meta.profileEnc,
          avatarPublic: meta.avatarPublic || "",
          provider: meta.provider || "local",
          googleSub: meta.googleSub || null,
          email: meta.email || "",
          createdAt: meta.createdAt || Date.now()
        };
        await idbSet(ACCOUNTS, undefined, account);
        for (const row of rows) {
          await idbAdd(HISTORY, {
            accountId: id,
            at: row.at || Date.now(),
            enc: row.enc
          });
        }
        resolve();
      };
      metaReq.onerror = () => {
        old.close();
        resolve();
      };
    };
  });
}

async function ensureReady() {
  await migrateFromV1();
}

export async function listAccounts() {
  await ensureReady();
  const rows = await idbGetAll(ACCOUNTS);
  return rows
    .map(publicMeta)
    .filter(Boolean)
    .sort((a, b) => (b.createdAt || 0) - (a.createdAt || 0));
}

export async function vaultExists() {
  const list = await listAccounts();
  return list.length > 0;
}

/** @deprecated use listAccounts / getAccountMeta */
export async function getVaultMeta() {
  const list = await listAccounts();
  return list[0] || null;
}

export async function getAccountMeta(accountId) {
  await ensureReady();
  return publicMeta(await idbGet(ACCOUNTS, accountId));
}

async function writeAccount(accountId, partial) {
  const meta = await idbGet(ACCOUNTS, accountId);
  if (!meta) throw new Error("Account not found.");
  const next = { ...meta, ...partial, id: accountId };
  await idbSet(ACCOUNTS, undefined, next);
  return next;
}

function sessionFrom(meta, key, profile) {
  return {
    accountId: meta.id,
    displayName: profile.displayName || meta.displayName,
    key,
    profile,
    provider: meta.provider || "local",
    email: meta.email || ""
  };
}

export async function createVault(displayName, passphrase, profileExtras) {
  await ensureReady();
  if (!displayName || displayName.trim().length < 1) throw new Error("Enter a display name.");
  if (!passphrase || passphrase.length < 8) throw new Error("Password must be at least 8 characters.");
  const name = displayName.trim().slice(0, 40);
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const key = await deriveKey(passphrase, salt);
  const profile = defaultProfile({ displayName: name, ...(profileExtras || {}) });
  const check = await encryptJson(key, { ok: true, created: Date.now() });
  const profileEnc = await encryptJson(key, profile);
  const id = newId();
  const meta = {
    id,
    displayName: profile.displayName,
    salt: bufToB64(salt),
    check,
    profileEnc,
    avatarPublic: profile.avatarDataUrl || profile.avatarRemoteUrl || "",
    provider: "local",
    email: "",
    createdAt: Date.now()
  };
  await idbSet(ACCOUNTS, undefined, meta);
  return sessionFrom(meta, key, profile);
}

export async function unlockVault(passphrase, accountId) {
  await ensureReady();
  let meta = accountId ? await idbGet(ACCOUNTS, accountId) : null;
  if (!meta) {
    const locals = (await idbGetAll(ACCOUNTS)).filter((a) => (a.provider || "local") === "local");
    if (locals.length === 1) meta = locals[0];
    else if (!locals.length) throw new Error("No password account on this device yet.");
    else throw new Error("Choose which account to unlock.");
  }
  if ((meta.provider || "local") === "google") {
    throw new Error("This account uses Google. Tap Continue with Google to log in.");
  }
  const key = await deriveKey(passphrase, b64ToBuf(meta.salt));
  try {
    await decryptJson(key, meta.check);
  } catch (_) {
    throw new Error("Wrong password.");
  }
  const profile = meta.profileEnc
    ? await decryptJson(key, meta.profileEnc)
    : defaultProfile({ displayName: meta.displayName });
  return sessionFrom(meta, key, profile);
}

/** Create or unlock using Google subject id — works alongside other accounts on this device. */
export async function loginWithGoogleIdentity(identity) {
  await ensureReady();
  if (!identity || !identity.sub) throw new Error("Google sign-in did not return a user id.");
  const material = "look-google-v1:" + identity.sub;
  const all = await idbGetAll(ACCOUNTS);
  let meta = all.find((a) => a.provider === "google" && a.googleSub === identity.sub) || null;

  if (meta) {
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
    if (identity.picture && !profile.avatarDataUrl) profile.avatarRemoteUrl = identity.picture;
    if (identity.name && !profile.displayName) profile.displayName = identity.name;
    meta = await writeAccount(meta.id, {
      displayName: profile.displayName,
      email: identity.email || meta.email || "",
      avatarPublic: profile.avatarDataUrl || profile.avatarRemoteUrl || meta.avatarPublic || "",
      profileEnc: await encryptJson(key, profile)
    });
    return sessionFrom(meta, key, profile);
  }

  const salt = crypto.getRandomValues(new Uint8Array(16));
  const key = await deriveKey(material, salt);
  const profile = defaultProfile({
    displayName: (identity.name || "Looker").slice(0, 40),
    avatarRemoteUrl: identity.picture || ""
  });
  const check = await encryptJson(key, { ok: true, created: Date.now(), provider: "google" });
  const profileEnc = await encryptJson(key, profile);
  const id = newId();
  meta = {
    id,
    displayName: profile.displayName,
    salt: bufToB64(salt),
    check,
    profileEnc,
    avatarPublic: profile.avatarRemoteUrl || "",
    provider: "google",
    googleSub: identity.sub,
    email: identity.email || "",
    createdAt: Date.now()
  };
  await idbSet(ACCOUNTS, undefined, meta);
  return sessionFrom(meta, key, profile);
}

export async function saveProfile(key, profile, accountId) {
  if (!accountId) throw new Error("Missing account.");
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
  if (clean.avatarDataUrl && clean.avatarDataUrl.length > 900000) {
    throw new Error("Profile photo is too large. Try a smaller image.");
  }
  const profileEnc = await encryptJson(key, clean);
  await writeAccount(accountId, {
    displayName: clean.displayName,
    avatarPublic: clean.avatarDataUrl || clean.avatarRemoteUrl || "",
    profileEnc
  });
  return clean;
}

export async function saveScan(key, plan, accountId) {
  if (!accountId) throw new Error("Missing account.");
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
  await idbAdd(HISTORY, { accountId, at: record.at, enc });
  return record;
}

export async function listScans(key, accountId) {
  const rows = await idbGetAll(HISTORY);
  const out = [];
  for (const row of rows) {
    if (accountId && row.accountId && row.accountId !== accountId) continue;
    // Legacy rows without accountId only show for the migrated primary account
    if (accountId && !row.accountId) continue;
    try {
      const rec = await decryptJson(key, row.enc);
      out.push({ id: row.id, ...rec });
    } catch (_) {
      /* skip */
    }
  }
  out.sort((a, b) => b.at - a.at);
  return out;
}

export async function exportEncryptedBackup(accountId) {
  await ensureReady();
  const meta = accountId ? await idbGet(ACCOUNTS, accountId) : null;
  const rows = (await idbGetAll(HISTORY)).filter(
    (r) => !accountId || r.accountId === accountId || (!r.accountId && meta)
  );
  return {
    version: 3,
    exportedAt: Date.now(),
    notice: "LOOK Account encrypted backup — keep offline. Contains no LOOK face scans.",
    account: meta,
    history: rows
  };
}

export async function deleteAccount(accountId) {
  await ensureReady();
  const rows = await idbGetAll(HISTORY);
  for (const row of rows) {
    if (row.accountId === accountId) await idbDelete(HISTORY, row.id);
  }
  await idbDelete(ACCOUNTS, accountId);
}

export async function clearVault() {
  const db = await openDb();
  return new Promise((resolve, reject) => {
    const tx = db.transaction([ACCOUNTS, HISTORY], "readwrite");
    tx.objectStore(ACCOUNTS).clear();
    tx.objectStore(HISTORY).clear();
    tx.oncomplete = () => resolve();
    tx.onerror = () => reject(tx.error);
  });
}

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
