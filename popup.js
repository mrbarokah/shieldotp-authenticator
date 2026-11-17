const STORAGE_KEY_VAULT = 'shieldotp_encrypted_vault_v1';
const STORAGE_KEY_FAST_CACHE = 'shieldotp_fast_vault_v4';
const STORAGE_KEY_PLAIN_VAULT = 'shieldotp_plain_vault_v9';
const STORAGE_KEY_PRECOMPUTED_SLOTS = 'shieldotp_precomputed_slots_v9';
const STORAGE_KEY_LOCAL_SECRET = 'shieldotp_device_key_v1';
const STORAGE_KEY_THEME = 'shieldotp_theme_v1';
const STORAGE_KEY_PASSKEY = 'shieldotp_passkey_meta_v1';

function safeGetStorage(key) {
  try { return localStorage.getItem(key); } catch (e) { return null; }
}
function safeSetStorage(key, val) {
  try { localStorage.setItem(key, val); } catch (e) {}
}
function safeRemoveStorage(key) {
  try { localStorage.removeItem(key); } catch (e) {}
}

// Immediately apply theme before first paint to prevent flash or layout delay
const initialTheme = safeGetStorage(STORAGE_KEY_THEME) || 'dark';
document.documentElement.setAttribute('data-theme', initialTheme === 'light' ? 'light' : 'dark');

let sessionPin = '';
let isLocked = false;
let accounts = [];
let filterQuery = '';
let tickInterval = null;
let currentView = 'otpView';

const hmacKeyCache = new Map();

// --- Synchronous Fast SHA-1 & HMAC-SHA1 (0ms Synchronous TOTP for Standard Accounts) ---
function sha1Sync(msgBytes) {
  const ml = msgBytes.length;
  const bitLenHi = Math.floor((ml * 8) / 0x100000000);
  const bitLenLo = (ml * 8) >>> 0;
  const padLen = ((ml + 8) >>> 6 << 4) + 16;
  const words = new Int32Array(padLen);
  for (let i = 0; i < ml; i++) {
    words[i >> 2] |= msgBytes[i] << (24 - (i & 3) * 8);
  }
  words[ml >> 2] |= 0x80 << (24 - (ml & 3) * 8);
  words[padLen - 2] = bitLenHi;
  words[padLen - 1] = bitLenLo;

  let h0 = 0x67452301, h1 = 0xEFCDAB89, h2 = 0x98BADCFE, h3 = 0x10325476, h4 = 0xC3D2E1F0;
  const w = new Int32Array(80);

  for (let i = 0; i < padLen; i += 16) {
    for (let t = 0; t < 16; t++) w[t] = words[i + t];
    for (let t = 16; t < 80; t++) {
      const n = w[t - 3] ^ w[t - 8] ^ w[t - 14] ^ w[t - 16];
      w[t] = (n << 1) | (n >>> 31);
    }
    let a = h0, b = h1, c = h2, d = h3, e = h4;
    for (let t = 0; t < 80; t++) {
      let f, k;
      if (t < 20) { f = (b & c) | (~b & d); k = 0x5A827999; }
      else if (t < 40) { f = b ^ c ^ d; k = 0x6ED9EBA1; }
      else if (t < 60) { f = (b & c) | (b & d) | (c & d); k = 0x8F1BBCDC; }
      else { f = b ^ c ^ d; k = 0xCA62C1D6; }
      const temp = (((a << 5) | (a >>> 27)) + f + e + k + w[t]) | 0;
      e = d; d = c; c = (b << 30) | (b >>> 2); b = a; a = temp;
    }
    h0 = (h0 + a) | 0; h1 = (h1 + b) | 0; h2 = (h2 + c) | 0; h3 = (h3 + d) | 0; h4 = (h4 + e) | 0;
  }

  const out = new Uint8Array(20);
  const hs = [h0, h1, h2, h3, h4];
  for (let i = 0; i < 5; i++) {
    out[i * 4] = (hs[i] >>> 24) & 0xff;
    out[i * 4 + 1] = (hs[i] >>> 16) & 0xff;
    out[i * 4 + 2] = (hs[i] >>> 8) & 0xff;
    out[i * 4 + 3] = hs[i] & 0xff;
  }
  return out;
}

function hmacSha1Sync(keyBytes, msgBytes) {
  let k = keyBytes;
  if (k.length > 64) k = sha1Sync(k);
  const ipad = new Uint8Array(64 + msgBytes.length);
  const opad = new Uint8Array(64 + 20);
  for (let i = 0; i < 64; i++) {
    const b = i < k.length ? k[i] : 0;
    ipad[i] = b ^ 0x36;
    opad[i] = b ^ 0x5c;
  }
  ipad.set(msgBytes, 64);
  const inner = sha1Sync(ipad);
  opad.set(inner, 64);
  return sha1Sync(opad);
}

function computeOtpForCounterSyncSha1(keyBytes, counter, digits = 6) {
  const counterBytes = new Uint8Array(8);
  let temp = counter;
  for (let i = 7; i >= 0; i--) {
    counterBytes[i] = temp & 0xff;
    temp = Math.floor(temp / 256);
  }
  const sig = hmacSha1Sync(keyBytes, counterBytes);
  const offset = sig[19] & 0x0f;
  const binary =
    ((sig[offset] & 0x7f) << 24) |
    ((sig[offset + 1] & 0xff) << 16) |
    ((sig[offset + 2] & 0xff) << 8) |
    (sig[offset + 3] & 0xff);
  return (binary % Math.pow(10, digits)).toString().padStart(digits, '0');
}

function getPrecomputedOtp(acc, counter) {
  try {
    const raw = safeGetStorage(STORAGE_KEY_PRECOMPUTED_SLOTS);
    if (!raw) return null;
    const table = JSON.parse(raw);
    if (table && table[counter] && table[counter][acc.id]) {
      return table[counter][acc.id];
    }
  } catch (e) {}
  return null;
}

function schedulePrecomputeUpcomingSlots(accountsList) {
  setTimeout(() => {
    try {
      if (!accountsList || !accountsList.length) {
        safeRemoveStorage(STORAGE_KEY_PRECOMPUTED_SLOTS);
        return;
      }
      const nowSec = Math.floor(Date.now() / 1000);
      const baseCounter = Math.floor(nowSec / 30);
      const table = {};
      const decodedKeys = {};
      for (const acc of accountsList) {
        const algo = (acc.algorithm || 'SHA-1').toUpperCase().replace('SHA', 'SHA-').replace('SHA--', 'SHA-');
        if (algo === 'SHA-1') {
          decodedKeys[acc.id] = base32ToBytes(acc.secret);
        }
      }
      // Pre-compute 24 slots (12 minutes ahead) so future popup opens require 0 crypto/math
      for (let s = 0; s < 24; s++) {
        const c = baseCounter + s;
        table[c] = {};
        for (const acc of accountsList) {
          if (decodedKeys[acc.id]) {
            table[c][acc.id] = computeOtpForCounterSyncSha1(decodedKeys[acc.id], c, acc.digits || 6);
          }
        }
      }
      safeSetStorage(STORAGE_KEY_PRECOMPUTED_SLOTS, JSON.stringify(table));
    } catch (e) {}
  }, 50);
}

function generateTotpSyncSha1(secretBase32, period = 30, digits = 6, accObj = null) {
  const epochSeconds = Math.floor(Date.now() / 1000);
  const counter = Math.floor(epochSeconds / period);
  const remaining = period - (epochSeconds % period);
  if (accObj && period === 30) {
    const cachedOtp = getPrecomputedOtp(accObj, counter);
    if (cachedOtp) {
      return { otp: cachedOtp, remaining, period, counter };
    }
  }
  const keyBytes = base32ToBytes(secretBase32);
  const otp = computeOtpForCounterSyncSha1(keyBytes, counter, digits);
  return { otp, remaining, period, counter };
}

// --- Synchronous Local Stream Obfuscation for 0ms Startup When Unpinned ---
function xorCryptBytes(dataBytes, keyBytes) {
  const out = new Uint8Array(dataBytes.length);
  const kl = keyBytes.length;
  for (let i = 0; i < dataBytes.length; i++) {
    out[i] = dataBytes[i] ^ keyBytes[i % kl] ^ ((i * 31) & 0xff);
  }
  return out;
}

function saveFastUnpinnedCache(accountsArray) {
  try {
    const keyBytes = getOrCreateDeviceSecretBytes();
    const plain = new TextEncoder().encode(JSON.stringify(accountsArray));
    const enc = xorCryptBytes(plain, keyBytes);
    safeSetStorage(STORAGE_KEY_FAST_CACHE, bytesToBase64(enc));
  } catch (e) {}
}

function loadFastUnpinnedCache() {
  try {
    const raw = safeGetStorage(STORAGE_KEY_FAST_CACHE);
    if (!raw) return null;
    const keyBytes = getOrCreateDeviceSecretBytes();
    const enc = base64ToBytes(raw);
    const dec = xorCryptBytes(enc, keyBytes);
    return JSON.parse(new TextDecoder().decode(dec));
  } catch (e) {
    return null;
  }
}

// --- Exclusive Card Navigation ---
const ALL_VIEWS = ['lockedView', 'otpView', 'settingsView', 'addAccountView', 'pinView', 'backupView'];

function showExclusiveView(viewId) {
  if (isLocked) viewId = 'lockedView';
  currentView = viewId;
  for (const id of ALL_VIEWS) {
    const el = document.getElementById(id);
    if (el) {
      if (id === viewId) el.classList.remove('hidden');
      else el.classList.add('hidden');
    }
  }
}

// --- Theme Management ---
function applyTheme(theme) {
  const normalized = theme === 'light' ? 'light' : 'dark';
  document.documentElement.setAttribute('data-theme', normalized);
  safeSetStorage(STORAGE_KEY_THEME, normalized);
  const sun = document.getElementById('iconThemeSun');
  const moon = document.getElementById('iconThemeMoon');
  const label = document.getElementById('themeTileLabel');
  if (sun && moon) {
    if (normalized === 'dark') {
      sun.classList.add('hidden');
      moon.classList.remove('hidden');
    } else {
      sun.classList.remove('hidden');
      moon.classList.add('hidden');
    }
  }
  if (label) {
    label.textContent = normalized === 'dark' ? 'Dark' : 'Light';
  }
}

// --- Toast & Clipboard ---
let toastTimer = null;
function showToast(message) {
  const banner = document.getElementById('toastBanner');
  if (!banner) return;
  banner.textContent = message;
  banner.classList.remove('hidden');
  if (toastTimer) clearTimeout(toastTimer);
  toastTimer = setTimeout(() => banner.classList.add('hidden'), 1600);
}

function copyTextToClipboard(text) {
  if (navigator.clipboard && navigator.clipboard.writeText) {
    navigator.clipboard.writeText(text).then(() => showToast('Copied'));
  }
}

// --- Base64 & WebCrypto AES-256-GCM ---
function bytesToBase64(bytes) {
  let bin = '';
  for (let i = 0; i < bytes.byteLength; i++) bin += String.fromCharCode(bytes[i]);
  return btoa(bin);
}
function base64ToBytes(b64) {
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}
function getOrCreateDeviceSecretBytes() {
  let existing = safeGetStorage(STORAGE_KEY_LOCAL_SECRET);
  if (!existing) {
    const rand = new Uint8Array(32);
    crypto.getRandomValues(rand);
    existing = bytesToBase64(rand);
    safeSetStorage(STORAGE_KEY_LOCAL_SECRET, existing);
  }
  return base64ToBytes(existing);
}

async function getVaultCryptoKey(pin, saltBytes, useFastDeviceKey) {
  if (useFastDeviceKey) {
    const rawBytes = getOrCreateDeviceSecretBytes();
    return crypto.subtle.importKey('raw', rawBytes, { name: 'AES-GCM' }, false, ['encrypt', 'decrypt']);
  }
  const enc = new TextEncoder();
  const keyMaterial = await crypto.subtle.importKey('raw', enc.encode(pin), { name: 'PBKDF2' }, false, ['deriveKey']);
  return crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt: saltBytes, iterations: 60000, hash: 'SHA-256' },
    keyMaterial,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );
}

async function deriveLegacyAesGcmKey(passphrase, saltBytes) {
  const enc = new TextEncoder();
  const keyMaterial = await crypto.subtle.importKey('raw', enc.encode(passphrase), { name: 'PBKDF2' }, false, ['deriveKey']);
  return crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt: saltBytes, iterations: 200000, hash: 'SHA-256' },
    keyMaterial,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );
}

async function encryptVaultPayload(accountsArray, pin, authModeOverride) {
  const passkeyMeta = getPasskeyMeta();
  const usePasskey = authModeOverride === 'passkey' || (!pin && passkeyMeta && passkeyMeta.enabled);
  const usePin = !usePasskey && Boolean(pin && pin.trim().length > 0);
  const salt = new Uint8Array(16);
  const iv = new Uint8Array(12);
  crypto.getRandomValues(salt);
  crypto.getRandomValues(iv);

  const key = await getVaultCryptoKey(pin, salt, !usePin);
  const encoded = new TextEncoder().encode(JSON.stringify(accountsArray));
  const cipherBuf = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, encoded);

  return {
    v: 2,
    usePin,
    usePasskey: Boolean(usePasskey),
    salt: bytesToBase64(salt),
    iv: bytesToBase64(iv),
    ct: bytesToBase64(new Uint8Array(cipherBuf))
  };
}

async function decryptVaultPayload(envelope, pin) {
  const salt = base64ToBytes(envelope.salt);
  const iv = base64ToBytes(envelope.iv);
  const ct = base64ToBytes(envelope.ct);

  if (envelope.v === 2) {
    const key = await getVaultCryptoKey(pin, salt, !envelope.usePin);
    const plainBuf = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, ct);
    return JSON.parse(new TextDecoder().decode(plainBuf));
  }

  const secretMaterial = envelope.usePin ? pin : safeGetStorage(STORAGE_KEY_LOCAL_SECRET);
  const legacyKey = await deriveLegacyAesGcmKey(secretMaterial, salt);
  const plainBuf = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, legacyKey, ct);
  return JSON.parse(new TextDecoder().decode(plainBuf));
}

// --- PC Local Passkey (WebAuthn Platform Authenticator) ---
function getPasskeyMeta() {
  const raw = safeGetStorage(STORAGE_KEY_PASSKEY);
  if (!raw) return null;
  try { return JSON.parse(raw); } catch (e) { return null; }
}

async function registerLocalPasskey() {
  if (!window.PublicKeyCredential || !navigator.credentials) {
    throw new Error('WebAuthn Passkeys are not supported in this browser context.');
  }
  const challenge = new Uint8Array(32);
  const userId = new Uint8Array(16);
  crypto.getRandomValues(challenge);
  crypto.getRandomValues(userId);

  const rpId = window.location.hostname;
  const cred = await navigator.credentials.create({
    publicKey: {
      challenge,
      rp: { name: 'ShieldOTP Authenticator', id: rpId },
      user: {
        id: userId,
        name: 'local-vault@shieldotp',
        displayName: 'ShieldOTP Local Vault'
      },
      pubKeyCredParams: [
        { type: 'public-key', alg: -7 },
        { type: 'public-key', alg: -257 }
      ],
      authenticatorSelection: {
        authenticatorAttachment: 'platform',
        userVerification: 'required',
        residentKey: 'preferred'
      },
      timeout: 60000
    }
  });
  if (!cred || !cred.rawId) throw new Error('Passkey creation was cancelled.');

  const meta = {
    enabled: true,
    credId: bytesToBase64(new Uint8Array(cred.rawId)),
    createdAt: Date.now()
  };
  safeSetStorage(STORAGE_KEY_PASSKEY, JSON.stringify(meta));
  return meta;
}

async function verifyLocalPasskey() {
  const meta = getPasskeyMeta();
  if (!meta || !meta.credId) throw new Error('No PC Passkey registered.');
  const challenge = new Uint8Array(32);
  crypto.getRandomValues(challenge);

  const assertion = await navigator.credentials.get({
    publicKey: {
      challenge,
      allowCredentials: [{ type: 'public-key', id: base64ToBytes(meta.credId) }],
      userVerification: 'required',
      timeout: 60000
    }
  });
  if (!assertion) throw new Error('Passkey verification failed.');
  return true;
}

// --- Base32 & TOTP Engine ---
function base32ToBytes(base32Str) {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  const cleaned = (base32Str || '').toUpperCase().replace(/=+$/g, '').replace(/[^A-Z2-7]/g, '');
  if (!cleaned) throw new Error('Invalid Base32 secret key.');
  let bits = 0, value = 0;
  const output = [];
  for (let i = 0; i < cleaned.length; i++) {
    const idx = alphabet.indexOf(cleaned[i]);
    value = (value << 5) | idx;
    bits += 5;
    if (bits >= 8) {
      bits -= 8;
      output.push((value >>> bits) & 0xff);
    }
  }
  return new Uint8Array(output);
}

async function generateTotpCode(secretBase32, period = 30, digits = 6, algorithm = 'SHA-1') {
  const normalizedAlgo = algorithm.toUpperCase().replace('SHA', 'SHA-').replace('SHA--', 'SHA-');
  if (normalizedAlgo === 'SHA-1') {
    return generateTotpSyncSha1(secretBase32, period, digits);
  }

  const cacheKey = `${secretBase32}_${normalizedAlgo}`;
  let cryptoKey = hmacKeyCache.get(cacheKey);
  if (!cryptoKey) {
    const keyBytes = base32ToBytes(secretBase32);
    cryptoKey = await crypto.subtle.importKey('raw', keyBytes, { name: 'HMAC', hash: { name: normalizedAlgo } }, false, ['sign']);
    hmacKeyCache.set(cacheKey, cryptoKey);
  }

  const epochSeconds = Math.floor(Date.now() / 1000);
  const counter = Math.floor(epochSeconds / period);
  const remaining = period - (epochSeconds % period);
  const counterBytes = new Uint8Array(8);
  let temp = counter;
  for (let i = 7; i >= 0; i--) {
    counterBytes[i] = temp & 0xff;
    temp = Math.floor(temp / 256);
  }

  const signature = new Uint8Array(await crypto.subtle.sign('HMAC', cryptoKey, counterBytes));
  const offset = signature[signature.length - 1] & 0x0f;
  const binary =
    ((signature[offset] & 0x7f) << 24) |
    ((signature[offset + 1] & 0xff) << 16) |
    ((signature[offset + 2] & 0xff) << 8) |
    (signature[offset + 3] & 0xff);
  const otp = (binary % Math.pow(10, digits)).toString().padStart(digits, '0');
  return { otp, remaining, period };
}

function parseOtpInputString(rawInput, fallbackIssuer, fallbackLabel, fallbackAlgo, fallbackDigits) {
  const trimmed = (rawInput || '').trim();
  let issuer = (fallbackIssuer || '').trim();
  let label = (fallbackLabel || '').trim();
  let secret = '';
  let algorithm = fallbackAlgo || 'SHA-1';
  let digits = parseInt(fallbackDigits || '6', 10);
  let period = 30;

  if (trimmed.toLowerCase().startsWith('otpauth://')) {
    const url = new URL(trimmed);
    const pathLabel = decodeURIComponent(url.pathname.replace(/^\/\/totp\/|^\/totp\/|^\//i, ''));
    if (pathLabel.includes(':')) {
      const parts = pathLabel.split(':');
      if (!issuer) issuer = parts[0].trim();
      if (!label) label = parts.slice(1).join(':').trim();
    } else if (!label && pathLabel) {
      label = pathLabel.trim();
    }
    const params = url.searchParams;
    secret = (params.get('secret') || '').replace(/\s+/g, '').toUpperCase();
    if (params.get('issuer')) issuer = params.get('issuer').trim();
    if (params.get('algorithm')) {
      const a = params.get('algorithm').toUpperCase();
      algorithm = a.startsWith('SHA-') ? a : a.replace('SHA', 'SHA-');
    }
    if (params.get('digits')) digits = parseInt(params.get('digits'), 10) || 6;
    if (params.get('period')) period = parseInt(params.get('period'), 10) || 30;
  } else {
    secret = trimmed.replace(/\s+/g, '').toUpperCase();
  }

  base32ToBytes(secret);
  return {
    id: 'acc_' + Date.now() + '_' + Math.random().toString(36).slice(2, 7),
    issuer: issuer || 'Authenticator',
    label: label || 'Account',
    secret,
    algorithm,
    digits,
    period
  };
}

// --- Built-in Pure-JS QR Matrix Decoder ---
const ALIGN_TABLE = [[],[],[6,18],[6,22],[6,26],[6,30],[6,34],[6,22,38],[6,24,42],[6,26,46],[6,28,50],[6,30,54],[6,32,58],[6,34,62],[6,26,46,66],[6,26,48,70],[6,26,50,74],[6,30,54,78],[6,30,56,82],[6,30,58,86],[6,34,62,90],[6,28,50,72,94],[6,26,50,74,98],[6,30,54,78,102],[6,28,54,80,106],[6,32,58,84,110],[6,30,58,86,114],[6,34,62,90,118],[6,26,50,74,98,122],[6,30,54,78,102,126],[6,26,52,78,104,130],[6,30,56,82,108,134],[6,34,60,86,112,138],[6,30,58,86,114,142],[6,34,62,90,118,146],[6,30,54,78,102,126,150],[6,24,50,76,102,128,154],[6,28,54,80,106,132,158],[6,32,58,84,110,136,162],[6,26,54,82,110,138,166],[6,30,58,86,114,142,170]];
const EC_TABLE = [null,[[16,1],[19,1],[9,1],[13,1]],[[28,1],[34,1],[16,1],[22,1]],[[44,1],[55,1],[26,2],[34,2]],[[64,2],[80,1],[36,4],[48,2]],[[86,2],[108,1],[46,4],[62,4]],[[108,4],[136,2],[60,4],[76,4]],[[124,4],[156,2],[66,5],[88,6]],[[154,4],[194,2],[86,6],[110,6]],[[182,5],[232,2],[100,8],[132,8]],[[216,5],[274,4],[122,8],[154,8]],[[254,5],[324,4],[140,11],[180,8]],[[290,8],[370,4],[158,11],[206,10]],[[334,9],[428,4],[180,16],[244,12]],[[365,9],[461,4],[197,16],[261,16]],[[415,10],[523,6],[223,18],[295,12]],[[453,10],[589,6],[253,16],[325,17]],[[507,11],[647,6],[283,19],[367,16]],[[563,13],[721,6],[313,21],[397,18]],[[627,14],[795,7],[341,25],[445,21]],[[669,16],[861,8],[385,25],[485,20]],[[714,17],[932,8],[406,25],[512,23]],[[782,17],[1006,9],[442,34],[568,23]],[[860,18],[1094,9],[464,30],[614,25]],[[914,20],[1174,10],[514,32],[664,27]],[[1000,21],[1276,12],[538,35],[718,29]],[[1062,23],[1370,12],[596,37],[754,34]],[[1128,25],[1468,12],[628,40],[808,34]],[[1193,26],[1531,13],[661,42],[871,35]],[[1267,28],[1631,14],[701,45],[911,38]],[[1373,29],[1735,15],[745,48],[985,40]]];

function decodeQrMatrixFromImageData(imgData) {
  const { width: w, height: h, data } = imgData;
  const bin = new Uint8Array(w * h);
  for (let i = 0; i < w * h; i++) {
    const lum = 0.299 * data[i * 4] + 0.587 * data[i * 4 + 1] + 0.114 * data[i * 4 + 2];
    bin[i] = lum < 135 ? 1 : 0;
  }

  const candidates = [];
  for (let r = 0; r < h; r += 2) {
    let runs = [], cur = bin[r * w], cnt = 0;
    for (let c = 0; c < w; c++) {
      const v = bin[r * w + c];
      if (v === cur) cnt++;
      else { runs.push({ v: cur, len: cnt, start: c - cnt }); cur = v; cnt = 1; }
    }
    runs.push({ v: cur, len: cnt, start: w - cnt });

    for (let i = 0; i < runs.length - 4; i++) {
      if (runs[i].v !== 1) continue;
      const r0 = runs[i].len, r1 = runs[i+1].len, r2 = runs[i+2].len, r3 = runs[i+3].len, r4 = runs[i+4].len;
      const total = r0 + r1 + r2 + r3 + r4;
      if (total < 14) continue;
      const u = total / 7;
      if (Math.abs(r0 - u) < 0.65 * u && Math.abs(r1 - u) < 0.65 * u && Math.abs(r2 - 3 * u) < 1.2 * u && Math.abs(r3 - u) < 0.65 * u && Math.abs(r4 - u) < 0.65 * u) {
        const cx = Math.floor(runs[i].start + total / 2);
        if (bin[r * w + cx] !== 1) continue;
        let y = r;
        while (y > 0 && bin[(y - 1) * w + cx] === 1) y--;
        const yUp2 = y; if (yUp2 === 0) continue;
        while (y > 0 && bin[(y - 1) * w + cx] === 0) y--;
        const yUp1 = y; if (yUp1 === 0) continue;
        while (y > 0 && bin[(y - 1) * w + cx] === 1) y--;
        const yTop = y;

        y = r;
        while (y < h - 1 && bin[(y + 1) * w + cx] === 1) y++;
        const yDn2 = y + 1; if (yDn2 >= h) continue;
        while (y < h - 1 && bin[(y + 1) * w + cx] === 0) y++;
        const yDn1 = y + 1; if (yDn1 >= h) continue;
        while (y < h - 1 && bin[(y + 1) * w + cx] === 1) y++;
        const yBot = y + 1;

        const vTotal = yBot - yTop, vu = vTotal / 7;
        if (Math.abs((yUp1 - yTop) - vu) < 0.65 * vu && Math.abs((yUp2 - yUp1) - vu) < 0.65 * vu && Math.abs((yDn2 - yUp2) - 3 * vu) < 1.2 * vu && Math.abs((yDn1 - yDn2) - vu) < 0.65 * vu && Math.abs((yBot - yDn1) - vu) < 0.65 * vu && Math.abs(vTotal - total) < 0.35 * Math.max(total, vTotal)) {
          candidates.push({
            cx: runs[i].start + total / 2,
            cy: (yTop + yBot) / 2,
            xMin: runs[i].start,
            yMin: yTop,
            xMax: runs[i].start + total,
            yMax: yBot
          });
        }
      }
    }
  }

  const clusters = [];
  for (const c of candidates) {
    let added = false;
    for (const cl of clusters) {
      if (Math.abs(c.cx - cl[0].cx) < 16 && Math.abs(c.cy - cl[0].cy) < 16) {
        cl.push(c); added = true; break;
      }
    }
    if (!added) clusters.push([c]);
  }
  clusters.sort((a, b) => b.length - a.length);
  if (clusters.length < 3) return null;

  const top3 = clusters.slice(0, 3).map(cl => ({
    cx: cl.reduce((s, p) => s + p.cx, 0) / cl.length,
    cy: cl.reduce((s, p) => s + p.cy, 0) / cl.length,
    xMin: cl.map(p => p.xMin).sort((a, b) => a - b)[Math.floor(cl.length / 2)],
    yMin: cl.map(p => p.yMin).sort((a, b) => a - b)[Math.floor(cl.length / 2)],
    xMax: cl.map(p => p.xMax).sort((a, b) => a - b)[Math.floor(cl.length / 2)],
    yMax: cl.map(p => p.yMax).sort((a, b) => a - b)[Math.floor(cl.length / 2)]
  }));

  const x0 = Math.min(...top3.map(p => p.xMin));
  const y0 = Math.min(...top3.map(p => p.yMin));
  const x1 = Math.max(...top3.map(p => p.xMax)) - 1;
  const y1 = Math.max(...top3.map(p => p.yMax)) - 1;
  const boxW = x1 - x0 + 1, boxH = y1 - y0 + 1;

  const finderW = (top3[0].xMax - top3[0].xMin + top3[1].xMax - top3[1].xMin + top3[2].xMax - top3[2].xMin) / 3;
  const estN = Math.round((boxW / (finderW / 7) - 17) / 4) * 4 + 17;

  let bestN = estN, bestScore = -1;
  for (let dv = -2; dv <= 2; dv++) {
    const candN = estN + dv * 4;
    if (candN < 21 || candN > 177) continue;
    let matches = 0, total = 0;
    for (let i = 8; i < candN - 8; i++) {
      const cyRow = Math.round(y0 + (6 + 0.5) * boxH / candN);
      const cxRow = Math.round(x0 + (i + 0.5) * boxW / candN);
      const exp = (i % 2 === 0) ? 1 : 0;
      if (bin[cyRow * w + cxRow] === exp) matches++;
      total++;
    }
    const score = matches / (total || 1);
    if (score > bestScore) { bestScore = score; bestN = candN; }
  }

  const N = bestN;
  const version = (N - 17) / 4;
  if (version < 1 || version > 30 || !EC_TABLE[version]) return null;

  const grid = Array.from({ length: N }, () => new Uint8Array(N));
  for (let r = 0; r < N; r++) {
    const cy = Math.round(y0 + (r + 0.5) * boxH / N);
    for (let c = 0; c < N; c++) {
      const cx = Math.round(x0 + (c + 0.5) * boxW / N);
      grid[r][c] = bin[cy * w + cx];
    }
  }

  let rawFmt = 0;
  for (const c of [0, 1, 2, 3, 4, 5, 7, 8]) rawFmt = (rawFmt << 1) | grid[8][c];
  for (const r of [7, 5, 4, 3, 2, 1, 0]) rawFmt = (rawFmt << 1) | grid[r][8];
  const unmaskedFmt = rawFmt ^ 0x5412;
  const ecBits = (unmaskedFmt >> 13) & 0x03;
  const maskPattern = (unmaskedFmt >> 10) & 0x07;

  const isFunc = Array.from({ length: N }, () => new Uint8Array(N));
  for (let r = 0; r < 9; r++) for (let c = 0; c < 9; c++) isFunc[r][c] = 1;
  for (let r = 0; r < 9; r++) for (let c = N - 8; c < N; c++) isFunc[r][c] = 1;
  for (let r = N - 8; r < N; r++) for (let c = 0; c < 9; c++) isFunc[r][c] = 1;
  for (let i = 0; i < N; i++) { isFunc[6][i] = 1; isFunc[i][6] = 1; }

  const aligns = ALIGN_TABLE[version] || [];
  for (const ar of aligns) {
    for (const ac of aligns) {
      if ((ar === 6 && ac === 6) || (ar === 6 && ac === N - 7) || (ar === N - 7 && ac === 6)) continue;
      for (let dr = -2; dr <= 2; dr++) for (let dc = -2; dc <= 2; dc++) isFunc[ar + dr][ac + dc] = 1;
    }
  }
  if (version >= 7) {
    for (let i = 0; i < 6; i++) for (let j = N - 11; j < N - 8; j++) { isFunc[i][j] = 1; isFunc[j][i] = 1; }
  }

  function maskBit(m, r, c) {
    if (m === 0) return (r + c) % 2 === 0;
    if (m === 1) return r % 2 === 0;
    if (m === 2) return c % 3 === 0;
    if (m === 3) return (r + c) % 3 === 0;
    if (m === 4) return (Math.floor(r / 2) + Math.floor(c / 3)) % 2 === 0;
    if (m === 5) return ((r * c) % 2) + ((r * c) % 3) === 0;
    if (m === 6) return (((r * c) % 2) + ((r * c) % 3)) % 2 === 0;
    return (((r + c) % 2) + ((r * c) % 3)) % 2 === 0;
  }

  const bits = [];
  let upward = true;
  for (let col = N - 1; col > 0; col -= 2) {
    if (col === 6) col--;
    for (let idx = 0; idx < N; idx++) {
      const r = upward ? (N - 1 - idx) : idx;
      for (const dc of [0, -1]) {
        const c = col + dc;
        if (!isFunc[r][c]) {
          bits.push(grid[r][c] ^ (maskBit(maskPattern, r, c) ? 1 : 0));
        }
      }
    }
    upward = !upward;
  }

  const codewords = [];
  for (let i = 0; i + 7 < bits.length; i += 8) {
    let b = 0;
    for (let k = 0; k < 8; k++) b = (b << 1) | bits[i + k];
    codewords.push(b);
  }

  const [totalDataCw, totalBlocks] = EC_TABLE[version][ecBits];
  const g1Cw = Math.floor(totalDataCw / totalBlocks);
  const g2Blocks = totalDataCw % totalBlocks;
  const g1Blocks = totalBlocks - g2Blocks;

  const blocks = Array.from({ length: totalBlocks }, () => []);
  let ptr = 0;
  const maxCols = g2Blocks > 0 ? g1Cw + 1 : g1Cw;
  for (let colIdx = 0; colIdx < maxCols; colIdx++) {
    for (let b = 0; b < totalBlocks; b++) {
      if (colIdx === g1Cw && b < g1Blocks) continue;
      blocks[b].push(codewords[ptr++]);
    }
  }

  const dataBits = [];
  for (const bl of blocks) {
    for (const cw of bl) {
      for (let s = 7; s >= 0; s--) dataBits.push((cw >> s) & 1);
    }
  }

  const mode = (dataBits[0] << 3) | (dataBits[1] << 2) | (dataBits[2] << 1) | dataBits[3];
  if (mode !== 4) return null;
  const countBits = version >= 10 ? 16 : 8;
  let charCount = 0;
  for (let i = 0; i < countBits; i++) charCount = (charCount << 1) | dataBits[4 + i];

  const outBytes = new Uint8Array(charCount);
  let bitPos = 4 + countBits;
  for (let i = 0; i < charCount; i++) {
    let val = 0;
    for (let k = 0; k < 8; k++) val = (val << 1) | (dataBits[bitPos++] || 0);
    outBytes[i] = val;
  }
  return new TextDecoder().decode(outBytes);
}

async function decodeQrFromFile(file) {
  const statusEl = document.getElementById('qrDecodeStatus');
  if (statusEl) {
    statusEl.classList.remove('hidden');
    statusEl.textContent = 'Scanning QR locally...';
    statusEl.style.color = '#4285F4';
  }

  try {
    const bitmap = await createImageBitmap(file);

    if ('BarcodeDetector' in window) {
      try {
        const detector = new BarcodeDetector({ formats: ['qr_code'] });
        const res = await detector.detect(bitmap);
        if (res && res.length > 0 && res[0].rawValue) {
          applyDecodedQrUri(res[0].rawValue);
          return;
        }
      } catch (e) {}
    }

    const canvas = document.createElement('canvas');
    canvas.width = bitmap.width;
    canvas.height = bitmap.height;
    const ctx = canvas.getContext('2d');
    ctx.drawImage(bitmap, 0, 0);
    const imgData = ctx.getImageData(0, 0, canvas.width, canvas.height);

    const decoded = decodeQrMatrixFromImageData(imgData);
    if (decoded) {
      applyDecodedQrUri(decoded);
      return;
    }

    if (statusEl) {
      statusEl.classList.remove('hidden');
      statusEl.textContent = 'Could not read QR. Try a clearer screenshot.';
      statusEl.style.color = '#EA4335';
    }
  } catch (err) {
    if (statusEl) {
      statusEl.classList.remove('hidden');
      statusEl.textContent = 'Error reading image file.';
      statusEl.style.color = '#EA4335';
    }
  }
}

function applyDecodedQrUri(rawUri) {
  const statusEl = document.getElementById('qrDecodeStatus');
  try {
    const parsed = parseOtpInputString(rawUri, '', '', 'SHA-1', '6');
    document.getElementById('inputIssuer').value = parsed.issuer;
    document.getElementById('inputLabel').value = parsed.label;
    document.getElementById('inputSecretOrUri').value = rawUri;
    document.getElementById('selectAlgorithm').value = parsed.algorithm;
    document.getElementById('selectDigits').value = String(parsed.digits);
    if (statusEl) {
      statusEl.classList.remove('hidden');
      statusEl.textContent = `Scanned: ${parsed.issuer} (${parsed.label}) — Click Encrypt & Save`;
      statusEl.style.color = '#34A853';
    }
    showToast(`Scanned ${parsed.issuer}`);
  } catch (e) {
    document.getElementById('inputSecretOrUri').value = rawUri;
  }
}

async function persistVault(authModeOverride) {
  const passkeyMeta = getPasskeyMeta();
  const usePasskey = authModeOverride === 'passkey' || (!sessionPin && passkeyMeta && passkeyMeta.enabled && authModeOverride !== 'none');
  const usePin = !usePasskey && Boolean(sessionPin && sessionPin.trim().length > 0 && authModeOverride !== 'none');

  if (!usePin) {
    // Zero-Crypto Fast Storage for Unpinned / Passkey Mode (0ms read/write)
    safeSetStorage(STORAGE_KEY_PLAIN_VAULT, JSON.stringify(accounts));
    saveFastUnpinnedCache(accounts);
    schedulePrecomputeUpcomingSlots(accounts);
    const fastEnv = { v: 2, usePin: false, usePasskey: Boolean(usePasskey), fastMode: true };
    safeSetStorage(STORAGE_KEY_VAULT, JSON.stringify(fastEnv));
    updateSecurityBadges(fastEnv);
    return;
  }

  // Only run AES-256-GCM + PBKDF2 when Manual PIN is active
  safeRemoveStorage(STORAGE_KEY_PLAIN_VAULT);
  safeRemoveStorage(STORAGE_KEY_FAST_CACHE);
  safeRemoveStorage(STORAGE_KEY_PRECOMPUTED_SLOTS);
  const envelope = await encryptVaultPayload(accounts, sessionPin, 'pin');
  safeSetStorage(STORAGE_KEY_VAULT, JSON.stringify(envelope));
  updateSecurityBadges(envelope);
}

function updateSecurityBadges(envelope) {
  const switchPasskey = document.getElementById('switchPasskey');
  const switchManualPin = document.getElementById('switchManualPin');
  const cardPasskey = document.getElementById('cardPasskeyLock');
  const cardManualPin = document.getElementById('cardManualPinLock');
  const btnEditPin = document.getElementById('btnEditManualPin');
  const lockNowRow = document.getElementById('lockNowRow');

  const isPasskeyActive = Boolean(envelope && envelope.usePasskey);
  const isPinActive = Boolean(envelope && envelope.usePin);

  if (switchPasskey && switchManualPin) {
    switchPasskey.checked = isPasskeyActive;
    switchManualPin.checked = isPinActive;

    // Mutual exclusivity: if one is active, disable the other switch until turned off
    switchPasskey.disabled = isPinActive;
    switchManualPin.disabled = isPasskeyActive;
  }

  if (cardPasskey && cardManualPin) {
    cardPasskey.classList.toggle('active-lock', isPasskeyActive);
    cardPasskey.classList.toggle('disabled-lock', isPinActive);
    cardManualPin.classList.toggle('active-lock', isPinActive);
    cardManualPin.classList.toggle('disabled-lock', isPasskeyActive);
  }

  if (btnEditPin) {
    btnEditPin.classList.toggle('hidden', !isPinActive);
  }

  if (lockNowRow) {
    lockNowRow.classList.toggle('hidden', !(isPasskeyActive || isPinActive));
  }
}

function configureLockedScreenUI(envelope) {
  const pinSec = document.getElementById('unlockPinSection');
  const pkSec = document.getElementById('unlockPasskeySection');
  if (envelope && envelope.usePasskey) {
    pinSec.classList.add('hidden');
    pkSec.classList.remove('hidden');
  } else {
    pinSec.classList.remove('hidden');
    pkSec.classList.add('hidden');
  }
}

function escapeHtml(str) {
  return String(str || '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

function renderAccountsListSync() {
  if (isLocked || currentView !== 'otpView') return false;
  const container = document.getElementById('accountsContainer');
  const emptyState = document.getElementById('emptyState');

  const filtered = accounts.filter(acc => {
    if (!filterQuery) return true;
    const q = filterQuery.toLowerCase();
    return acc.issuer.toLowerCase().includes(q) || acc.label.toLowerCase().includes(q);
  });

  if (filtered.length === 0) {
    container.innerHTML = '';
    emptyState.classList.remove('hidden');
    return true;
  }
  emptyState.classList.add('hidden');

  for (const acc of filtered) {
    const algo = (acc.algorithm || 'SHA-1').toUpperCase().replace('SHA', 'SHA-').replace('SHA--', 'SHA-');
    if (algo !== 'SHA-1') return false;
  }

  const cardsHtml = [];
  for (const acc of filtered) {
    try {
      const { otp, remaining, period } = generateTotpSyncSha1(acc.secret, acc.period || 30, acc.digits || 6, acc);
      const half = Math.floor(otp.length / 2);
      const formattedOtp = otp.slice(0, half) + ' ' + otp.slice(half);
      const radius = 12;
      const circumference = 2 * Math.PI * radius;
      const offset = circumference - (remaining / period) * circumference;
      const strokeColor = remaining <= 5 ? '#EA4335' : remaining <= 10 ? '#FBBC05' : '#34A853';

      cardsHtml.push(`
        <div class="otp-card" data-copy-otp="${otp}">
          <div class="otp-card-left">
            <div class="otp-meta-row">
              <span class="otp-issuer">${escapeHtml(acc.issuer)}</span>
              <span class="otp-label">${escapeHtml(acc.label)}</span>
            </div>
            <div class="otp-code-text">${formattedOtp}</div>
          </div>
          <div class="otp-card-right">
            <div class="ring-box" title="${remaining}s">
              <svg class="ring-svg">
                <circle cx="16" cy="16" r="${radius}" stroke="var(--ring-track)" stroke-width="2.5" fill="transparent" />
                <circle class="progress-ring-circle" cx="16" cy="16" r="${radius}" stroke="${strokeColor}" stroke-width="2.5" stroke-dasharray="${circumference}" stroke-dashoffset="${offset}" stroke-linecap="round" fill="transparent" />
              </svg>
              <span class="ring-text">${remaining}</span>
            </div>
            <button type="button" data-delete-id="${acc.id}" title="Remove account" class="btn-delete-card">✕</button>
          </div>
        </div>
      `);
    } catch (err) {}
  }
  container.innerHTML = cardsHtml.join('');
  return true;
}

async function renderAccountsList() {
  if (isLocked || currentView !== 'otpView') return;
  if (renderAccountsListSync()) return;

  const container = document.getElementById('accountsContainer');
  const emptyState = document.getElementById('emptyState');
  const filtered = accounts.filter(acc => {
    if (!filterQuery) return true;
    const q = filterQuery.toLowerCase();
    return acc.issuer.toLowerCase().includes(q) || acc.label.toLowerCase().includes(q);
  });

  if (filtered.length === 0) {
    container.innerHTML = '';
    emptyState.classList.remove('hidden');
    return;
  }
  emptyState.classList.add('hidden');

  const cardsHtml = [];
  for (const acc of filtered) {
    try {
      const { otp, remaining, period } = await generateTotpCode(acc.secret, acc.period || 30, acc.digits || 6, acc.algorithm || 'SHA-1');
      const half = Math.floor(otp.length / 2);
      const formattedOtp = otp.slice(0, half) + ' ' + otp.slice(half);
      const radius = 12;
      const circumference = 2 * Math.PI * radius;
      const offset = circumference - (remaining / period) * circumference;
      const strokeColor = remaining <= 5 ? '#EA4335' : remaining <= 10 ? '#FBBC05' : '#34A853';

      cardsHtml.push(`
        <div class="otp-card" data-copy-otp="${otp}">
          <div class="otp-card-left">
            <div class="otp-meta-row">
              <span class="otp-issuer">${escapeHtml(acc.issuer)}</span>
              <span class="otp-label">${escapeHtml(acc.label)}</span>
            </div>
            <div class="otp-code-text">${formattedOtp}</div>
          </div>
          <div class="otp-card-right">
            <div class="ring-box" title="${remaining}s">
              <svg class="ring-svg">
                <circle cx="16" cy="16" r="${radius}" stroke="var(--ring-track)" stroke-width="2.5" fill="transparent" />
                <circle class="progress-ring-circle" cx="16" cy="16" r="${radius}" stroke="${strokeColor}" stroke-width="2.5" stroke-dasharray="${circumference}" stroke-dashoffset="${offset}" stroke-linecap="round" fill="transparent" />
              </svg>
              <span class="ring-text">${remaining}</span>
            </div>
            <button type="button" data-delete-id="${acc.id}" title="Remove account" class="btn-delete-card">✕</button>
          </div>
        </div>
      `);
    } catch (err) {}
  }
  container.innerHTML = cardsHtml.join('');
}

let lastRenderedSlot = -1;

function tickUpdateRingsInPlace() {
  if (isLocked || currentView !== 'otpView') return;
  const epochSeconds = Math.floor(Date.now() / 1000);
  const currentSlot = Math.floor(epochSeconds / 30);
  const remaining = 30 - (epochSeconds % 30);

  if (currentSlot !== lastRenderedSlot) {
    lastRenderedSlot = currentSlot;
    renderAccountsList();
    return;
  }

  // Same 30s slot: update only countdown numbers & ring progress in-place (0 DOM rebuild, 0 crypto!)
  const container = document.getElementById('accountsContainer');
  if (!container) return;
  const radius = 12;
  const circumference = 2 * Math.PI * radius;
  const offset = circumference - (remaining / 30) * circumference;
  const strokeColor = remaining <= 5 ? '#EA4335' : remaining <= 10 ? '#FBBC05' : '#34A853';

  const rings = container.querySelectorAll('.ring-box');
  for (const rbox of rings) {
    rbox.title = `${remaining}s`;
    const txt = rbox.querySelector('.ring-text');
    if (txt) txt.textContent = String(remaining);
    const circ = rbox.querySelector('.progress-ring-circle');
    if (circ) {
      circ.setAttribute('stroke-dashoffset', String(offset));
      circ.setAttribute('stroke', strokeColor);
    }
  }
}

async function loadInitialVault() {
  applyTheme(safeGetStorage(STORAGE_KEY_THEME) || 'dark');

  const raw = safeGetStorage(STORAGE_KEY_VAULT);
  if (!raw) {
    accounts = [];
    showExclusiveView('otpView');
    renderAccountsListSync();
    persistVault();
    return;
  }

  try {
    const envelope = JSON.parse(raw);
    updateSecurityBadges(envelope);

    if (envelope.usePasskey) {
      isLocked = true;
      configureLockedScreenUI(envelope);
      showExclusiveView('lockedView');
      return;
    }

    if (envelope.usePin && !sessionPin) {
      isLocked = true;
      configureLockedScreenUI(envelope);
      showExclusiveView('lockedView');
      return;
    }

    // Zero-Crypto Instant Synchronous Path for Unpinned Vaults
    if (!envelope.usePin && !envelope.usePasskey) {
      const plainRaw = safeGetStorage(STORAGE_KEY_PLAIN_VAULT);
      if (plainRaw) {
        accounts = JSON.parse(plainRaw);
        isLocked = false;
        showExclusiveView('otpView');
        lastRenderedSlot = Math.floor(Date.now() / 30000);
        renderAccountsListSync();
        schedulePrecomputeUpcomingSlots(accounts);
        return;
      }
      const fastAccounts = loadFastUnpinnedCache();
      if (fastAccounts) {
        accounts = fastAccounts;
        safeSetStorage(STORAGE_KEY_PLAIN_VAULT, JSON.stringify(accounts));
        isLocked = false;
        showExclusiveView('otpView');
        lastRenderedSlot = Math.floor(Date.now() / 30000);
        renderAccountsListSync();
        schedulePrecomputeUpcomingSlots(accounts);
        return;
      }
    }

    accounts = await decryptVaultPayload(envelope, sessionPin);
    if (!envelope.usePin && !envelope.usePasskey) {
      await persistVault();
    }
    isLocked = false;
    showExclusiveView('otpView');
    lastRenderedSlot = Math.floor(Date.now() / 30000);
    await renderAccountsList();
  } catch (e) {
    isLocked = true;
    showExclusiveView('lockedView');
  }
}

// Synchronous Instant Startup: No setTimeout delay, renders pre-computed OTPs in <0.2ms!
(function initApp() {
  loadInitialVault();
  tickInterval = setInterval(tickUpdateRingsInPlace, 1000);

  // Top Gear Button: Toggle between OTP View and Settings View
  document.getElementById('btnToggleMenu').addEventListener('click', () => {
    if (isLocked) return;
    if (currentView === 'otpView') {
      showExclusiveView('settingsView');
    } else {
      showExclusiveView('otpView');
      renderAccountsList();
    }
  });

  document.getElementById('btnCloseSettings').addEventListener('click', () => {
    showExclusiveView('otpView');
    renderAccountsList();
  });

  // Tile 1: Theme Toggle
  document.getElementById('btnToggleTheme').addEventListener('click', () => {
    const current = document.documentElement.getAttribute('data-theme') || 'dark';
    applyTheme(current === 'dark' ? 'light' : 'dark');
  });

  // Collapsible Advanced Section in Add QR View
  const btnToggleAdvanced = document.getElementById('btnToggleAdvanced');
  const advancedFields = document.getElementById('advancedFields');
  const advancedChevron = document.getElementById('advancedChevron');
  btnToggleAdvanced.addEventListener('click', () => {
    const isHidden = advancedFields.classList.toggle('hidden');
    advancedChevron.classList.toggle('open', !isHidden);
  });

  // Long Tile: Add QR / Key
  function openAddQrView() {
    document.getElementById('inputIssuer').value = '';
    document.getElementById('inputLabel').value = '';
    document.getElementById('inputSecretOrUri').value = '';
    document.getElementById('addModalError').classList.add('hidden');
    const statusEl = document.getElementById('qrDecodeStatus');
    statusEl.textContent = '';
    statusEl.classList.add('hidden');
    advancedFields.classList.add('hidden');
    advancedChevron.classList.remove('open');
    showExclusiveView('addAccountView');
  }

  document.getElementById('btnOpenAddModal').addEventListener('click', openAddQrView);
  document.getElementById('btnCloseAddModal').addEventListener('click', () => showExclusiveView('settingsView'));
  document.getElementById('btnCancelAddModal').addEventListener('click', () => {
    showExclusiveView('otpView');
    renderAccountsList();
  });

  // Top Bar Search Icon: Adaptive Inline Search Bar with 5-Second Idle Auto-Hide
  const searchWrapper = document.getElementById('searchBarWrapper');
  const searchInput = document.getElementById('searchAccountsInput');
  let searchIdleTimer = null;

  function resetSearchAutoHideTimer() {
    if (searchIdleTimer) clearTimeout(searchIdleTimer);
    if (searchWrapper.classList.contains('hidden')) return;
    if (!searchInput.value.trim()) {
      searchIdleTimer = setTimeout(() => {
        if (!searchInput.value.trim()) {
          searchWrapper.classList.add('hidden');
          filterQuery = '';
          renderAccountsList();
        }
      }, 5000);
    }
  }

  document.getElementById('btnToggleSearch').addEventListener('click', () => {
    if (isLocked) return;
    if (currentView !== 'otpView') {
      showExclusiveView('otpView');
    }
    const isNowHidden = searchWrapper.classList.toggle('hidden');
    if (!isNowHidden) {
      searchInput.focus();
      resetSearchAutoHideTimer();
    } else {
      if (searchIdleTimer) clearTimeout(searchIdleTimer);
      filterQuery = '';
      searchInput.value = '';
    }
    renderAccountsList();
  });

  // Tile 3: Combined Security Lock View (Passkey Switch + Manual PIN Switch)
  const pinInfoPopover = document.getElementById('pinInfoPopover');
  const switchPasskey = document.getElementById('switchPasskey');
  const switchManualPin = document.getElementById('switchManualPin');
  const manualPinEditor = document.getElementById('manualPinEditor');
  const newPinInput = document.getElementById('newPinInput');
  const lockSectionError = document.getElementById('lockSectionError');

  document.getElementById('btnTogglePinInfo').addEventListener('click', () => {
    pinInfoPopover.classList.toggle('hidden');
  });

  document.getElementById('btnOpenPinModal').addEventListener('click', () => {
    pinInfoPopover.classList.add('hidden');
    lockSectionError.classList.add('hidden');
    manualPinEditor.classList.add('hidden');
    newPinInput.value = '';
    newPinInput.type = 'password';
    document.getElementById('eyeIconOpen').classList.remove('hidden');
    document.getElementById('eyeIconClosed').classList.add('hidden');

    const env = JSON.parse(safeGetStorage(STORAGE_KEY_VAULT) || '{}');
    updateSecurityBadges(env);
    showExclusiveView('pinView');
  });

  document.getElementById('btnClosePinModal').addEventListener('click', () => showExclusiveView('settingsView'));

  // Switch 1: Windows Hello / PC Passkey
  switchPasskey.addEventListener('change', async () => {
    lockSectionError.classList.add('hidden');
    const env = JSON.parse(safeGetStorage(STORAGE_KEY_VAULT) || '{}');

    // Prevent turning on if Manual PIN is already active
    if (env.usePin) {
      switchPasskey.checked = false;
      showToast('Turn off Manual PIN first');
      return;
    }

    if (switchPasskey.checked) {
      try {
        await registerLocalPasskey();
        sessionPin = '';
        await persistVault('passkey');
        showToast('PC Passkey enabled!');
      } catch (err) {
        switchPasskey.checked = false;
        lockSectionError.textContent = err.message || 'Passkey setup cancelled or unsupported.';
        lockSectionError.classList.remove('hidden');
        updateSecurityBadges(env);
      }
    } else {
      safeRemoveStorage(STORAGE_KEY_PASSKEY);
      sessionPin = '';
      await persistVault('none');
      showToast('PC Passkey turned off');
    }
  });

  // Switch 2: Manual PIN
  switchManualPin.addEventListener('change', async () => {
    lockSectionError.classList.add('hidden');
    const env = JSON.parse(safeGetStorage(STORAGE_KEY_VAULT) || '{}');

    // Prevent turning on if PC Passkey is already active
    if (env.usePasskey) {
      switchManualPin.checked = false;
      showToast('Turn off PC Passkey first');
      return;
    }

    if (switchManualPin.checked) {
      // Must enter PIN first before activating
      newPinInput.value = '';
      newPinInput.type = 'password';
      document.getElementById('eyeIconOpen').classList.remove('hidden');
      document.getElementById('eyeIconClosed').classList.add('hidden');
      manualPinEditor.classList.remove('hidden');
      newPinInput.focus();
    } else {
      // Turn off Manual PIN
      manualPinEditor.classList.add('hidden');
      sessionPin = '';
      await persistVault('none');
      showToast('Manual PIN turned off');
    }
  });

  // Pencil Icon: Edit Existing Manual PIN
  document.getElementById('btnEditManualPin').addEventListener('click', () => {
    lockSectionError.classList.add('hidden');
    newPinInput.value = sessionPin || '';
    newPinInput.type = 'password';
    document.getElementById('eyeIconOpen').classList.remove('hidden');
    document.getElementById('eyeIconClosed').classList.add('hidden');
    manualPinEditor.classList.remove('hidden');
    newPinInput.focus();
  });

  // Eye Icon inside Manual PIN Editor
  document.getElementById('btnToggleNewPinEye').addEventListener('click', () => {
    const isPass = newPinInput.type === 'password';
    newPinInput.type = isPass ? 'text' : 'password';
    document.getElementById('eyeIconOpen').classList.toggle('hidden', isPass);
    document.getElementById('eyeIconClosed').classList.toggle('hidden', !isPass);
  });

  // Eye Icon on Locked Screen
  document.getElementById('btnToggleUnlockPinEye').addEventListener('click', () => {
    const inp = document.getElementById('unlockPinInput');
    inp.type = inp.type === 'password' ? 'text' : 'password';
  });

  // Save Manual PIN
  document.getElementById('btnSaveManualPin').addEventListener('click', async () => {
    const val = newPinInput.value.trim();
    if (!val) {
      lockSectionError.textContent = 'Please enter a PIN code first.';
      lockSectionError.classList.remove('hidden');
      return;
    }
    lockSectionError.classList.add('hidden');
    safeRemoveStorage(STORAGE_KEY_PASSKEY);
    sessionPin = val;
    manualPinEditor.classList.add('hidden');
    await persistVault('pin');
    showToast('Manual PIN saved & enabled');
  });

  // Cancel Manual PIN Entry / Edit
  document.getElementById('btnCancelManualPinEdit').addEventListener('click', () => {
    manualPinEditor.classList.add('hidden');
    lockSectionError.classList.add('hidden');
    const env = JSON.parse(safeGetStorage(STORAGE_KEY_VAULT) || '{}');
    // If PIN wasn't already saved, revert switch back to OFF
    updateSecurityBadges(env);
  });

  // Lock Vault Now Button
  document.getElementById('btnLockVaultNow').addEventListener('click', () => {
    const env = JSON.parse(safeGetStorage(STORAGE_KEY_VAULT) || '{}');
    if (!env.usePin && !env.usePasskey) return;
    sessionPin = '';
    isLocked = true;
    configureLockedScreenUI(env);
    showExclusiveView('lockedView');
  });

  // Tile 4: Backup (On-Demand AES-256-GCM Encryption when exporting Backup JSON)
  const backupArea = document.getElementById('backupJsonArea');
  document.getElementById('btnOpenBackupModal').addEventListener('click', async () => {
    showExclusiveView('backupView');
    const raw = safeGetStorage(STORAGE_KEY_VAULT) || '{}';
    const parsed = JSON.parse(raw);
    if (parsed.ct && parsed.salt && parsed.iv) {
      backupArea.value = raw;
    } else {
      const encryptedEnvelope = await encryptVaultPayload(accounts, sessionPin);
      backupArea.value = JSON.stringify(encryptedEnvelope);
    }
  });
  document.getElementById('btnCloseBackupModal').addEventListener('click', () => showExclusiveView('settingsView'));

  // OTP Card Copy & Delete
  document.getElementById('accountsContainer').addEventListener('click', async (e) => {
    const deleteBtn = e.target.closest('[data-delete-id]');
    if (deleteBtn) {
      e.stopPropagation();
      const id = deleteBtn.getAttribute('data-delete-id');
      accounts = accounts.filter(a => a.id !== id);
      renderAccountsList();
      await persistVault();
      showToast('Removed');
      return;
    }
    const copyTarget = e.target.closest('[data-copy-otp]');
    if (copyTarget) copyTextToClipboard(copyTarget.getAttribute('data-copy-otp'));
  });

  document.getElementById('searchAccountsInput').addEventListener('input', (e) => {
    filterQuery = e.target.value.trim();
    resetSearchAutoHideTimer();
    renderAccountsList();
  });

  document.getElementById('btnToggleSecretVis').addEventListener('click', (e) => {
    const s = document.getElementById('inputSecretOrUri');
    const isPass = s.type === 'password';
    s.type = isPass ? 'text' : 'password';
    e.currentTarget.textContent = isPass ? 'Hide' : 'Show';
  });

  const qrFileInput = document.getElementById('qrFileInput');
  const qrDropzone = document.getElementById('qrDropzone');
  qrFileInput.addEventListener('change', (e) => {
    if (e.target.files && e.target.files[0]) {
      decodeQrFromFile(e.target.files[0]);
      qrFileInput.value = '';
    }
  });
  qrDropzone.addEventListener('dragover', (e) => {
    e.preventDefault();
    qrDropzone.classList.add('drag-active');
  });
  qrDropzone.addEventListener('dragleave', () => {
    qrDropzone.classList.remove('drag-active');
  });
  qrDropzone.addEventListener('drop', (e) => {
    e.preventDefault();
    qrDropzone.classList.remove('drag-active');
    if (e.dataTransfer && e.dataTransfer.files && e.dataTransfer.files[0]) {
      decodeQrFromFile(e.dataTransfer.files[0]);
    }
  });

  window.addEventListener('paste', (e) => {
    if (isLocked) return;
    const items = (e.clipboardData || e.originalEvent.clipboardData)?.items || [];
    for (const item of items) {
      if (item.type.indexOf('image') === 0) {
        const blob = item.getAsFile();
        if (blob) {
          if (currentView !== 'addAccountView') openAddQrView();
          decodeQrFromFile(blob);
          break;
        }
      }
    }
  });

  document.getElementById('btnSaveAccount').addEventListener('click', async () => {
    const errEl = document.getElementById('addModalError');
    errEl.classList.add('hidden');
    try {
      const newAcc = parseOtpInputString(
        document.getElementById('inputSecretOrUri').value,
        document.getElementById('inputIssuer').value,
        document.getElementById('inputLabel').value,
        document.getElementById('selectAlgorithm').value,
        document.getElementById('selectDigits').value
      );
      accounts.unshift(newAcc);
      showExclusiveView('otpView');
      renderAccountsList();
      await persistVault();
      showToast(`Added ${newAcc.issuer}`);
    } catch (err) {
      errEl.textContent = err.message || 'Invalid Base32 secret or otpauth URI.';
      errEl.classList.remove('hidden');
    }
  });

  // Enable Enter key on Unlock Manual PIN & Save Manual PIN inputs
  document.getElementById('unlockPinInput').addEventListener('keydown', (e) => {
    if (e.key === 'Enter') {
      e.preventDefault();
      document.getElementById('btnUnlockVault').click();
    }
  });
  document.getElementById('newPinInput').addEventListener('keydown', (e) => {
    if (e.key === 'Enter') {
      e.preventDefault();
      document.getElementById('btnSaveManualPin').click();
    }
  });

  // Unlock Vault (Manual PIN or PC Passkey)
  document.getElementById('btnUnlockVault').addEventListener('click', async () => {
    const pinInput = document.getElementById('unlockPinInput');
    const errEl = document.getElementById('unlockErrorMsg');
    errEl.classList.add('hidden');
    try {
      const env = JSON.parse(safeGetStorage(STORAGE_KEY_VAULT));
      accounts = await decryptVaultPayload(env, pinInput.value);
      sessionPin = pinInput.value;
      pinInput.value = '';
      isLocked = false;
      showExclusiveView('otpView');
      await renderAccountsList();
      showToast('Unlocked');
    } catch (err) {
      errEl.textContent = 'Incorrect PIN';
      errEl.classList.remove('hidden');
    }
  });

  document.getElementById('btnUnlockWithPasskey').addEventListener('click', async () => {
    const errEl = document.getElementById('unlockErrorMsg');
    errEl.classList.add('hidden');
    try {
      await verifyLocalPasskey();
      const env = JSON.parse(safeGetStorage(STORAGE_KEY_VAULT));
      const plainRaw = safeGetStorage(STORAGE_KEY_PLAIN_VAULT);
      accounts = (env.fastMode && plainRaw) ? JSON.parse(plainRaw) : await decryptVaultPayload(env, '');
      isLocked = false;
      showExclusiveView('otpView');
      await renderAccountsList();
      showToast('Unlocked with Passkey');
    } catch (err) {
      errEl.textContent = 'Passkey verification cancelled or failed.';
      errEl.classList.remove('hidden');
    }
  });

  document.getElementById('btnCopyBackupJson').addEventListener('click', () => copyTextToClipboard(backupArea.value));
  document.getElementById('btnRestoreBackupJson').addEventListener('click', async () => {
    try {
      const parsed = JSON.parse(backupArea.value.trim());
      if (!parsed.ct || !parsed.salt || !parsed.iv) throw new Error();
      safeSetStorage(STORAGE_KEY_VAULT, JSON.stringify(parsed));
      safeRemoveStorage(STORAGE_KEY_FAST_CACHE);
      safeRemoveStorage(STORAGE_KEY_PLAIN_VAULT);
      safeRemoveStorage(STORAGE_KEY_PRECOMPUTED_SLOTS);
      await loadInitialVault();
      showToast('Backup restored');
    } catch (err) {
      showToast('Invalid JSON backup');
    }
  });
})();


// --- Auto-Resize & Instant Wake Hook for In-Page Floating Overlay ---
function notifyOverlayHeight() {
  if (window.parent && window.parent !== window) {
    const shell = document.querySelector('.shell-container');
    if (shell) {
      const h = shell.scrollHeight;
      window.parent.postMessage({ type: 'SHIELDOTP_RESIZE', height: h }, '*');
    }
  }
}

window.addEventListener('message', (e) => {
  if (e.data && e.data.type === 'SHIELDOTP_OVERLAY_SHOWN') {
    if (!isLocked && currentView === 'otpView') {
      tickUpdateRingsInPlace();
    }
    notifyOverlayHeight();
  }
});

window.addEventListener('keydown', (e) => {
  if (e.key === 'Escape' && window.parent && window.parent !== window) {
    window.parent.postMessage({ type: 'SHIELDOTP_CLOSE_OVERLAY' }, '*');
  }
});

const resizeObserver = new ResizeObserver(() => {
  notifyOverlayHeight();
});
const shellEl = document.querySelector('.shell-container');
if (shellEl) resizeObserver.observe(shellEl);
