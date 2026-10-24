import { initializeApp } from "https://www.gstatic.com/firebasejs/10.12.0/firebase-app.js";
import { getAuth, createUserWithEmailAndPassword, signInWithEmailAndPassword, signOut, onAuthStateChanged, sendEmailVerification, sendPasswordResetEmail, updateProfile, GoogleAuthProvider, signInWithPopup, deleteUser } from "https://www.gstatic.com/firebasejs/10.12.0/firebase-auth.js";
import { initializeFirestore, persistentLocalCache, doc, setDoc, getDoc, getDocs, updateDoc, deleteDoc, collection, query, where, orderBy, onSnapshot, addDoc, serverTimestamp, writeBatch, limit, Timestamp, increment, arrayUnion, arrayRemove } from "https://www.gstatic.com/firebasejs/10.12.0/firebase-firestore.js";
import { createClient } from "https://cdn.jsdelivr.net/npm/@supabase/supabase-js@2/+esm";
import {
  initWebRTC,
  startCall as startWebRTCCall,
  acceptCall as acceptWebRTCCall,
  declineCall as declineWebRTCCall,
  hangUpCall as hangUpWebRTCCall,
  toggleAudio as toggleWebRTCAudio,
  toggleVideo as toggleWebRTCVideo,
  toggleScreenShare as toggleWebRTCScreenShare,
  getLocalStream,
  cleanUpCall,
  registerCallbacks
} from "./webrtc.js";

const FB = initializeApp({
  apiKey: "AIzaSyB5LZyLk27DTdTn655mYWd1F3q2LkPs9_8",
  authDomain: "fir-chatwave-4-supa.firebaseapp.com",
  projectId: "fir-chatwave-4-supa",
  storageBucket: "fir-chatwave-4-supa.firebasestorage.app",
  messagingSenderId: "1099317711681",
  appId: "1:1099317711681:web:0c89f8fb2eb51bb47bc7c0"
});
const auth = getAuth(FB);
// Enable IndexedDB persistence so re-opening a chat costs 0 Firestore reads (served from cache)
const db = initializeFirestore(FB, { localCache: persistentLocalCache() });

// ── SUPABASE CLIENT (HYBRID PRESENCE & REALTIME) ──
const SUPABASE_URL = "https://cejtngzybawccjqlaabq.supabase.co";
const SUPABASE_ANON_KEY = "sb_publishable_JRfPBYe9BFV5VWKno1km5A_kfwoXyDZ";

const supabase = createClient(SUPABASE_URL, SUPABASE_ANON_KEY, {
  auth: {
    persistSession: false,
    autoRefreshToken: false,
  },
  accessToken: async () => {
    if (!auth.currentUser) return null;
    return (await auth.currentUser.getIdToken(false)) ?? null;
  }
});

// Initialize WebRTC engine with Firestore and Supabase instances
initWebRTC({ db, supabase });



// ── STATE ──
let currentUser = null;
let currentConvId = null;
let currentPeer = null;
let unsubMsgs = null;
let unsubConvs = null;
let unsubPeerPresence = null; // Firestore peer presence listener
let ctxMsgId = null;
let ctxMsgData = null;
let allConvs = [];
let swRegistration = null;
let totalUnread = 0;
let knownMsgIds = new Set();
let myClearedAt = null; // Firestore Timestamp — messages older than this are hidden for me
let myBlockedUsers = [];  // list of UIDs blocked by current user
let amIBlocked = false;   // true when the PEER has blocked ME (shadow-block mode)
let currentLinkPreview = null; // { url, title, description, image, domain } | null
let linkPreviewTimer = null;
let replyingTo = null;

// ── USER CACHE FOR FIRESTORE (Minimizes Reads) ──
const usersCache = new Map();

async function fetchUserCached(uid) {
  if (!uid) return null;
  if (usersCache.has(uid)) {
    return usersCache.get(uid);
  }
  try {
    const snap = await getDoc(doc(db, "users", uid));
    if (snap.exists()) {
      const data = snap.data();
      usersCache.set(uid, data);
      return data;
    }
  } catch (err) {
    console.warn("Failed to fetch user data for cache", err);
  }
  return null;
}

// ── E2EE CRYPTO UTILITIES ──
let myPrivateKey = null;
let currentSharedKey = null;

// ── E2EE PIN UI CONTROLLER ──
let pinResolve = null;

window.askPin = (title, desc) => {
  return new Promise((resolve) => {
    const modal = document.getElementById("pin-modal");
    document.getElementById("pin-title").textContent = title;
    document.getElementById("pin-desc").textContent = desc;
    const inp = document.getElementById("pin-input");
    inp.value = ""; // Clear old input
    modal.classList.remove("hidden");
    // Ensure splash screen doesn't block it
    const splash = document.getElementById("splash-screen");
    if(splash) splash.style.zIndex = "999"; 
    setTimeout(() => inp.focus(), 100);

    pinResolve = resolve;
  });
};

document.getElementById("pin-submit")?.addEventListener("click", () => {
  const val = document.getElementById("pin-input").value;
  document.getElementById("pin-modal").classList.add("hidden");
  if (pinResolve) pinResolve(val);
});

document.getElementById("pin-cancel")?.addEventListener("click", () => {
  document.getElementById("pin-modal").classList.add("hidden");
  if (pinResolve) pinResolve(null);
});

// Submit when pressing Enter
document.getElementById("pin-input")?.addEventListener("keydown", (e) => {
  if (e.key === "Enter") document.getElementById("pin-submit").click();
});

// ── PIN-BASED KEY VAULT (Like WhatsApp) ──
async function deriveKeyFromPIN(pin) {
  const enc = new TextEncoder();
  const keyMaterial = await window.crypto.subtle.importKey(
    "raw", enc.encode(pin), { name: "PBKDF2" }, false, ["deriveBits", "deriveKey"]
  );
  // We use the user's UID as a "salt" to make the hash mathematically unique to them
  const salt = enc.encode(currentUser.uid + "chatwave_secure_salt");
  return window.crypto.subtle.deriveKey(
    { name: "PBKDF2", salt: salt, iterations: 100000, hash: "SHA-256" },
    keyMaterial, { name: "AES-GCM", length: 256 }, true, ["encrypt", "decrypt"]
  );
}

async function loadMyPrivateKey(userDbData) {
  const stored = localStorage.getItem(`privKey_${currentUser.uid}`);
  const unlockBtn = document.getElementById("unlock-chats-btn");
  if (unlockBtn) unlockBtn.classList.add("hidden"); // Hide by default
  
  if (stored) {
    // 1. PERFECT SCENARIO: Key is on device.
    myPrivateKey = await window.crypto.subtle.importKey(
      "jwk", JSON.parse(stored), { name: "ECDH", namedCurve: "P-256" }, true, ["deriveKey", "deriveBits"]
    );
    return null; 
  } 
  
  if (userDbData && userDbData.encryptedPrivKey) {
    // 2. NEW DEVICE DETECTED: Ask for PIN using custom UI
    let success = false;
    while (!success) {
      const pin = await askPin("New Device Detected", "Enter your 6-digit PIN to restore your encrypted messages.");
      
      if (!pin) {
        // User clicked cancel! Show the button in the profile so they can try later.
        toast("Messages remain locked. Go to Profile to unlock.", "info");
        if (unlockBtn) unlockBtn.classList.remove("hidden");
        return null;
      }
      
      try {
        const wrappingKey = await deriveKeyFromPIN(pin);
        const decryptedStr = await decryptText(userDbData.encryptedPrivKey, wrappingKey);
        if (decryptedStr.includes("🔒 [Encrypted Message]")) throw new Error("Wrong PIN");
        
        myPrivateKey = await window.crypto.subtle.importKey(
          "jwk", JSON.parse(decryptedStr), { name: "ECDH", namedCurve: "P-256" }, true, ["deriveKey", "deriveBits"]
        );
        localStorage.setItem(`privKey_${currentUser.uid}`, decryptedStr);
        toast("Keys restored! Unencrypting...", "ok");
        success = true;
        setTimeout(() => window.location.reload(), 1000); // Reload to unencrypt
      } catch (err) {
        toast("Incorrect PIN. Please try again.", "err");
      }
    }
    return null;
  } 
  
  // 3. BRAND NEW ACCOUNT: Create PIN using custom UI
  let newPin = await askPin("Welcome to ChatWave Ultra!", "Create a 6-digit PIN to backup your encrypted chats. Don't forget it!");

  const keyPair = await window.crypto.subtle.generateKey(
    { name: "ECDH", namedCurve: "P-256" }, true, ["deriveKey", "deriveBits"]
  );
  
  const pubKeyJwk = await window.crypto.subtle.exportKey("jwk", keyPair.publicKey);
  const privKeyJwk = await window.crypto.subtle.exportKey("jwk", keyPair.privateKey);
  const privKeyStr = JSON.stringify(privKeyJwk);
  
  localStorage.setItem(`privKey_${currentUser.uid}`, privKeyStr);
  myPrivateKey = keyPair.privateKey;

  const result = { pubKeyJwk };

  // 👈 THE FIX: Only encrypt and upload if they actually provided a PIN
  if (newPin && newPin.length >= 4) {
    const wrappingKey = await deriveKeyFromPIN(newPin);
    result.encryptedPrivKey = await encryptText(privKeyStr, wrappingKey);
  } else {
    toast("E2EE Cloud Backup skipped. You can enable it in your Profile later.", "info");
  }

  return result; 
}

async function deriveSharedKey(peerPubKeyJwk) {
  if (!myPrivateKey || !peerPubKeyJwk) return null;
  const peerPubKey = await window.crypto.subtle.importKey(
    "jwk", peerPubKeyJwk, { name: "ECDH", namedCurve: "P-256" }, true, []
  );
  return await window.crypto.subtle.deriveKey(
    { name: "ECDH", public: peerPubKey }, myPrivateKey,
    { name: "AES-GCM", length: 256 }, true, ["encrypt", "decrypt"]
  );
}

function uint8ToBase64(bytes) {
  let binary = "";
  const len = bytes.byteLength;
  const chunkSize = 8192;
  for (let i = 0; i < len; i += chunkSize) {
    const chunk = bytes.subarray(i, Math.min(i + chunkSize, len));
    binary += String.fromCharCode.apply(null, chunk);
  }
  return btoa(binary);
}

function base64ToUint8(base64) {
  const binary = atob(base64);
  const len = binary.length;
  const bytes = new Uint8Array(len);
  for (let i = 0; i < len; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

async function encryptText(text, sharedKey) {
  if (!text || !sharedKey) return text;
  const iv = window.crypto.getRandomValues(new Uint8Array(12));
  const encodedText = new TextEncoder().encode(text);
  const cipherBuffer = await window.crypto.subtle.encrypt({ name: "AES-GCM", iv: iv }, sharedKey, encodedText);
  // Combine IV and Ciphertext into one Base64 string for easy Firebase storage
  const combined = new Uint8Array(iv.length + cipherBuffer.byteLength);
  combined.set(iv, 0);
  combined.set(new Uint8Array(cipherBuffer), iv.length);
  return uint8ToBase64(combined);
}

async function decryptText(base64Cipher, sharedKey) {
  if (!base64Cipher || !sharedKey) return base64Cipher;
  try {
    const combined = base64ToUint8(base64Cipher);
    if (combined.length < 13) return base64Cipher;
    const iv = combined.slice(0, 12);
    const data = combined.slice(12);
    const decryptedBuffer = await window.crypto.subtle.decrypt({ name: "AES-GCM", iv: iv }, sharedKey, data);
    return new TextDecoder().decode(decryptedBuffer);
  } catch (err) {
    return "🔒 [Encrypted Message]"; // Failsafe if keys don't match
  }
}

// ── CHANGE PIN & FORCE UNLOCK ──
window.changeE2EEPin = async () => {
  closeModal("profile-modal");
  const userSnap = await getDoc(doc(db, "users", currentUser.uid));
  const dbData = userSnap.exists() ? userSnap.data() : null;

  const hasBackup = dbData && dbData.encryptedPrivKey;
  let decryptedStr;

  if (hasBackup) {
    // Step 1: Verify current PIN because a backup exists
    const oldPin = await askPin("Change PIN (Step 1 of 2)", "Enter your CURRENT 6-digit PIN.");
    if (!oldPin) return;

    try {
      const oldWrappingKey = await deriveKeyFromPIN(oldPin);
      decryptedStr = await decryptText(dbData.encryptedPrivKey, oldWrappingKey);
      if (decryptedStr.includes("🔒 [Encrypted Message]")) throw new Error("Wrong PIN");
    } catch (err) {
      return toast("Incorrect current PIN. Action cancelled.", "err");
    }
  } else {
    // NO BACKUP EXISTS YET: Grab the raw key directly from their browser storage
    decryptedStr = localStorage.getItem(`privKey_${currentUser.uid}`);
    if (!decryptedStr) return toast("Error: Private key missing from this device.", "err");
  }

  // Step 2: Enter new PIN
  const promptTitle = hasBackup ? "Change PIN (Step 2 of 2)" : "Setup E2EE Backup";
  const newPin = await askPin(promptTitle, "Create a new 6-digit PIN to secure your backup.");
  if (!newPin || newPin.length < 4) return toast("Invalid PIN. Cancelled.", "err");

  // Step 3: Encrypt and save to the Cloud Vault
  const newWrappingKey = await deriveKeyFromPIN(newPin);
  const newEncryptedPrivKey = await encryptText(decryptedStr, newWrappingKey);

  await updateDoc(doc(db, "users", currentUser.uid), { encryptedPrivKey: newEncryptedPrivKey });
  
  // Dynamically update the button text in the UI to reflect the new state
  document.querySelector(`button[onclick="changeE2EEPin()"]`).textContent = "Change Security PIN";
  toast(hasBackup ? "E2EE PIN changed successfully! ✓" : "E2EE Backup enabled! ✓", "ok");
};

window.forceUnlockKeys = async () => {
  closeModal("profile-modal");
  const userSnap = await getDoc(doc(db, "users", currentUser.uid));
  const dbData = userSnap.exists() ? userSnap.data() : null;
  // This will trigger the PIN modal again
  await loadMyPrivateKey(dbData);
};

let myReportedReadIds = {}; // Local memory to stop race conditions
let pendingReadReceipt = null;

// Only sends the read receipt if the user is ACTUALLY looking at the chat
function trySendReadReceipt() {
  if (document.visibilityState === 'visible' && document.hasFocus() && pendingReadReceipt && currentConvId === pendingReadReceipt.convId) {
    updateDoc(doc(db, "conversations", pendingReadReceipt.convId), {
      [`lastReadId.${currentUser.uid}`]: pendingReadReceipt.msgId,
      [`lastReadTs.${currentUser.uid}`]: pendingReadReceipt.ts || serverTimestamp(),
      [`unread.${currentUser.uid}`]: 0
    }).catch(()=>{});
    
    pendingReadReceipt = null; // Clear it out so we don't spam writes
  }
}

// Fire this whenever the user returns to the tab or clicks inside the window
window.addEventListener('focus', trySendReadReceipt);
document.addEventListener('visibilitychange', trySendReadReceipt);


// ── HELPERS ──
const esc = (str) => String(str || '').replace(/[&<>"']/g, m => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[m]));
window.esc = esc;

window.toast = (msg, type = "info") => {
  const el = document.createElement("div");
  el.className = `toast ${type}`;
  el.textContent = msg;
  document.getElementById("toasts").appendChild(el);
  setTimeout(() => el.remove(), 3200);
};
window.setLoading = (btnId, on) => {
  const b = document.getElementById(btnId);
  if (!b) return;
  b.querySelector(".bt").classList.toggle("hidden", on);
  b.querySelector(".bl").classList.toggle("hidden", !on);
  b.disabled = on;
};
window.showErr = (msg) => {
  const el = document.getElementById("auth-err");
  el.textContent = msg;
  el.classList.remove("hidden");
  setTimeout(() => el.classList.add("hidden"), 5000);
};
window.openModal = (id) => document.getElementById(id).classList.remove("hidden");
window.closeModal = (id) => document.getElementById(id).classList.add("hidden");
window.maybeCloseModal = (e, id) => { if (e.target === e.currentTarget) closeModal(id); };

const initials = (name) => name ? name.split(" ").map(w => w[0]).join("").toUpperCase().slice(0, 2) : "?";
const avatarEl = (el, name, url) => { el.innerHTML = url ? `<img src="${esc(url)}" />` : esc(initials(name)); };
const fmtTime = (ts) => { if (!ts) return ""; const d = ts.toDate ? ts.toDate() : new Date(ts); return d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" }); };
const fmtDate = (ts) => { if (!ts) return ""; const d = ts.toDate ? ts.toDate() : new Date(ts); const now = new Date(); if (d.toDateString() === now.toDateString()) return "Today"; const y = new Date(now); y.setDate(y.getDate() - 1); if (d.toDateString() === y.toDateString()) return "Yesterday"; return d.toLocaleDateString([], { month: "short", day: "numeric" }); };

// ── TAB SWITCH ──
window.switchTab = (t) => {
  ["login", "reg"].forEach(x => {
    document.getElementById(`tab-${x}`).classList.toggle("active", x === t);
    document.getElementById(`form-${x}`).classList.toggle("active", x === t);
  });
  document.getElementById("verify-notice").classList.add("hidden");
  document.getElementById("auth-err").classList.add("hidden");
};
window.togglePw = (id, btn) => {
  const inp = document.getElementById(id);
  inp.type = inp.type === "password" ? "text" : "password";
  btn.textContent = inp.type === "password" ? "👁" : "🙈";
};

// ── AUTH ──
window.doLogin = async (e) => {
  e.preventDefault();
  const email = document.getElementById("li-email").value.trim();
  const pw = document.getElementById("li-pw").value;
  setLoading("li-btn", true);
  try {
    const cred = await signInWithEmailAndPassword(auth, email, pw);
    if (!cred.user.emailVerified) {
      await signOut(auth);
      document.getElementById("vfy-email").textContent = email;
      document.getElementById("verify-notice").classList.remove("hidden");
      document.getElementById("form-login").classList.remove("active");
      setLoading("li-btn", false);
      return;
    }
  } catch (err) { showErr(friendlyErr(err)); setLoading("li-btn", false); }
};

window.doRegister = async (e) => {
  e.preventDefault();
  const name = document.getElementById("rg-name").value.trim();
  const email = document.getElementById("rg-email").value.trim();
  const phone = document.getElementById("rg-phone").value.trim();
  const pw = document.getElementById("rg-pw").value;
  setLoading("rg-btn", true);
  try {
    const cred = await createUserWithEmailAndPassword(auth, email, pw);
    await updateProfile(cred.user, { displayName: name });
    await sendEmailVerification(cred.user);
    await setDoc(doc(db, "users", cred.user.uid), {
      uid: cred.user.uid, name, email, phone: phone || "", photoURL: "", statusMsg: "Hey! I'm using ChatWave Ultra", createdAt: serverTimestamp()
    });
    await signOut(auth);
    document.getElementById("vfy-email").textContent = email;
    document.getElementById("form-reg").classList.remove("active");
    document.getElementById("verify-notice").classList.remove("hidden");
  } catch (err) { showErr(friendlyErr(err)); }
  setLoading("rg-btn", false);
};

window.doGoogle = async () => {
  try {
    const provider = new GoogleAuthProvider();
    const cred = await signInWithPopup(auth, provider);
    const u = cred.user;
    const ref = doc(db, "users", u.uid);
    const snap = await getDoc(ref);
    if (!snap.exists()) {
      await setDoc(ref, { uid: u.uid, name: u.displayName || "User", email: u.email, phone: "", photoURL: u.photoURL || "", statusMsg: "Hey! I'm using ChatWave Ultra", createdAt: serverTimestamp() });
    }
  } catch (err) { showErr(friendlyErr(err)); }
};

window.doForgot = async () => {
  const email = document.getElementById("li-email").value.trim();
  if (!email) { showErr("Enter your email first."); return; }
  try { await sendPasswordResetEmail(auth, email); toast("Password reset email sent!", "ok"); }
  catch (err) { showErr(friendlyErr(err)); }
};

window.doResend = async () => {
  try {
    const email = document.getElementById("li-email").value.trim() || document.getElementById("rg-email").value.trim();
    const pw = document.getElementById("li-pw").value || document.getElementById("rg-pw").value;
    if (email && pw) {
      const cred = await signInWithEmailAndPassword(auth, email, pw);
      await sendEmailVerification(cred.user);
      await signOut(auth);
    }
    toast("Verification email resent!", "ok");
  } catch { toast("Could not resend. Try again.", "err"); }
};

// ── ROBUST REALTIME PRESENCE SYSTEM (Multi-Tab Safe & Instant) ──
let presenceChannel = null;
let offlineTimer = null;
let isSubscribing = false;
const clientSessionId = Math.random().toString(36).substring(2, 9);

function isTabVisible() {
  return document.visibilityState === 'visible';
}

async function reportPresenceDb(isOnline) {
  if (!currentUser) return;
  const nowIso = new Date().toISOString();
  try {
    await supabase.from("user_presence").upsert({
      user_id: currentUser.uid,
      is_online: isOnline,
      last_seen: nowIso,
      updated_at: nowIso
    });
  } catch (err) {
    console.warn("Presence DB update error:", err);
  }
}

function sendBeaconOffline() {
  if (!currentUser) return;
  const nowIso = new Date().toISOString();
  const url = `${SUPABASE_URL}/rest/v1/user_presence?apikey=${SUPABASE_ANON_KEY}`;
  const payload = JSON.stringify({
    user_id: currentUser.uid,
    is_online: false,
    last_seen: nowIso,
    updated_at: nowIso
  });
  
  try {
    fetch(url, {
      method: "POST",
      headers: {
        "apikey": SUPABASE_ANON_KEY,
        "Content-Type": "application/json",
        "Prefer": "resolution=merge-duplicates"
      },
      body: payload,
      keepalive: true
    }).catch(() => {});
  } catch {}

  try {
    navigator.sendBeacon?.(
      url,
      new Blob([payload], { type: "application/json; charset=UTF-8" })
    );
  } catch {}
}

async function trackOnline() {
  if (!currentUser || !presenceChannel || presenceChannel.state !== 'joined') return;
  try {
    await presenceChannel.track({
      uid: currentUser.uid,
      session: clientSessionId,
      online: true,
      updated_at: new Date().toISOString()
    });
  } catch (err) {
    console.warn("Presence track warning:", err);
  }
}

function startSupabasePresence() {
  if (!currentUser || isSubscribing) return;
  isSubscribing = true;

  if (presenceChannel) {
    try { presenceChannel.unsubscribe(); } catch {}
    presenceChannel = null;
  }

  presenceChannel = supabase.channel("online-users", {
    config: { presence: { key: `${currentUser.uid}:${clientSessionId}` } }
  });

  const onPresenceUpdate = () => {
    if (currentPeer) {
      syncPeerPresenceState(currentPeer.id);
    }
  };

  presenceChannel
    .on("presence", { event: "sync" }, onPresenceUpdate)
    .on("presence", { event: "join" }, onPresenceUpdate)
    .on("presence", { event: "leave" }, onPresenceUpdate)
    .subscribe(async (status) => {
      isSubscribing = false;
      if (status === "SUBSCRIBED") {
        if (isTabVisible()) {
          await trackOnline();
          await reportPresenceDb(true);
        }
        if (currentPeer) {
          syncPeerPresenceState(currentPeer.id);
        }
      }
    });
}

function stopSupabasePresence() {
  if (presenceChannel) {
    try {
      presenceChannel.untrack();
      presenceChannel.unsubscribe();
    } catch {}
    presenceChannel = null;
  }
  reportPresenceDb(false);
}

// ── TAB & FOCUS LIFECYCLE HANDLERS ──
function handleTabActive() {
  if (!currentUser) return;
  if (offlineTimer) {
    clearTimeout(offlineTimer);
    offlineTimer = null;
  }

  if (!presenceChannel || presenceChannel.state !== 'joined') {
    startSupabasePresence();
  } else {
    trackOnline();
    reportPresenceDb(true);
  }

  if (currentPeer) {
    syncPeerPresenceState(currentPeer.id);
  }
}

function handleTabInactive() {
  if (!currentUser) return;
  if (offlineTimer) clearTimeout(offlineTimer);

  // 3-second grace period: prevents rapid flickering on quick tab switching
  offlineTimer = setTimeout(async () => {
    if (document.visibilityState === 'hidden') {
      if (presenceChannel && presenceChannel.state === 'joined') {
        try {
          await presenceChannel.track({
            uid: currentUser.uid,
            session: clientSessionId,
            online: false,
            updated_at: new Date().toISOString()
          });
        } catch {}
      }
      await reportPresenceDb(false);
    }
  }, 3000);
}

document.addEventListener('visibilitychange', () => {
  if (document.visibilityState === 'visible') {
    handleTabActive();
  } else {
    handleTabInactive();
  }
});

window.addEventListener('pageshow', handleTabActive);
window.addEventListener('focus', handleTabActive);

window.addEventListener('pagehide', () => {
  sendBeaconOffline();
});

window.addEventListener('beforeunload', () => {
  sendBeaconOffline();
});

// Periodic heartbeat (every 25s) to guarantee presence channel stays joined
setInterval(() => {
  if (currentUser && document.visibilityState === 'visible') {
    if (!presenceChannel || presenceChannel.state !== 'joined') {
      startSupabasePresence();
    } else {
      trackOnline();
    }
  }
}, 25000);

window.doLogout = async () => {
  stopSupabasePresence();
  await signOut(auth);
};

const friendlyErr = (err) => {
  const m = { "auth/user-not-found": "No account with that email.", "auth/wrong-password": "Incorrect password.", "auth/email-already-in-use": "Email already registered.", "auth/invalid-email": "Invalid email address.", "auth/weak-password": "Password too weak (min 6 chars).", "auth/too-many-requests": "Too many attempts. Try again later.", "auth/popup-closed-by-user": "Google sign-in cancelled." };
  return m[err.code] || err.message || "Something went wrong.";
};

// ── AUTH STATE ──
onAuthStateChanged(auth, async (user) => {
  if (user && user.emailVerified) {
    currentUser = user;
    
    // Fetch the user's current Firestore data first to preserve E2EE keys & custom profiles
    const myUserSnap = await getDoc(doc(db, "users", user.uid));
    const myUserData = myUserSnap.exists() ? myUserSnap.data() : null;

    // Run the Smart Loader using Firestore data
    const newKeys = await loadMyPrivateKey(myUserData);

    // Write Firestore profile (Only basic info now, NO KEYS unless new ones generated!)
    const profileUpdate = {
      uid: user.uid,
      name: myUserData?.name || user.displayName || "User",
      email: user.email,
      phone: myUserData?.phone || "",
      photoURL: myUserData?.photoURL || user.photoURL || "",
      createdAt: myUserData?.createdAt || serverTimestamp()
    };

    // If new keys were generated, store them in the Firestore document
    if (newKeys) {
      profileUpdate.publicKey = newKeys.pubKeyJwk;
      profileUpdate.encryptedPrivKey = newKeys.encryptedPrivKey || "";
    }

    await setDoc(doc(db, "users", user.uid), profileUpdate, { merge: true });
    
    // Connect to Supabase Presence (Realtime WebSocket)
    startSupabasePresence();
    
    document.getElementById("splash-screen").classList.remove("active");
    document.getElementById("auth-screen").classList.remove("active");
    document.getElementById("app-screen").classList.add("active");
    loadMyProfile();
    setupNotifications();
    // ── Pre-load blocked list BEFORE first listenConversations call ──
    // This prevents blocked conversations from briefly appearing on first render
    myBlockedUsers = myUserData?.blockedUsers || [];
    listenConversations();
    startIncomingCallsListener(user.uid);
    // ── Live-sync blocked users from Firestore ──
    onSnapshot(doc(db, "users", user.uid), (snap) => {
      const prev = [...myBlockedUsers];
      myBlockedUsers = snap.data()?.blockedUsers || [];
      // Re-render sidebar if block list changed so blocked chats disappear instantly
      if (JSON.stringify(prev) !== JSON.stringify(myBlockedUsers)) {
        if (unsubConvs) { unsubConvs(); unsubConvs = null; }
        listenConversations();
        // Close the currently open chat if the peer was just blocked
        if (currentPeer && myBlockedUsers.includes(currentPeer.id)) {
          closeChat();
          toast('Chat closed — you blocked this user.', 'info');
        }
      }
    });
  } else {
    stopSupabasePresence();
    stopIncomingCallsListener();
    endActiveCallUI();
    currentUser = null;
    document.getElementById("splash-screen").classList.remove("active");
    document.getElementById("auth-screen").classList.add("active");
    document.getElementById("app-screen").classList.remove("active");
    if (unsubConvs) { unsubConvs(); unsubConvs = null; }
    if (unsubMsgs) { unsubMsgs(); unsubMsgs = null; }
    if (unsubPeerPresence) { unsubPeerPresence(); unsubPeerPresence = null; }
  }
});

// ── NOTIFICATIONS ──
async function setupNotifications() {
  // Register Service Worker
  if ('serviceWorker' in navigator) {
    try {
      swRegistration = await navigator.serviceWorker.register('/sw.js');
    } catch (e) { console.warn('SW registration failed:', e); }
  }
  // Request notification permission
  if ('Notification' in window && Notification.permission === 'default') {
    const perm = await Notification.requestPermission();
    if (perm === 'granted') toast('🔔 Notifications enabled!', 'ok');
  }
}

function playNotifSound() {
  try {
    const ctx = new (window.AudioContext || window.webkitAudioContext)();
    const osc = ctx.createOscillator();
    const gain = ctx.createGain();
    osc.connect(gain);
    gain.connect(ctx.destination);
    osc.frequency.setValueAtTime(880, ctx.currentTime);
    osc.frequency.setValueAtTime(660, ctx.currentTime + 0.1);
    gain.gain.setValueAtTime(0.3, ctx.currentTime);
    gain.gain.exponentialRampToValueAtTime(0.001, ctx.currentTime + 0.4);
    osc.start(ctx.currentTime);
    osc.stop(ctx.currentTime + 0.4);
  } catch (e) { /* audio not supported */ }
}

function updateTitleBadge(count) {
  totalUnread = count;
  document.title = count > 0 ? `(${count}) ChatWave Ultra` : 'ChatWave Ultra';
}

function showBrowserNotif(title, body) {
  if (!('Notification' in window) || Notification.permission !== 'granted') return;
  // Don't notify if tab is focused
  if (document.visibilityState === 'visible' && document.hasFocus()) return;
  if (swRegistration) {
    // Use Service Worker for rich notification
    swRegistration.active?.postMessage({
      type: 'SHOW_NOTIFICATION',
      title,
      body,
      icon: '/icon.png',
      tag: 'chatwave-msg'
    });
  } else {
    // Fallback: direct Notification API
    new Notification(title, { body, icon: '/icon.png', tag: 'chatwave-msg' });
  }
}

// ── PROFILE ──
async function loadMyProfile() {
  const snap = await getDoc(doc(db, "users", currentUser.uid));
  if (!snap.exists()) return;
  const d = snap.data();
  document.getElementById("my-name").textContent = d.name || currentUser.displayName || "You";
  avatarEl(document.getElementById("my-av"), d.name, d.photoURL);
  document.getElementById("pf-av").innerHTML = d.photoURL ? `<img src="${esc(d.photoURL)}"/>` : esc(initials(d.name));
  document.getElementById("pf-name").value = d.name || "";
  document.getElementById("pf-status").value = d.statusMsg || "";
  document.getElementById("pf-phone").value = d.phone || "";
  document.getElementById("pf-email").textContent = d.email || currentUser.email;
  if (currentUser.emailVerified) document.getElementById("pf-verified").classList.remove("hidden");
}

window.saveProfile = async () => {
  const name = document.getElementById("pf-name").value.trim();
  const statusMsg = document.getElementById("pf-status").value.trim();
  const phone = document.getElementById("pf-phone").value.trim();
  try {
    const profileData = { name, statusMsg, phone };
    await updateDoc(doc(db, "users", currentUser.uid), profileData);
    
    // Update local cache
    const existingCache = usersCache.get(currentUser.uid) || {};
    usersCache.set(currentUser.uid, { ...existingCache, ...profileData });

    await updateProfile(currentUser, { displayName: name });
    document.getElementById("my-name").textContent = name;
    avatarEl(document.getElementById("my-av"), name, currentUser.photoURL);
    closeModal("profile-modal");
    toast("Profile updated!", "ok");
  } catch { toast("Failed to update profile.", "err"); }
};

window.uploadAv = async (e) => {
  const file = e.target.files[0];
  if (!file) return;

  // Let the user know the upload is starting
  toast("Uploading profile photo...", "info");

  try {
    // 1. Prepare the image for Cloudinary
    const fd = new FormData();
    fd.append("file", file);
    fd.append("upload_preset", "chatwave-ultra-profile"); // 👈 Your new preset!

    // 2. Upload to your existing Cloudinary cloud (dogwrel9i)
    const res = await fetch("https://api.cloudinary.com/v1_1/dogwrel9i/image/upload", {
      method: "POST",
      body: fd
    });
    
    if (!res.ok) throw new Error(`Cloudinary Error: ${res.status}`);
    const json = await res.json();
    const secure_url = json.secure_url; // The clean image link

    // 3. Save the clean URL to Firestore
    await updateDoc(doc(db, "users", currentUser.uid), { photoURL: secure_url });
    
    // Update local cache
    const existingCache = usersCache.get(currentUser.uid) || {};
    usersCache.set(currentUser.uid, { ...existingCache, photoURL: secure_url });
    
    // 4. Update Firebase Auth Profile memory
    await updateProfile(currentUser, { photoURL: secure_url });

    // 5. Update the UI instantly
    document.getElementById("pf-av").innerHTML = `<img src="${esc(secure_url)}"/>`;
    avatarEl(document.getElementById("my-av"), "", secure_url);
    
    toast("Profile photo updated successfully! ✓", "ok");
  } catch (err) {
    console.error("Avatar Upload Error:", err);
    toast("Failed to upload photo: " + err.message, "err");
  }
};

window.deleteAccount = async () => {
  if (!confirm("Delete your account? This cannot be undone.")) return;
  try {
    await deleteDoc(doc(db, "users", currentUser.uid));
    await deleteUser(currentUser);
    toast("Account deleted.", "ok");
  } catch { toast("Re-login required to delete account.", "err"); }
};

// ── CONVERSATIONS ──
let prevUnreadTotal = 0; // track previous total to detect new incoming messages
function listenConversations() {
  const q = query(collection(db, "conversations"), where("participants", "array-contains", currentUser.uid));
  unsubConvs = onSnapshot(q, async (snap) => {
    const list = document.getElementById("conv-list");
    const empty = document.getElementById("empty-convs");
    
    // Generate a unique ID for this render pass to abort stale updates
    const currentRenderId = Date.now().toString() + Math.random().toString();
    list.dataset.renderId = currentRenderId;

    if (snap.empty) { 
      list.innerHTML = "";
      list.appendChild(empty);
      empty.classList.remove("hidden"); 
      allConvs = [];
      return; 
    }
    
    const docs = snap.docs.map(d => ({ id: d.id, ...d.data() }));
    docs.sort((a, b) => {
      const ta = a.lastAt?.toMillis?.() || 0;
      const tb = b.lastAt?.toMillis?.() || 0;
      return tb - ta;
    });

    let unreadTotal = 0;
    const validDocs = [];
    allConvs = [];

    for (const data of docs) {
      if (data.hiddenUI?.[currentUser.uid] === true) {
        if (currentConvId === data.id) {
          closeChat();
          toast("This conversation was deleted.", "info");
        }
        continue;
      }
      const peerId = data.participants?.find(p => p !== currentUser.uid);
      if (peerId && myBlockedUsers.includes(peerId)) continue; // ── block filter
      
      if (currentConvId === data.id) {
        const newClearedAt = data.cleared?.[currentUser.uid] || null;
        const oldMs = myClearedAt?.toMillis?.() || 0;
        const newMs = newClearedAt?.toMillis?.() || 0;
        
        if (newMs > oldMs) {
          myClearedAt = newClearedAt;
          listenMessages(currentConvId); // Re-run the message listener with the new filter
        }
      }
      unreadTotal += (data.unread || {})[currentUser.uid] || 0;
      validDocs.push(data);
      allConvs.push(data);
    }
    
    // Zero-Cost Blue Ticks: Live sync without reloading DOM
    if (currentConvId) {
      updateBlueTicks(currentConvId);
    }

    // Pre-fetch peers in parallel to preserve order and prevent race conditions
    const renderItems = await Promise.all(validDocs.map(async conv => {
      const peerId = conv.participants.find(p => p !== currentUser.uid);
      if (!peerId) return null;
      
      // Fetch user profile from cache (or Firestore if not cached)
      const cached = await fetchUserCached(peerId);
      const peer = cached 
          ? { name: cached.name, photoURL: cached.photoURL } 
          : { name: "Unknown", photoURL: "" };
      
      return { conv, peerId, peer };
    }));

    // Abort if another snapshot arrived while we were fetching
    if (list.dataset.renderId !== currentRenderId) return;

    // Synchronously update the DOM
    list.innerHTML = "";
    list.appendChild(empty);

    if (renderItems.length === 0) {
      empty.classList.remove("hidden");
    } else {
      empty.classList.add("hidden");
      for (const item of renderItems) {
        if (!item) continue;
        renderConvItemSync(item.conv, item.peerId, item.peer, list);
      }
    }

    updateTitleBadge(unreadTotal);
    // ── Global notification: fire when unread total rises (message in any conversation) ──
    if (unreadTotal > prevUnreadTotal) {
      playNotifSound();
      showBrowserNotif('New Message', 'You have a new message');
    }
    prevUnreadTotal = unreadTotal;
  });
}

function updateBlueTicks(convId) {
  if (currentConvId !== convId) return;
  const convData = allConvs.find(c => c.id === convId);
  if (!convData) return;
  
  const peerReadId = convData.lastReadId?.[currentPeer?.id];
  const peerReadTs = convData.lastReadTs?.[currentPeer?.id]?.toMillis?.() || 0;
  
  const myMsgs = Array.from(document.querySelectorAll(".msg-row.me"));
  let foundBoundary = false;
  
  // Loop backwards (from newest message at the bottom, to oldest at the top)
  for (let i = myMsgs.length - 1; i >= 0; i--) {
    const row = myMsgs[i];
    const statusSpan = row.querySelector(".msg-status");
    if (!statusSpan) continue;
    
    const msgTime = parseInt(row.dataset.createdAt || "0", 10);
    if (msgTime === 0) {
      // Message is still pending write
      statusSpan.className = "msg-status sent";
      continue;
    }
    
    // 1. EXACT ID MATCH: Bypasses time completely. If we hit the ID they saw, this and everything above is read.
    if (row.dataset.id === peerReadId) {
      foundBoundary = true;
    }
    
    // 2. TIMESTAMP FALLBACK: Only triggers if the exact message ID was soft-deleted from the DOM
    if (!foundBoundary && peerReadTs > 0 && msgTime <= peerReadTs) {
      foundBoundary = true;
    }
    
    statusSpan.className = `msg-status ${foundBoundary ? 'read' : 'sent'}`;
  }
}

function renderConvItemSync(conv, peerId, peer, container) {
  const item = document.createElement("div");
  item.className = `conv-item${conv.id === currentConvId ? " active" : ""}`;
  item.id = `conv-${conv.id}`;
  item.onclick = () => openChat(conv.id, peerId, peer);
  const unread = (conv.unread || {})[currentUser.uid] || 0;
  
  // Pull status message from our Firestore cache!
  const statusMsg = usersCache.get(peerId)?.statusMsg || "Available";

  item.innerHTML = `
    <div class="av">${peer.photoURL ? `<img src="${esc(peer.photoURL)}"/>` : esc(initials(peer.name))}</div>
    <div class="conv-meta">
      <div class="conv-name">${esc(peer.name)}</div>
      <div class="conv-last">${esc(statusMsg)}</div> 
    </div>
    <div class="conv-right">
      <span class="conv-time">${esc(fmtTime(conv.lastAt))}</span>
      ${unread > 0 ? `<span class="unread-badge">${unread}</span>` : ""}
    </div>`;
  container.appendChild(item);
}

window.filterConvs = (val) => {
  document.querySelectorAll(".conv-item").forEach(el => {
    const name = el.querySelector(".conv-name")?.textContent.toLowerCase() || "";
    el.style.display = name.includes(val.toLowerCase()) ? "" : "none";
  });
};

// ── FIND USER ──
let findTimer = null;
window.findUser = (val) => {
  clearTimeout(findTimer);
  const res = document.getElementById("find-result");
  if (!val || val.length < 3) { res.innerHTML = ""; return; }
  findTimer = setTimeout(async () => {
    res.innerHTML = `<div style="color:var(--text3);font-size:.82rem;padding:8px 0">Searching…</div>`;
    const q = query(collection(db, "users"), where("email", "==", val.trim().toLowerCase()), limit(1));
    const snap = await getDocs(q);
    if (snap.empty || snap.docs[0].id === currentUser.uid) {
      res.innerHTML = `<div class="uc-notfound">No user found with that email.</div>`; return;
    }
    const peer = { id: snap.docs[0].id, ...snap.docs[0].data() };
    const isBlocked = myBlockedUsers.includes(peer.id);
    res.innerHTML = `
      <div class="user-card">
        <div class="av">${peer.photoURL ? `<img src="${esc(peer.photoURL)}"/>` : esc(initials(peer.name))}</div>
        <div class="uc-info">
          <div class="uc-name">${esc(peer.name)}${isBlocked ? ' <span style="color:var(--red);font-size:.72rem">🚫 Blocked</span>' : ''}</div>
          <div class="uc-email">${esc(peer.email)}</div>
        </div>
        ${isBlocked
          ? `<button class="btn-unblock" onclick="unblockUser('${esc(peer.id)}')">✓ Unblock</button>`
          : `<button class="btn-primary" onclick="startChat('${esc(peer.id)}')">Chat</button>`
        }
      </div>`;
  }, 500);
};

window.startChat = async (peerId) => {
  try {
    closeModal("new-chat-modal");
    const ids = [currentUser.uid, peerId].sort();
    const convId = ids.join("_");
    // setDoc with merge:true creates if not exists, no-op if exists
    // Avoids reading a non-existent doc (which fails security rules)
    await setDoc(doc(db, "conversations", convId), {
      participants: ids,
      lastMsg: "",
      lastAt: serverTimestamp(),
      unread: {}
    }, { merge: true });
    
    // Force unhide the conversation for the current user using dot notation
    await updateDoc(doc(db, "conversations", convId), {
      [`hiddenUI.${currentUser.uid}`]: false
    }).catch(() => {}); // Catch in case the document was just created and rules don't like it or something
    const peerSnap = await getDoc(doc(db, "users", peerId));
    const peer = peerSnap.exists() ? peerSnap.data() : { name: "Unknown", photoURL: "" };
    openChat(convId, peerId, peer);
  } catch (err) {
    console.error("startChat error:", err);
    toast("Could not start chat: " + err.message, "err");
  }
};

// ── PEER PRESENCE INSPECTOR ──
function checkPeerIsLive(peerId) {
  if (!presenceChannel || !peerId) return false;
  try {
    const state = presenceChannel.presenceState();
    for (const key in state) {
      const metas = state[key];
      if (metas && (key.startsWith(peerId) || metas.some(m => m.uid === peerId))) {
        if (metas.some(m => m.online === true)) {
          return true;
        }
      }
    }
  } catch (e) {
    console.warn("checkPeerIsLive error:", e);
  }
  return false;
}

function renderPeerPresenceUI(isOnline, lastSeenIso) {
  const st = document.getElementById("peer-status");
  if (!st) return;
  if (amIBlocked) {
    st.textContent = "offline";
    st.className = "peer-status";
    return;
  }

  let lastSeenMs = 0;
  if (lastSeenIso) {
    lastSeenMs = new Date(lastSeenIso).getTime();
  }

  if (isOnline) {
    st.textContent = "online";
    st.className = "peer-status online";
  } else {
    st.textContent = lastSeenMs > 0 ? `last seen ${fmtTime(lastSeenMs)}` : "offline";
    st.className = "peer-status";
  }
}

function syncPeerPresenceState(peerId) {
  if (!peerId || amIBlocked) return;
  const isLive = checkPeerIsLive(peerId);
  if (isLive) {
    renderPeerPresenceUI(true, null);
  } else {
    supabase
      .from("user_presence")
      .select("is_online, last_seen")
      .eq("user_id", peerId)
      .maybeSingle()
      .then(({ data }) => {
        if (!checkPeerIsLive(peerId)) {
          renderPeerPresenceUI(data?.is_online === true, data?.last_seen);
        }
      })
      .catch(() => {
        if (!checkPeerIsLive(peerId)) {
          renderPeerPresenceUI(false, null);
        }
      });
  }
}

function listenPeerSupabasePresence(peerId) {
  if (amIBlocked) {
    renderPeerPresenceUI(false, null);
    return () => {};
  }

  // 1. Instant check against Realtime Presence Room
  syncPeerPresenceState(peerId);

  // 2. Listen for Postgres changes on user_presence table for this peer
  const subChannel = supabase
    .channel(`peer-presence-${peerId}-${Date.now()}`)
    .on("postgres_changes", {
      event: "*",
      schema: "public",
      table: "user_presence",
      filter: `user_id=eq.${peerId}`
    }, (payload) => {
      if (payload.new) {
        const live = checkPeerIsLive(peerId) || payload.new.is_online === true;
        renderPeerPresenceUI(live, payload.new.last_seen);
      }
    })
    .subscribe();

  return () => {
    try { subChannel.unsubscribe(); } catch {}
  };
}

// ── CHAT ──
window.openChat = async (convId, peerId, peer) => {
  // Guard: you (the current user) blocked this person — you cannot open their chat
  // This is one-directional: if THEY blocked YOU, your side is completely unaffected
  if (myBlockedUsers.includes(peerId)) {
    toast('You blocked this user. Unblock them first to chat.', 'err');
    return;
  }
  currentConvId = convId;
  currentPeer = { id: peerId, ...peer };
  
  // Fetch peer info from cache (or Firestore if needed)
  const peerData = await fetchUserCached(peerId);
  if (peerData) {
    currentPeer = { id: peerId, ...peer, ...peerData };
  }

  // ── SHADOW BLOCK: check if the peer has blocked ME ──
  amIBlocked = (peerData?.blockedUsers || []).includes(currentUser.uid);
  
  if (peerData && peerData.publicKey) {
      currentSharedKey = await deriveSharedKey(peerData.publicKey);
  } else {
      currentSharedKey = null; // Peer is using an old account without E2EE
  }

  document.getElementById("welcome").classList.add("hidden");
  document.getElementById("chat-view").classList.remove("hidden");
  document.getElementById("peer-name").textContent = peer.name;
  avatarEl(document.getElementById("peer-av"), peer.name, peer.photoURL);
  document.querySelectorAll(".conv-item").forEach(el => el.classList.remove("active"));
  document.getElementById(`conv-${convId}`)?.classList.add("active");
  // Reset unread badge in Firestore
  
  // ── Soft-delete: read my personal clearedAt for this conversation ──
  const convSnap = await getDoc(doc(db, "conversations", convId));
  myClearedAt = convSnap.exists() ? (convSnap.data().cleared?.[currentUser.uid] || null) : null;
  
  if (!amIBlocked) {
    if (unsubPeerPresence) {
      unsubPeerPresence();
      unsubPeerPresence = null;
    }
    const unsubPresence = listenPeerSupabasePresence(peerId);
    const unsubPeerDoc = onSnapshot(doc(db, "users", peerId), (snap) => {
      const data = snap.data();
      if (!data) return;
      usersCache.set(peerId, data);
      document.getElementById("peer-name").textContent = data.name || "Unknown";
      avatarEl(document.getElementById("peer-av"), data.name, data.photoURL);
      const isNowBlocked = (data.blockedUsers || []).includes(currentUser.uid);
      if (isNowBlocked !== amIBlocked) {
        amIBlocked = isNowBlocked;
        if (amIBlocked) renderPeerPresenceUI(false, null);
      }
    });
    unsubPeerPresence = () => {
      if (unsubPresence) unsubPresence();
      unsubPeerDoc();
    };
  } else {
    // Shadow-blocked: show forced offline
    if (unsubPeerPresence) { unsubPeerPresence(); unsubPeerPresence = null; }
    renderPeerPresenceUI(false, null);
  }
  listenMessages(convId);
  document.getElementById("sidebar").classList.add("slide-out");
  document.getElementById("msg-inp").focus();
};

window.closeChat = () => {
  document.getElementById("chat-view").classList.add("hidden");
  document.getElementById("welcome").classList.remove("hidden");
  document.getElementById("sidebar").classList.remove("slide-out");
  if (unsubMsgs) { unsubMsgs(); unsubMsgs = null; }
  if (unsubPeerPresence) { unsubPeerPresence(); unsubPeerPresence = null; }
  currentConvId = null;
  currentPeer = null;
  myClearedAt = null;
  document.querySelectorAll(".conv-item").forEach(el => el.classList.remove("active"));
};

function listenMessages(convId) {
  if (unsubMsgs) unsubMsgs();
  let isFirstLoad = true;
  // 👈 FIX: Order descending and limit to 50, to stop fetching huge chat histories
  const q = myClearedAt
    ? query(collection(db, "conversations", convId, "messages"), where("createdAt", ">", myClearedAt), orderBy("createdAt", "desc"), limit(50))
    : query(collection(db, "conversations", convId, "messages"), orderBy("createdAt", "desc"), limit(50));
  unsubMsgs = onSnapshot(q, async (snap) => { // 👈 Make this callback async
    // 👈 FIX: Reverse the documents so the UI still displays them top-to-bottom (oldest at top, newest at bottom)
    const docs = [...snap.docs].reverse();
    
    const inner = document.getElementById("msgs-inner");
    inner.innerHTML = "";
    let lastDate = null;
    
    // 👈 E2EE UPDATE: Process all docs and decrypt in parallel
    const processedMsgs = await Promise.all(docs.map(async (d) => {
        const msg = { id: d.id, ...d.data() };
        if (msg.senderId === currentUser.uid && d.metadata.hasPendingWrites) msg.isPending = true;
        
        // 👈 WHATSAPP CALL LOG: Call event documents bypass encryption
        if (msg.type === "call") {
          return { msg, d };
        }

        // Explicit encrypted flag takes precedence.
        // Legacy fallback: for older messages sent before encrypted flag existed, check length & base64
        const isLegacyEncrypted = msg.encrypted === undefined &&
          currentSharedKey &&
          msg.text &&
          msg.text.length >= 38 &&
          /^[A-Za-z0-9+/]+={0,2}$/.test(msg.text);

        const shouldDecrypt = currentSharedKey && (msg.encrypted === true || isLegacyEncrypted);

        if (shouldDecrypt) {
          if (msg.text) {
            msg.text = await decryptText(msg.text, currentSharedKey);
          }
          if (msg.image && !msg.image.startsWith("http")) {
            msg.image = await decryptText(msg.image, currentSharedKey);
          }
          if (msg.replyTo && msg.replyTo.text) {
            msg.replyTo.text = await decryptText(msg.replyTo.text, currentSharedKey);
          }
          if (msg.preview && typeof msg.preview === "string") {
            try {
              const decryptedPreview = await decryptText(msg.preview, currentSharedKey);
              if (decryptedPreview && !decryptedPreview.startsWith("🔒")) {
                msg.preview = JSON.parse(decryptedPreview);
              } else {
                msg.preview = null;
              }
            } catch {
              msg.preview = null;
            }
          }
        }
        
        return { msg, d };
    }));

    processedMsgs.forEach(({ msg, d }) => {
      if (myBlockedUsers.includes(msg.senderId)) { knownMsgIds.add(d.id); return; }
      
      const dateStr = fmtDate(msg.createdAt);
      if (dateStr !== lastDate) {
        const sep = document.createElement("div");
        sep.className = "date-sep";
        sep.innerHTML = `<span>${esc(dateStr)}</span>`;
        inner.appendChild(sep);
        lastDate = dateStr;
      }
      inner.appendChild(buildMsgEl(msg));
      knownMsgIds.add(d.id);
    });
    isFirstLoad = false;
    const box = document.getElementById("msgs-box");
    box.scrollTop = box.scrollHeight;
    
    // The Eye Tracker: Report the exact ID of the latest message seen from the peer
    // The Eye Tracker: Report the exact ID of the latest message seen from the peer
   // The Eye Tracker: Report the exact ID of the latest message seen from the peer
    const theirMsgs = docs.filter(d => d.data().senderId !== currentUser.uid);
    const newestMsg = theirMsgs[theirMsgs.length - 1];
    
    if (newestMsg) {
      const convData = allConvs.find(c => c.id === convId);
      // Get the current read ID from either our local memory OR the database
      const currentReadId = myReportedReadIds[convId] || (convData ? convData.lastReadId?.[currentUser.uid] : null);
      
      // Only trigger if we haven't already reported this exact ID
      if (currentReadId !== newestMsg.id) {
        
        // 1. Mark it as locally reported to prevent race condition loops
        myReportedReadIds[convId] = newestMsg.id;
        
        // 2. Queue the read receipt
        pendingReadReceipt = {
          convId: convId,
          msgId: newestMsg.id,
          ts: newestMsg.data().createdAt || null
        };
        
        // 3. Attempt to send it (will ONLY send if the window is actively focused)
        trySendReadReceipt();
      }
    }

    updateBlueTicks(convId); // Force tick check after DOM is drawn
  });
}

function buildMsgEl(msg) {
  // 👈 WHATSAPP CALL LOG: Render dedicated call message card
  if (msg.type === "call") {
    return buildCallMsgEl(msg);
  }

  const isMe = msg.senderId === currentUser.uid;
  const row = document.createElement("div");
  row.className = `msg-row ${isMe ? "me" : "them"}`;
  row.dataset.id = msg.id;
  const createdMs = (msg.isPending || !msg.createdAt) ? 0 : msg.createdAt.toMillis();
  if (isMe) row.dataset.createdAt = createdMs;
  
  if (!isMe) {
    const av = document.createElement("div");
    av.className = "av msg-av";
    av.innerHTML = currentPeer?.photoURL ? `<img src="${esc(currentPeer.photoURL)}"/>` : esc(initials(currentPeer?.name || "?"));
    row.appendChild(av);
  }
  
  const bubble = document.createElement("div");
  bubble.className = "msg-bubble";

  // 1. Render Reply Snippet securely
  if (msg.replyTo) {
    const repBox = document.createElement("div");
    repBox.className = "msg-reply-box";
    repBox.onclick = () => scrollToMsg(msg.replyTo.id);
    repBox.innerHTML = `<div class="msg-reply-name">${esc(msg.replyTo.senderName)}</div>
                        <div class="msg-reply-text">${esc(msg.replyTo.text)}</div>`;
    bubble.appendChild(repBox);
  }

  // 2. Render Image securely
  if (msg.image) {
    bubble.classList.add("has-img");
    const a = document.createElement("a");
    const safeImg = /^(https?:\/\/|data:image\/)/i.test(msg.image) ? msg.image : "#";
    a.href = safeImg;
    a.target = "_blank";
    a.rel = "noopener noreferrer";
    a.innerHTML = `<img src="${esc(msg.image)}" class="chat-img" alt="image" loading="lazy">`;
    bubble.appendChild(a);
  }
  
  // 3. Render Text securely
  if (msg.text) {
    const textNode = document.createElement("span");
    textNode.textContent = msg.text;
    bubble.appendChild(textNode);
  }

  // 4. Render Meta & Blue Ticks WITHOUT innerHTML+=
  const metaDiv = document.createElement("div");
  metaDiv.className = "msg-meta";
  
  if (isMe) {
    metaDiv.innerHTML = `${esc(fmtTime(msg.createdAt))} <span class="msg-status sent">&#10003;&#10003;</span>`;
  } else {
    metaDiv.innerHTML = `${esc(fmtTime(msg.createdAt))}`;
  }
  bubble.appendChild(metaDiv);

  // 5. Render Link Preview securely
  if (msg.preview) {
    const p = msg.preview;
    const a = document.createElement('a');
    const safeUrl = /^https?:\/\//i.test(p.url) ? p.url : "#";
    a.href = safeUrl;
    a.target = '_blank';
    a.rel = 'noopener noreferrer';
    a.className = 'msg-link-preview';
    a.innerHTML = `
      ${p.image ? `<img src="${esc(p.image)}" alt="" loading="lazy" onerror="this.style.display='none'">` : ''}
      <div class="lp-inner">
        <div class="lp-domain">${esc(p.domain || '')}</div>
        <div class="lp-title">${esc(p.title || p.url)}</div>
        ${p.description ? `<div class="lp-desc">${esc(p.description)}</div>` : ''}
      </div>`;
    bubble.appendChild(a);
  }
  
  bubble.addEventListener("contextmenu", (e) => { e.preventDefault(); showCtxMenu(e, msg, isMe); });
  row.appendChild(bubble);
  return row;
}

// ── WHATSAPP-STYLE CALL BUBBLE BUILDER ──
function buildCallMsgEl(msg) {
  const isMe = msg.senderId === currentUser.uid;
  const isVoice = msg.callType === "voice";
  const duration = msg.duration || 0;
  const status = msg.callStatus || "completed";

  // If currentUser is receiver/callee and the call was missed or cancelled
  const isMissedForMe = !isMe && (status === "missed" || status === "cancelled");
  const isCompleted = status === "completed" && duration > 0;

  let title = "";
  let subtitle = "";

  if (isCompleted) {
    title = isMe
      ? (isVoice ? "Outgoing voice call" : "Outgoing video call")
      : (isVoice ? "Incoming voice call" : "Incoming video call");
    subtitle = fmtDuration(duration);
  } else if (status === "declined") {
    title = isMe ? "Call declined" : (isVoice ? "Declined voice call" : "Declined video call");
    subtitle = "Declined";
  } else {
    // Missed or cancelled
    if (isMe) {
      title = isVoice ? "Cancelled voice call" : "Cancelled video call";
      subtitle = "No answer";
    } else {
      title = isVoice ? "Missed voice call" : "Missed video call";
      subtitle = "Tap to call back";
    }
  }

  const row = document.createElement("div");
  row.className = `msg-row ${isMe ? "me" : "them"} call-msg-row`;
  row.dataset.id = msg.id;

  const bubble = document.createElement("div");
  bubble.className = `msg-bubble msg-call-bubble ${isMissedForMe ? 'missed' : ''}`;

  const voiceIcon = `<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2"><path d="M22 16.92v3a2 2 0 0 1-2.18 2 19.79 19.79 0 0 1-8.63-3.07 19.5 19.5 0 0 1-6-6 19.79 19.79 0 0 1-3.07-8.67A2 2 0 0 1 4.11 2h3a2 2 0 0 1 2 1.72 12.84 12.84 0 0 0 .7 2.81 2 2 0 0 1-.45 2.11L8.09 9.91a16 16 0 0 0 6 6l1.27-1.27a2 2 0 0 1 2.11-.45 12.84 12.84 0 0 0 2.81.7A2 2 0 0 1 22 16.92z"/></svg>`;
  const videoIcon = `<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2"><polygon points="23 7 16 12 23 17 23 7"/><rect x="1" y="5" width="15" height="14" rx="2" ry="2"/></svg>`;

  let arrowIcon = "";
  if (isMissedForMe) {
    arrowIcon = `<svg class="arrow-icon missed" width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3"><line x1="17" y1="7" x2="7" y2="17"/><polyline points="17 17 7 17 7 7"/></svg>`;
  } else if (isMe) {
    arrowIcon = `<svg class="arrow-icon outgoing" width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3"><line x1="7" y1="17" x2="17" y2="7"/><polyline points="7 7 17 7 17 17"/></svg>`;
  } else {
    arrowIcon = `<svg class="arrow-icon incoming" width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3"><line x1="17" y1="7" x2="7" y2="17"/><polyline points="17 17 7 17 7 7"/></svg>`;
  }

  const callCard = document.createElement("div");
  callCard.className = "msg-call-card";
  callCard.innerHTML = `
    <div class="msg-call-icon-wrap ${isMissedForMe ? 'missed' : isCompleted ? 'completed' : 'neutral'}">
      ${isVoice ? voiceIcon : videoIcon}
      <div class="msg-call-arrow-badge">${arrowIcon}</div>
    </div>
    <div class="msg-call-content">
      <div class="msg-call-title ${isMissedForMe ? 'missed-text' : ''}">${esc(title)}</div>
      <div class="msg-call-subtitle">${esc(subtitle)}</div>
    </div>
    <button class="msg-call-btn" title="Call back" onclick="startCall('${msg.callType || 'voice'}')">
      ${isVoice ? voiceIcon : videoIcon}
    </button>
  `;

  const metaDiv = document.createElement("div");
  metaDiv.className = "msg-meta";
  metaDiv.innerHTML = `${esc(fmtTime(msg.createdAt))}`;

  bubble.appendChild(callCard);
  bubble.appendChild(metaDiv);
  bubble.addEventListener("contextmenu", (e) => { e.preventDefault(); showCtxMenu(e, msg, isMe); });
  row.appendChild(bubble);

  return row;
}


window.ctxReply = () => {
  if (!ctxMsgData) return;
  document.getElementById("msg-ctx").classList.add("hidden");
  
  const isMe = ctxMsgData.senderId === currentUser.uid;
  const senderName = isMe ? "You" : (currentPeer?.name || "User");
  let previewText = ctxMsgData.text || (ctxMsgData.image ? "📷 Photo" : "Attachment");
  
  replyingTo = {
    id: ctxMsgId,
    senderName: senderName,
    text: previewText
  };
  
  document.getElementById("rp-name").textContent = senderName;
  document.getElementById("rp-text").textContent = previewText;
  document.getElementById("reply-preview").classList.remove("hidden");
  document.getElementById("msg-inp").focus();
};

window.cancelReply = () => {
  replyingTo = null;
  document.getElementById("reply-preview").classList.add("hidden");
};

window.scrollToMsg = (id) => {
  const el = document.querySelector(`[data-id="${id}"]`);
  if (el) {
    el.scrollIntoView({ behavior: 'smooth', block: 'center' });
    el.style.animation = 'none'; // reset
    setTimeout(() => el.style.animation = 'popIn 0.4s ease', 10);
  }
};

// ── SEND MESSAGE ──
window.sendMsg = async (customText, imgUrl) => {
  const inp = document.getElementById("msg-inp");
  const text = (customText !== undefined && customText !== null) ? customText : inp.value.trim();
  if (!text && !imgUrl) return;          // must have text OR image
  if (!currentConvId || !currentPeer) return;
  if (!imgUrl) { inp.value = ""; autoResize(inp); }
  const isE2EE = !!currentSharedKey;

  // Build message document
  const msgData = {
    senderId: currentUser.uid,
    createdAt: serverTimestamp(),
    encrypted: isE2EE,
    ...(imgUrl ? { image: imgUrl } : {})
  };

  // Encrypt the reply snippet
  if (replyingTo) {
    msgData.replyTo = {
      id: replyingTo.id,
      senderName: replyingTo.senderName,
      text: replyingTo.text
    };
    if (isE2EE) {
      msgData.replyTo.text = await encryptText(replyingTo.text, currentSharedKey);
    }
  }

  // Encrypt link preview for E2EE chats
  if (currentLinkPreview && !imgUrl) {
    if (isE2EE) {
      msgData.preview = await encryptText(JSON.stringify(currentLinkPreview), currentSharedKey);
    } else {
      msgData.preview = currentLinkPreview;
    }
  }

  // Encrypt text if we have a shared key
  if (text) {
    if (isE2EE) {
      msgData.text = await encryptText(text, currentSharedKey);
    } else {
      msgData.text = text; // Fallback for non-E2EE accounts
    }
  } else {
    msgData.text = "";
  }

  await addDoc(collection(db, "conversations", currentConvId, "messages"), msgData);
  if (!imgUrl) clearLinkPreview();
  // Shadow-block: skip conversation doc update if peer has blocked me
  if (!amIBlocked) {
    // 👈 REMOVED lastMsg here to save massive Firestore writes
    await updateDoc(doc(db, "conversations", currentConvId), {
      lastAt: serverTimestamp(),
      [`unread.${currentPeer.id}`]: increment(1),
      [`unread.${currentUser.uid}`]: 0,
      [`hiddenUI.${currentUser.uid}`]: false,
      [`hiddenUI.${currentPeer.id}`]: false
    });
  }
  cancelReply();
};

// ── CLOUDINARY IMAGE UPLOAD ──
window.uploadChatImg = async (e) => {
  const file = e.target.files[0];
  if (!file || !currentConvId || !currentPeer) return;
  // Reset input so same file can be re-selected
  e.target.value = "";
  // Show spinner inside the message area
  const inner = document.getElementById("msgs-inner");
  const indicator = document.createElement("div");
  indicator.className = "img-uploading";
  indicator.innerHTML = `<div class="spin"></div><span>Uploading image…</span>`;
  inner.appendChild(indicator);
  const box = document.getElementById("msgs-box");
  box.scrollTop = box.scrollHeight;
  try {
    const fd = new FormData();
    fd.append("file", file);
    fd.append("upload_preset", "x7a9bc");
    const res = await fetch("https://api.cloudinary.com/v1_1/dogwrel9i/image/upload", {
      method: "POST",
      body: fd
    });
    if (!res.ok) throw new Error(`Cloudinary ${res.status}`);
    const json = await res.json();
    const secure_url = json.secure_url;
    indicator.remove();
    let finalUrl = secure_url;
    if (currentSharedKey) {
        finalUrl = await encryptText(secure_url, currentSharedKey);
    }
    await sendMsg(null, finalUrl);
  } catch (err) {
    indicator.remove();
    toast("Image upload failed: " + err.message, "err");
  }
};

window.onKey = (e) => { if (e.key === "Enter" && !e.shiftKey) { e.preventDefault(); sendMsg(); } };
window.autoResize = (el) => { el.style.height = "auto"; el.style.height = Math.min(el.scrollHeight, 140) + "px"; };

// ── LINK PREVIEW ──
const URL_REGEX = /(https?:\/\/[^\s]+)/i;

function clearLinkPreview() {
  currentLinkPreview = null;
  const card = document.getElementById('link-preview-card');
  if (card) { card.classList.add('hidden'); card.innerHTML = ''; }
}

window.dismissLinkPreview = clearLinkPreview;

window.onMsgPaste = (e) => {
  // Give browser time to update textarea value, then scan for URL
  setTimeout(() => detectLinkPreview(document.getElementById('msg-inp')?.value || ''), 50);
};

window.detectLinkPreview = (text) => {
  clearTimeout(linkPreviewTimer);
  const match = text.match(URL_REGEX);
  if (!match) { clearLinkPreview(); return; }
  const url = match[1];
  // Don't re-fetch if same URL already loaded
  if (currentLinkPreview && currentLinkPreview.url === url) return;
  linkPreviewTimer = setTimeout(() => fetchLinkPreview(url), 600);
};

async function fetchLinkPreview(url) {
  const card = document.getElementById('link-preview-card');
  if (!card) return;
  // Show loading state
  card.className = 'link-preview-card loading';
  card.innerHTML = `<div class="lp-meta"></div><button class="lp-dismiss" onclick="dismissLinkPreview()">✕</button>`;
  card.classList.remove('hidden');
  try {
    const apiUrl = `https://api.microlink.io/?url=${encodeURIComponent(url)}&screenshot=false&video=false&audio=false`;
    const res = await fetch(apiUrl);
    if (!res.ok) throw new Error('API error');
    const json = await res.json();
    if (json.status !== 'success') throw new Error('No data');
    const d = json.data;
    const domain = (() => { try { return new URL(url).hostname.replace('www.',''); } catch { return url; } })();
    currentLinkPreview = {
      url,
      domain,
      title: d.title || '',
      description: d.description || '',
      image: d.image?.url || d.logo?.url || ''
    };
    card.className = 'link-preview-card';
    card.innerHTML = `
      ${currentLinkPreview.image ? `<img class="lp-thumb" src="${esc(currentLinkPreview.image)}" alt="" onerror="this.style.display='none'">` : ''}
      <div class="lp-meta">
        <div class="lp-domain">${esc(currentLinkPreview.domain)}</div>
        <div class="lp-title">${esc(currentLinkPreview.title || url)}</div>
        ${currentLinkPreview.description ? `<div class="lp-desc">${esc(currentLinkPreview.description)}</div>` : ''}
      </div>
      <button class="lp-dismiss" onclick="dismissLinkPreview()">✕</button>`;
  } catch {
    // Fallback: show plain URL card without metadata
    const domain = (() => { try { return new URL(url).hostname.replace('www.',''); } catch { return url; } })();
    currentLinkPreview = { url, domain, title: url, description: '', image: '' };
    card.className = 'link-preview-card';
    card.innerHTML = `
      <div class="lp-meta">
        <div class="lp-domain">${esc(domain)}</div>
        <div class="lp-title">${esc(url)}</div>
      </div>
      <button class="lp-dismiss" onclick="dismissLinkPreview()">✕</button>`;
  }
}

// Also clear link preview when chat is closed
const _origCloseChat = window.closeChat;
window.closeChat = () => { clearLinkPreview(); if (_origCloseChat) _origCloseChat(); };



// ── CONTEXT MENU ──
function showCtxMenu(e, msg, isMe) {
  ctxMsgId = msg.id;
  ctxMsgData = msg;
  const menu = document.getElementById("msg-ctx");
  menu.style.top = `${e.clientY}px`;
  menu.style.left = `${Math.min(e.clientX, window.innerWidth - 160)}px`;
  menu.classList.remove("hidden");
  document.getElementById("msg-ctx-delete").classList.toggle("hidden", !isMe);
}
document.addEventListener("click", () => document.getElementById("msg-ctx").classList.add("hidden"));
window.ctxCopy = () => { navigator.clipboard.writeText(ctxMsgData?.text || ""); toast("Copied!", "ok"); };
window.ctxDelete = async () => {
  if (!currentConvId || !ctxMsgId) return;
  await deleteDoc(doc(db, "conversations", currentConvId, "messages", ctxMsgId));
  // Only overwrite the sidebar preview if the deleted message IS the newest one
  // (compare createdAt of this message vs lastAt on the conversation document)
  const msgTs = ctxMsgData?.createdAt?.toMillis?.() ?? 0;
  if (msgTs > 0) {
    const convSnap = await getDoc(doc(db, "conversations", currentConvId));
    const lastAt = convSnap.data()?.lastAt?.toMillis?.() ?? 0;
    if (msgTs >= lastAt) {
      await updateDoc(doc(db, "conversations", currentConvId), {
        lastMsg: "🚫 Message deleted"
      }).catch(() => {});
    }
  }
  toast("Message deleted.", "ok");
};

// ── CHAT MENU ──
window.toggleChatMenu = () => document.getElementById("chat-ctx-menu").classList.toggle("hidden");
document.addEventListener("click", (e) => { if (!e.target.closest("#chat-ctx-menu") && !e.target.closest("#chat-menu-btn")) document.getElementById("chat-ctx-menu")?.classList.add("hidden"); });

// ── BLOCK USER ──
window.blockUser = async () => {
  document.getElementById("chat-ctx-menu").classList.add("hidden");
  if (!currentPeer || !currentUser) return;
  const peerName = currentPeer.name || 'this user';
  const peerId   = currentPeer.id;
  if (!confirm(`Block ${peerName}? You will no longer see their messages.`)) return;
  try {
    await updateDoc(doc(db, "users", currentUser.uid), {
      blockedUsers: arrayUnion(peerId)
    });
    closeChat(); // sets currentPeer = null — safe because we saved peerName/peerId above
    toast(`🚫 ${peerName} blocked`, 'ok');
  } catch (err) {
    toast('Failed to block: ' + err.message, 'err');
  }
};

window.openBlockedModal = async () => {
  openModal('blocked-modal');
  const list = document.getElementById('blocked-list');
  if (myBlockedUsers.length === 0) {
    list.innerHTML = `<p style="color:var(--text3);text-align:center;padding:16px 0">No blocked users.</p>`;
    return;
  }
  list.innerHTML = `<p style="color:var(--text3);font-size:.78rem;padding:0 0 8px">Fetching…</p>`;
  const items = await Promise.all(myBlockedUsers.map(async (uid) => {
    try {
      const snap = await getDoc(doc(db, 'users', uid));
      const u = snap.exists() ? snap.data() : { name: 'Unknown', email: uid, photoURL: '' };
      return { uid, ...u };
    } catch { return { uid, name: 'Unknown', email: uid, photoURL: '' }; }
  }));
  list.innerHTML = items.map(u => `
    <div class="user-card">
      <div class="av">${u.photoURL ? `<img src="${esc(u.photoURL)}"/>` : esc(initials(u.name))}</div>
      <div class="uc-info">
        <div class="uc-name">${esc(u.name)}</div>
        <div class="uc-email">${esc(u.email || u.uid)}</div>
      </div>
      <button class="btn-unblock" onclick="unblockUser('${esc(u.uid)}')">Unblock</button>
    </div>`).join('');
};

window.unblockUser = async (uid) => {
  try {
    await updateDoc(doc(db, 'users', currentUser.uid), {
      blockedUsers: arrayRemove(uid)
    });
    // Force-refresh myBlockedUsers immediately so stale state is cleared
    // (the onSnapshot will also fire, but we refresh here for instant UI)
    myBlockedUsers = myBlockedUsers.filter(id => id !== uid);
    toast('User unblocked ✓ — you can now chat normally!', 'ok');
    // If the blocked modal is open, refresh it; otherwise close
    const modal = document.getElementById('blocked-modal');
    if (!modal.classList.contains('hidden')) {
      openBlockedModal(); // refresh the list
    }
    // Re-render sidebar so the unblocked conversation reappears
    if (unsubConvs) { unsubConvs(); unsubConvs = null; }
    listenConversations();
  } catch (err) {
    toast('Failed: ' + err.message, 'err');
  }
};

// ── SOFT CLEAR FOR ME ──
window.clearChat = async () => {
  document.getElementById("chat-ctx-menu").classList.add("hidden");
  if (!currentConvId) return;
  if (!confirm("Clear chat history? Only you will see this change.")) return;
  try {
    const nowTs = Timestamp.now();
    await updateDoc(doc(db, "conversations", currentConvId), {
      [`cleared.${currentUser.uid}`]: nowTs,
      [`unread.${currentUser.uid}`]: 0,
      lastMsg: "Chat cleared"
    });
    myClearedAt = nowTs;
    listenMessages(currentConvId);
    toast("Chat cleared for you ✓", "ok");
  } catch (err) {
    console.error("clearChat error:", err);
    toast("Failed: " + err.message, "err");
  }
};

// ── SOFT CLEAR FOR EVERYONE ──
window.clearChatEveryone = async () => {
  document.getElementById("chat-ctx-menu").classList.add("hidden");
  if (!currentConvId || !currentPeer) return;
  if (!confirm("Clear chat history for EVERYONE? Both of you will lose the messages.")) return;
  try {
    const nowTs = Timestamp.now();
    await updateDoc(doc(db, "conversations", currentConvId), {
      [`cleared.${currentUser.uid}`]: nowTs,
      [`cleared.${currentPeer.id}`]: nowTs,
      [`unread.${currentUser.uid}`]: 0,
      [`unread.${currentPeer.id}`]: 0,
      lastMsg: "Chat cleared"
    });
    myClearedAt = nowTs;
    listenMessages(currentConvId);
    toast("Chat cleared for everyone ✓", "ok");
  } catch (err) {
    console.error("clearChatEveryone error:", err);
    toast("Failed: " + err.message, "err");
  }
};

// ── SOFT DELETE FOR ME ──
window.deleteConv = async () => {
  document.getElementById("chat-ctx-menu").classList.add("hidden");
  if (!currentConvId) return;
  if (!confirm("Remove this conversation from your list? Only you will see this change.")) return;
  const convIdToDelete = currentConvId;
  try {
    const nowTs = Timestamp.now();
    closeChat(); // stop listeners
    await updateDoc(doc(db, "conversations", convIdToDelete), {
      [`hiddenUI.${currentUser.uid}`]: true,
      [`cleared.${currentUser.uid}`]: nowTs
    });
    toast("Conversation deleted for you ✓", "ok");
  } catch (err) {
    console.error("deleteConv error:", err);
    toast("Failed: " + err.message, "err");
  }
};

// ── SOFT DELETE FOR EVERYONE ──
window.deleteConvEveryone = async () => {
  document.getElementById("chat-ctx-menu").classList.add("hidden");
  if (!currentConvId || !currentPeer) return;
  if (!confirm("Delete this conversation for EVERYONE? It will be removed from both of your lists.")) return;
  const convIdToDelete = currentConvId;
  const peerId = currentPeer.id;
  try {
    const nowTs = Timestamp.now();
    closeChat(); // stop listeners
    await updateDoc(doc(db, "conversations", convIdToDelete), {
      [`hiddenUI.${currentUser.uid}`]: true,
      [`hiddenUI.${peerId}`]: true,
      [`cleared.${currentUser.uid}`]: nowTs,
      [`cleared.${peerId}`]: nowTs,
      [`unread.${currentUser.uid}`]: 0,
      [`unread.${peerId}`]: 0,
      lastMsg: "Chat deleted"
    });
    toast("Conversation deleted for everyone ✓", "ok");
  } catch (err) {
    console.error("deleteConvEveryone error:", err);
    toast("Failed: " + err.message, "err");
  }
};

// ── EMOJI ──
const EMOJIS = ["😀","😂","😍","🥰","😎","🤔","😢","😡","👍","👎","❤️","🔥","🎉","💯","✨","🙏","👏","😭","🤣","😊","😏","🤩","😴","🥳","💪","🎊","🌟","💀","👀","🫡","😤","🥹","🤗","😇","🤯","🫶","💬","🚀","🌈","⚡"];
window.toggleEmoji = () => {
  const box = document.getElementById("emoji-box");
  if (box.classList.contains("hidden")) {
    box.innerHTML = EMOJIS.map(e => `<span onclick="addEmoji('${e}')">${e}</span>`).join("");
    box.classList.remove("hidden");
  } else box.classList.add("hidden");
};
window.addEmoji = (e) => {
  const inp = document.getElementById("msg-inp");
  inp.value += e;
  if (typeof autoResize === "function") autoResize(inp);
  inp.dispatchEvent(new Event("input", { bubbles: true }));
  inp.focus();
  document.getElementById("emoji-box")?.classList.add("hidden");
};
document.addEventListener("click", (e) => {
  if (!e.target.closest("#emoji-box") && !e.target.closest(".emoji-toggle")) {
    document.getElementById("emoji-box")?.classList.add("hidden");
  }
});

// ==========================================================================
// ── CALLING CONTROLLERS (NEXCALL ENGINE: DUAL FIREBASE & SUPABASE RTDB) ──
// ==========================================================================

let incomingCallsListener = null;
let currentIncomingCallId = null;
let currentIncomingCallData = null;
let activeCallType = "video";
let callDurationSeconds = 0;
let callTimer = null;
let isAudioMuted = false;
let isVideoDisabled = false;
let isScreenSharing = false;
let isCallMinimized = false;
let audioRingingEl = null;

// Call metadata tracking for WhatsApp-style chat logging
let activeCallSessionId = null;
let activeCallCallerId = null;
let activeCallCalleeId = null;
let activeCallIsHost = false;
let activeCallConnected = false;
const loggedCallKeys = new Set();

function fmtDuration(seconds) {
  if (!seconds || seconds <= 0) return "0s";
  const m = Math.floor(seconds / 60);
  const s = seconds % 60;
  if (m === 0) return `${s}s`;
  if (m < 60) return `${m}m ${s}s`;
  const h = Math.floor(m / 60);
  const remM = m % 60;
  return `${h}h ${remM}m`;
}

async function recordCallInChat({ callerId, calleeId, callType, callStatus, duration = 0, callId }) {
  if (!callerId || !calleeId) return;
  const dedupKey = `${callId || 'direct'}_${callStatus}_${duration > 0 ? 'dur' : 'nodur'}`;
  if (callId && loggedCallKeys.has(dedupKey)) return;
  if (callId) loggedCallKeys.add(dedupKey);

  const convId = [callerId, calleeId].sort().join("_");
  const isVoice = callType === "voice";
  const typeLabel = isVoice ? "Voice call" : "Video call";

  let summaryText = "";
  if (callStatus === "completed" && duration > 0) {
    summaryText = `📞 ${typeLabel} (${fmtDuration(duration)})`;
  } else if (callStatus === "missed") {
    summaryText = `📞 Missed ${typeLabel.toLowerCase()}`;
  } else if (callStatus === "declined") {
    summaryText = `📞 Declined ${typeLabel.toLowerCase()}`;
  } else {
    summaryText = `📞 Cancelled ${typeLabel.toLowerCase()}`;
  }

  const callMsgData = {
    type: "call",
    callId: callId || null,
    senderId: callerId,
    receiverId: calleeId,
    callType: callType || "voice",
    callStatus: callStatus, // "completed" | "missed" | "declined" | "cancelled"
    duration: duration || 0,
    text: summaryText,
    createdAt: serverTimestamp()
  };

  try {
    // 1. Ensure conversation exists and is unhidden
    await setDoc(doc(db, "conversations", convId), {
      participants: [callerId, calleeId].sort(),
      lastAt: serverTimestamp(),
      [`hiddenUI.${callerId}`]: false,
      [`hiddenUI.${calleeId}`]: false,
    }, { merge: true }).catch(() => {});

    // 2. Write call message with deterministic ID per call
    const msgDocId = callId ? `call_${callId}` : undefined;
    if (msgDocId) {
      await setDoc(doc(db, "conversations", convId, "messages", msgDocId), callMsgData, { merge: true });
    } else {
      await addDoc(collection(db, "conversations", convId, "messages"), callMsgData);
    }

    // 3. Update conversation lastAt & unread badge for callee if missed
    const unreadUpdate = (callStatus === "missed" && currentUser?.uid === callerId)
      ? { [`unread.${calleeId}`]: increment(1) }
      : {};

    await updateDoc(doc(db, "conversations", convId), {
      lastAt: serverTimestamp(),
      ...unreadUpdate
    }).catch(() => {});
  } catch (err) {
    console.error("recordCallInChat error:", err);
  }
}

// Synthetic Web Audio ringtone fallback (for offline or browser autoplay blocks)
let synthRingInterval = null;
let synthAudioCtx = null;

function playSyntheticTone(frequency1 = 440, frequency2 = 480, duration = 1.2) {
  try {
    const AudioCtx = window.AudioContext || window.webkitAudioContext;
    if (!AudioCtx) return;
    if (!synthAudioCtx) synthAudioCtx = new AudioCtx();
    if (synthAudioCtx.state === "suspended") synthAudioCtx.resume();

    const osc1 = synthAudioCtx.createOscillator();
    const osc2 = synthAudioCtx.createOscillator();
    const gain = synthAudioCtx.createGain();

    osc1.type = "sine";
    osc2.type = "sine";
    osc1.frequency.value = frequency1;
    osc2.frequency.value = frequency2;

    gain.gain.setValueAtTime(0.12, synthAudioCtx.currentTime);
    gain.gain.exponentialRampToValueAtTime(0.001, synthAudioCtx.currentTime + duration);

    osc1.connect(gain);
    osc2.connect(gain);
    gain.connect(synthAudioCtx.destination);

    osc1.start();
    osc2.start();
    osc1.stop(synthAudioCtx.currentTime + duration);
    osc2.stop(synthAudioCtx.currentTime + duration);
  } catch (e) {
    console.warn("Synthetic ringtone tone error:", e);
  }
}

function startRingtoneSound() {
  audioRingingEl = document.getElementById("audio-ringing");
  if (audioRingingEl) {
    audioRingingEl.currentTime = 0;
    audioRingingEl.play().catch(() => {
      if (!synthRingInterval) {
        playSyntheticTone(440, 480, 1.2);
        synthRingInterval = setInterval(() => playSyntheticTone(440, 480, 1.2), 3000);
      }
    });
  } else {
    if (!synthRingInterval) {
      playSyntheticTone(440, 480, 1.2);
      synthRingInterval = setInterval(() => playSyntheticTone(440, 480, 1.2), 3000);
    }
  }
}

function stopRingtoneSound() {
  if (audioRingingEl) {
    audioRingingEl.pause();
    audioRingingEl.currentTime = 0;
  }
  if (synthRingInterval) {
    clearInterval(synthRingInterval);
    synthRingInterval = null;
  }
}

function setCallAvatarUI(type, name, photoURL) {
  const letterEl = document.getElementById(`${type}-avatar-letter`);
  const imgEl = document.getElementById(`${type}-avatar-img`);
  if (!letterEl || !imgEl) return;
  if (photoURL) {
    imgEl.src = esc(photoURL);
    imgEl.style.display = "block";
    letterEl.style.display = "none";
  } else {
    imgEl.style.display = "none";
    letterEl.style.display = "block";
    letterEl.textContent = (name || "?").charAt(0).toUpperCase();
  }
}

// ── INITIATE OUTGOING CALL ──
window.startCall = async function(callType = "video") {
  if (!currentPeer || !currentPeer.id) {
    toast("Open a chat first to start a call", "err");
    return;
  }
  if (amIBlocked) {
    toast("Cannot call this user.", "err");
    return;
  }

  activeCallType = callType;
  activeCallCallerId = currentUser.uid;
  activeCallCalleeId = currentPeer.id;
  activeCallIsHost = true;
  activeCallConnected = false;
  activeCallSessionId = null;

  const overlay = document.getElementById("call-overlay");
  const outgoingCard = document.getElementById("outgoing-call-card");
  const incomingCard = document.getElementById("incoming-call-card");
  const outName = document.getElementById("outgoing-callee-name");
  const outEmail = document.getElementById("outgoing-callee-email");
  const outTitle = outgoingCard?.querySelector(".call-title");

  if (outTitle) outTitle.textContent = callType === "voice" ? "Voice Calling" : "Video Calling";
  if (outName) outName.textContent = currentPeer.name || "User";
  if (outEmail) outEmail.textContent = currentPeer.email || "";

  setCallAvatarUI("outgoing", currentPeer.name, currentPeer.photoURL);

  outgoingCard?.classList.remove("hidden");
  incomingCard?.classList.add("hidden");
  overlay?.classList.remove("hidden");

  startRingtoneSound();

  try {
    const callId = await startWebRTCCall(currentUser, currentPeer, callType);
    activeCallSessionId = callId;
  } catch (err) {
    console.error("startCall error:", err);
    toast("Call failed: " + err.message, "err");
    endActiveCallUI();
  }
};

// ── LISTEN FOR INCOMING CALLS (DUAL RTDB: FIRESTORE + SUPABASE) ──
function startIncomingCallsListener(userId) {
  stopIncomingCallsListener();

  // 1. Firebase Firestore Realtime snapshot
  const callsQuery = query(
    collection(db, "calls"),
    where("calleeId", "==", userId),
    where("status", "==", "ringing")
  );

  incomingCallsListener = onSnapshot(callsQuery, (snapshot) => {
    snapshot.docChanges().forEach((change) => {
      if (change.type === "added") {
        const callData = change.doc.data();
        const callId = change.doc.id;

        // Auto-decline if caller is blocked
        if (myBlockedUsers.includes(callData.callerId)) {
          declineWebRTCCall(callId);
          return;
        }

        currentIncomingCallId = callId;
        currentIncomingCallData = callData;
        showIncomingCallUI(callData);
      }
    });
  });

  // 2. Supabase Realtime Channel (Zero-Latency WebSockets signaling)
  if (supabase) {
    const userCallChannel = supabase.channel(`user-call:${userId}`);
    userCallChannel
      .on('broadcast', { event: 'incoming-call' }, ({ payload }) => {
        if (!payload || !payload.callId) return;
        if (myBlockedUsers.includes(payload.callerId)) {
          declineWebRTCCall(payload.callId);
          return;
        }
        if (currentIncomingCallId === payload.callId) return;
        currentIncomingCallId = payload.callId;
        currentIncomingCallData = payload;
        showIncomingCallUI(payload);
      })
      .subscribe();
  }
}

function stopIncomingCallsListener() {
  if (incomingCallsListener) {
    incomingCallsListener();
    incomingCallsListener = null;
  }
}

function showIncomingCallUI(callData) {
  const overlay = document.getElementById("call-overlay");
  const outgoingCard = document.getElementById("outgoing-call-card");
  const incomingCard = document.getElementById("incoming-call-card");
  const inName = document.getElementById("incoming-caller-name");
  const inEmail = document.getElementById("incoming-caller-email");
  const inTitle = incomingCard?.querySelector(".call-title");

  const callType = callData.callType || "video";
  activeCallType = callType;
  activeCallCallerId = callData.callerId;
  activeCallCalleeId = currentUser.uid;
  activeCallIsHost = false;
  activeCallConnected = false;
  activeCallSessionId = callData.callId || currentIncomingCallId;

  if (inTitle) inTitle.textContent = callType === "voice" ? "Incoming Voice Call" : "Incoming Video Call";
  if (inName) inName.textContent = callData.callerName || "User";
  if (inEmail) inEmail.textContent = callData.callerEmail || "";

  setCallAvatarUI("incoming", callData.callerName, callData.callerPhotoURL);

  incomingCard?.classList.remove("hidden");
  outgoingCard?.classList.add("hidden");
  overlay?.classList.remove("hidden");

  startRingtoneSound();

  // Background Push / SW notification
  if (document.hidden && swRegistration && swRegistration.active) {
    swRegistration.active.postMessage({
      type: 'SHOW_NOTIFICATION',
      title: `Incoming ${callType === "voice" ? "Voice" : "Video"} Call`,
      body: `${callData.callerName} is calling you on ChatWave...`,
      tag: `call-${callData.callId}`
    });
  }
}

// ── ACCEPT INCOMING CALL ──
window.acceptIncomingCall = async function() {
  if (!currentIncomingCallId) return;

  stopRingtoneSound();
  activeCallConnected = true;

  const overlay = document.getElementById("call-overlay");
  const callRoom = document.getElementById("call-room-view");
  const partnerNameEl = document.getElementById("call-partner-name");

  overlay?.classList.add("hidden");
  callRoom?.classList.remove("hidden");
  callRoom?.classList.remove("minimized");

  const callerName = currentIncomingCallData?.callerName || "User";
  if (partnerNameEl) partnerNameEl.textContent = callerName;

  try {
    const result = await acceptWebRTCCall(currentIncomingCallId, currentUser.uid);
    const localVid = document.getElementById("local-video");
    const remoteVid = document.getElementById("remote-video");

    if (localVid) localVid.srcObject = result.localStream;
    if (remoteVid) remoteVid.srcObject = result.remoteStream;

    configureCallRoomUI(result.callType, callerName, result.callerPhotoURL);
    startCallTimer();
  } catch (err) {
    console.error("acceptIncomingCall error:", err);
    toast("Failed to connect call: " + err.message, "err");
    endActiveCallUI();
  }
};

// ── DECLINE / CANCEL / HANGUP ──
window.declineIncomingCall = function() {
  if (activeCallCallerId && activeCallCalleeId) {
    recordCallInChat({
      callerId: activeCallCallerId,
      calleeId: activeCallCalleeId,
      callType: activeCallType,
      callStatus: "declined",
      duration: 0,
      callId: activeCallSessionId
    });
  }
  if (currentIncomingCallId) {
    declineWebRTCCall(currentIncomingCallId);
  }
  endActiveCallUI();
};

window.cancelOutgoingCall = function() {
  if (activeCallCallerId && activeCallCalleeId) {
    recordCallInChat({
      callerId: activeCallCallerId,
      calleeId: activeCallCalleeId,
      callType: activeCallType,
      callStatus: "missed",
      duration: 0,
      callId: activeCallSessionId
    });
  }
  hangUpWebRTCCall();
  endActiveCallUI();
};

window.endActiveCall = function() {
  const duration = callDurationSeconds;
  const status = duration > 0 ? "completed" : (activeCallConnected ? "completed" : "cancelled");
  if (activeCallCallerId && activeCallCalleeId) {
    recordCallInChat({
      callerId: activeCallCallerId,
      calleeId: activeCallCalleeId,
      callType: activeCallType,
      callStatus: status,
      duration: duration,
      callId: activeCallSessionId
    });
  }
  hangUpWebRTCCall(duration);
  endActiveCallUI();
};

// ── CONFIGURE CALL ROOM (VOICE VS VIDEO) ──
function configureCallRoomUI(callType, partnerName, partnerPhotoURL) {
  const voiceContainer = document.getElementById("voice-call-avatar-container");
  const voiceNameEl = document.getElementById("voice-call-partner-name");
  const localContainer = document.getElementById("local-video-container");
  const remoteVid = document.getElementById("remote-video");
  const btnToggleVideo = document.getElementById("btn-toggle-video");

  if (voiceNameEl) voiceNameEl.textContent = partnerName || "Partner";

  if (callType === "voice") {
    setCallAvatarUI("voice", partnerName, partnerPhotoURL);
    if (voiceContainer) voiceContainer.classList.remove("hidden");
    if (localContainer) localContainer.classList.add("hidden");
    if (remoteVid) remoteVid.classList.add("hidden");
    if (btnToggleVideo) btnToggleVideo.style.display = "none";
  } else {
    if (voiceContainer) voiceContainer.classList.add("hidden");
    if (localContainer) localContainer.classList.remove("hidden");
    if (remoteVid) remoteVid.classList.remove("hidden");
    if (btnToggleVideo) btnToggleVideo.style.display = "";
  }
}

// ── CALL DURATION TIMER ──
function startCallTimer() {
  stopCallTimer();
  callDurationSeconds = 0;
  const timerEl = document.getElementById("call-duration-timer");
  if (timerEl) timerEl.textContent = "00:00";

  const localVid = document.getElementById("local-video");
  const stream = getLocalStream();
  if (localVid && stream) {
    localVid.srcObject = stream;
  }

  callTimer = setInterval(() => {
    callDurationSeconds++;
    const mins = Math.floor(callDurationSeconds / 60).toString().padStart(2, '0');
    const secs = (callDurationSeconds % 60).toString().padStart(2, '0');
    if (timerEl) timerEl.textContent = `${mins}:${secs}`;
  }, 1000);
}

function stopCallTimer() {
  if (callTimer) {
    clearInterval(callTimer);
    callTimer = null;
  }
}

// ── RESTORE INTERFACE AFTER CALL ──
function endActiveCallUI() {
  stopRingtoneSound();
  stopCallTimer();

  const overlay = document.getElementById("call-overlay");
  const callRoom = document.getElementById("call-room-view");
  const localVid = document.getElementById("local-video");
  const remoteVid = document.getElementById("remote-video");

  if (overlay) overlay.classList.add("hidden");
  if (callRoom) {
    callRoom.classList.add("hidden");
    callRoom.classList.remove("minimized");
  }

  if (localVid) localVid.srcObject = null;
  if (remoteVid) remoteVid.srcObject = null;

  isAudioMuted = false;
  isVideoDisabled = false;
  isScreenSharing = false;
  isCallMinimized = false;

  const btnAudio = document.getElementById("btn-toggle-audio");
  const btnVideo = document.getElementById("btn-toggle-video");
  const btnShare = document.getElementById("btn-share-screen");
  if (btnAudio) btnAudio.classList.remove("active");
  if (btnVideo) btnVideo.classList.remove("active");
  if (btnShare) btnShare.classList.remove("active");

  const micIcon = btnAudio?.querySelector(".icon-mic");
  const micOffIcon = btnAudio?.querySelector(".icon-mic-off");
  if (micIcon) micIcon.classList.remove("hidden");
  if (micOffIcon) micOffIcon.classList.add("hidden");

  const vidIcon = btnVideo?.querySelector(".icon-video");
  const vidOffIcon = btnVideo?.querySelector(".icon-video-off");
  if (vidIcon) vidIcon.classList.remove("hidden");
  if (vidOffIcon) vidOffIcon.classList.add("hidden");

  currentIncomingCallId = null;
  currentIncomingCallData = null;
  activeCallSessionId = null;
  activeCallCallerId = null;
  activeCallCalleeId = null;
  activeCallConnected = false;
  cleanUpCall();
}

// ── HARDWARE & MEDIA TOGGLES ──
window.toggleCallAudio = function() {
  isAudioMuted = !isAudioMuted;
  toggleWebRTCAudio(isAudioMuted);

  const btn = document.getElementById("btn-toggle-audio");
  const micIcon = btn?.querySelector(".icon-mic");
  const micOffIcon = btn?.querySelector(".icon-mic-off");

  if (btn) btn.classList.toggle("active", isAudioMuted);
  if (micIcon) micIcon.classList.toggle("hidden", isAudioMuted);
  if (micOffIcon) micOffIcon.classList.toggle("hidden", !isAudioMuted);
};

window.toggleCallVideo = function() {
  isVideoDisabled = !isVideoDisabled;
  toggleWebRTCVideo(isVideoDisabled);

  const btn = document.getElementById("btn-toggle-video");
  const vidIcon = btn?.querySelector(".icon-video");
  const vidOffIcon = btn?.querySelector(".icon-video-off");

  if (btn) btn.classList.toggle("active", isVideoDisabled);
  if (vidIcon) vidIcon.classList.toggle("hidden", isVideoDisabled);
  if (vidOffIcon) vidOffIcon.classList.toggle("hidden", !isVideoDisabled);
};

window.toggleCallScreen = async function() {
  try {
    const btn = document.getElementById("btn-share-screen");
    if (!isScreenSharing) {
      await toggleWebRTCScreenShare(true, () => {
        isScreenSharing = false;
        if (btn) btn.classList.remove("active");
      });
      isScreenSharing = true;
      if (btn) btn.classList.add("active");
    } else {
      await toggleWebRTCScreenShare(false);
      isScreenSharing = false;
      if (btn) btn.classList.remove("active");
    }
  } catch (err) {
    console.warn("Screen share error:", err);
  }
};

window.toggleCallMinimize = function() {
  const callRoom = document.getElementById("call-room-view");
  if (!callRoom) return;
  isCallMinimized = !isCallMinimized;
  callRoom.classList.toggle("minimized", isCallMinimized);
};

// ── REGISTER WEBRTC CALLBACKS ──
registerCallbacks({
  onCallAccepted: () => {
    stopRingtoneSound();
    activeCallConnected = true;
    const overlay = document.getElementById("call-overlay");
    const callRoom = document.getElementById("call-room-view");
    const partnerNameEl = document.getElementById("call-partner-name");

    if (overlay) overlay.classList.add("hidden");
    if (callRoom) {
      callRoom.classList.remove("hidden");
      callRoom.classList.remove("minimized");
    }

    const peerName = currentPeer?.name || "User";
    if (partnerNameEl) partnerNameEl.textContent = peerName;

    configureCallRoomUI(activeCallType, peerName, currentPeer?.photoURL || null);
    startCallTimer();
  },

  onCallEnded: (reason) => {
    const duration = callDurationSeconds;
    let status = "completed";
    if (reason === "declined") {
      status = "declined";
    } else if (duration > 0 || activeCallConnected) {
      status = "completed";
    } else {
      status = "missed";
    }

    if (activeCallCallerId && activeCallCalleeId) {
      recordCallInChat({
        callerId: activeCallCallerId,
        calleeId: activeCallCalleeId,
        callType: activeCallType,
        callStatus: status,
        duration: duration,
        callId: activeCallSessionId
      });
    }

    endActiveCallUI();
    if (reason === "declined") {
      toast("Contact declined the call", "err");
    } else {
      toast("Call ended", "ok");
    }
  },

  onRemoteStream: (stream) => {
    const remoteVid = document.getElementById("remote-video");
    if (remoteVid) remoteVid.srcObject = stream;
  },

  onError: (errorMsg) => {
    toast(errorMsg, "err");
    endActiveCallUI();
  }
});

// ── BIND CALL CONTROL BUTTON LISTENERS ──
document.getElementById("btn-cancel-call")?.addEventListener("click", window.cancelOutgoingCall);
document.getElementById("btn-decline-call")?.addEventListener("click", window.declineIncomingCall);
document.getElementById("btn-accept-call")?.addEventListener("click", window.acceptIncomingCall);
document.getElementById("btn-hangup")?.addEventListener("click", window.endActiveCall);
document.getElementById("btn-toggle-audio")?.addEventListener("click", window.toggleCallAudio);
document.getElementById("btn-toggle-video")?.addEventListener("click", window.toggleCallVideo);
document.getElementById("btn-share-screen")?.addEventListener("click", window.toggleCallScreen);
document.getElementById("btn-minimize-call")?.addEventListener("click", window.toggleCallMinimize);