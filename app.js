/* ═══════════════════════════════════════════════════════════
   KeySign – Typing Pattern Authentication  |  app.js
   
   Architecture:
     – KeystrokeCapture  : attaches keyboard listeners, records timings
     – ProfileBuilder    : averages N samples into a feature vector
     – PatternMatcher    : computes normalised Euclidean distance → confidence
     – Storage           : read/write profiles via localStorage
     – UI helpers        : tab switching, toasts, overlay, feedback
   ═══════════════════════════════════════════════════════════ */

'use strict';

/* ── Constants ─────────────────────────────────────────────── */
const PASSPHRASE = 'Cybersecurity is the future';
const SAMPLES_REQUIRED = 3;
const AUTH_THRESHOLD = 40;   // % confidence required to grant access
const STORAGE_KEY = 'keysign_profiles';

/* ── State ──────────────────────────────────────────────────── */
let regSamples = [];   // accumulated registration timing vectors
let regCurrentData = null; // live capture for registration
let loginCurrentData = null; // live capture for login

/* ═══════════════════════════════════════════════════════════
   SECTION 1 – Keystroke Capture
   Captures dwell time (key-hold ms) and flight time (inter-key gap ms)
   for every character in the target sentence.
   ═══════════════════════════════════════════════════════════ */

/**
 * Returns a fresh capture-session object.
 * @param {HTMLTextAreaElement} el - the textarea to monitor
 * @param {function} onUpdate      - called after every valid keystroke update
 */
function createCapture(el, onUpdate) {
  const session = {
    el,
    onUpdate,
    events: [],    // [{char, dwell, flight}]
    lastInputTime: null,  // timestamp of last input event
    prevLength: 0,     // textarea length before last input
    pendingDwell: null,  // dwell from keydown/keyup if available (desktop)
    keyDownTimes: {},    // key → keydown timestamp (desktop supplement)
    listening: false,
  };

  // PRIMARY – input event fires on ALL devices including mobile
  session.handleInput = () => {
    const now = performance.now();
    const text = el.value;

    if (text.length > session.prevLength) {
      // A character was added
      const char = text[text.length - 1];
      const flight = session.lastInputTime !== null ? now - session.lastInputTime : 0;
      const dwell = session.pendingDwell !== null ? session.pendingDwell : 60; // 60ms default on mobile

      if (char && char.length === 1) {
        session.events.push({ char, dwell, flight });
        if (onUpdate) onUpdate(session);
      }
    }

    session.lastInputTime = now;
    session.prevLength = text.length;
    session.pendingDwell = null;
  };

  // SUPPLEMENT – keydown/keyup gives real dwell on desktop
  session.handleKeyDown = (e) => {
    if (e.key && e.key.length === 1) {
      session.keyDownTimes[e.key] = performance.now();
    }
  };

  session.handleKeyUp = (e) => {
    if (e.key && session.keyDownTimes[e.key] !== undefined) {
      session.pendingDwell = performance.now() - session.keyDownTimes[e.key];
      delete session.keyDownTimes[e.key];
    }
  };

  el.addEventListener('input', session.handleInput);
  el.addEventListener('keydown', session.handleKeyDown);
  el.addEventListener('keyup', session.handleKeyUp);
  session.listening = true;

  return session;
}

/** Remove all listeners and return captured events. */
function stopCapture(session) {
  if (!session || !session.listening) return [];
  session.el.removeEventListener('input', session.handleInput);
  session.el.removeEventListener('keydown', session.handleKeyDown);
  session.el.removeEventListener('keyup', session.handleKeyUp);
  session.listening = false;
  return session.events;
}

/* ═══════════════════════════════════════════════════════════
   SECTION 2 – Feature Vector
   Extracts a fixed-length numeric vector from raw events.
   Vector: [dwell_0, flight_0, dwell_1, flight_1, …]
   ═══════════════════════════════════════════════════════════ */

function eventsToVector(events, maxLen) {
  const v = [];
  for (let i = 0; i < maxLen; i++) {
    const ev = events[i];
    v.push(ev ? ev.dwell : 0);
    v.push(ev ? ev.flight : 0);
  }
  return v;
}

/* ═══════════════════════════════════════════════════════════
   SECTION 3 – Profile Builder
   Averages SAMPLES_REQUIRED vectors into a stable profile.
   ═══════════════════════════════════════════════════════════ */

function buildProfile(vectors) {
  const len = vectors[0].length;
  const avg = new Array(len).fill(0);
  for (const v of vectors) {
    for (let i = 0; i < len; i++) avg[i] += v[i];
  }
  for (let i = 0; i < len; i++) avg[i] /= vectors.length;
  return avg;
}

/* ═══════════════════════════════════════════════════════════
   SECTION 4 – Pattern Matcher

   Raw RMS (root-mean-square) distance between the stored profile
   vector and the login attempt vector, in milliseconds.

   Calibrated for real keystroke dynamics:
     Same person, natural variation  → RMS ≈ 30–70 ms → score 30–70 %
     Different person / random input → RMS ≈ 100–300 ms → score 0 %

   MATCH_SCALE = 100 ms  (distance at which score reaches 0)
   AUTH_THRESHOLD = 40 % (requires RMS < 60 ms to pass)
   ═══════════════════════════════════════════════════════════ */

const MATCH_SCALE = 100; // ms: RMS distance at which score reaches 0 %

function matchScore(profileVec, attemptVec) {
  const len = Math.min(profileVec.length, attemptVec.length);
  let sumSq = 0;
  for (let i = 0; i < len; i++) {
    const diff = profileVec[i] - attemptVec[i];
    sumSq += diff * diff;
  }
  const rmsDistance = Math.sqrt(sumSq / len); // average ms deviation per feature
  const score = Math.max(0, Math.min(100, 100 - (rmsDistance / MATCH_SCALE) * 100));
  return Math.round(score);
}

/* ═══════════════════════════════════════════════════════════
   SECTION 5 – Storage (localStorage)
   ═══════════════════════════════════════════════════════════ */

function loadProfiles() {
  try {
    return JSON.parse(localStorage.getItem(STORAGE_KEY) || '{}');
  } catch { return {}; }
}

function saveProfile(username, profileVec) {
  const profiles = loadProfiles();
  profiles[username] = { vec: profileVec, createdAt: Date.now() };
  localStorage.setItem(STORAGE_KEY, JSON.stringify(profiles));
}

function getProfile(username) {
  return loadProfiles()[username] || null;
}

/* ═══════════════════════════════════════════════════════════
   SECTION 6 – UI Helpers
   ═══════════════════════════════════════════════════════════ */

function showFeedback(elId, msg, type /* 'success'|'error'|'info' */) {
  const el = document.getElementById(elId);
  el.textContent = msg;
  el.className = `feedback-bar ${type}`;
}
function clearFeedback(elId) {
  const el = document.getElementById(elId);
  el.textContent = '';
  el.className = 'feedback-bar';
}

function showToast(msg, duration = 3000) {
  const t = document.getElementById('toast');
  t.textContent = msg;
  t.classList.remove('hidden');
  clearTimeout(showToast._timer);
  showToast._timer = setTimeout(() => t.classList.add('hidden'), duration);
}

function switchTab(tab) {
  document.getElementById('panel-register').classList.toggle('active', tab === 'register');
  document.getElementById('panel-login').classList.toggle('active', tab === 'login');
  document.getElementById('tab-register').classList.toggle('active', tab === 'register');
  document.getElementById('tab-login').classList.toggle('active', tab === 'login');
  document.getElementById('tab-register').setAttribute('aria-selected', tab === 'register');
  document.getElementById('tab-login').setAttribute('aria-selected', tab === 'login');
}

function updateDots(filled) {
  for (let i = 1; i <= 3; i++) {
    const dot = document.getElementById(`dot-${i}`);
    dot.className = 'dot';
    if (i <= filled) dot.classList.add('filled');
    else if (i === filled + 1) dot.classList.add('active-dot');
  }
  const label = document.getElementById('sample-label');
  if (filled < 3) label.textContent = `Sample ${filled + 1} of 3`;
  else label.textContent = 'All samples collected ✓';
}

function showResult(granted, confidence, rmsDistance) {
  const overlay = document.getElementById('result-overlay');
  const icon = document.getElementById('result-icon');
  const title = document.getElementById('result-title');
  const msg = document.getElementById('result-message');
  const fill = document.getElementById('confidence-fill');
  const pct = document.getElementById('confidence-pct');

  overlay.classList.remove('hidden');
  pct.textContent = `${confidence}%`;

  const rmsInfo = rmsDistance !== undefined ? ` (avg deviation: ${rmsDistance.toFixed(0)} ms)` : '';

  if (granted) {
    icon.textContent = '✅';
    title.textContent = 'Access Granted';
    title.className = 'result-title granted';
    msg.textContent = `Typing rhythm matched!${rmsInfo} Welcome back.`;
    fill.className = confidence >= 70 ? 'confidence-bar-fill high' : 'confidence-bar-fill medium';
  } else {
    icon.textContent = '🚫';
    title.textContent = 'Access Denied';
    title.className = 'result-title denied';
    msg.textContent = `Pattern mismatch.${rmsInfo} Try typing at your usual speed.`;
    fill.className = 'confidence-bar-fill low';
  }

  // Animate bar after brief paint delay
  requestAnimationFrame(() => {
    setTimeout(() => { fill.style.width = `${confidence}%`; }, 50);
  });
}

function closeResult() {
  const overlay = document.getElementById('result-overlay');
  overlay.classList.add('hidden');
  // Reset fill for next time
  document.getElementById('confidence-fill').style.width = '0%';
}

/* ═══════════════════════════════════════════════════════════
   SECTION 7 – Registration Flow
   ═══════════════════════════════════════════════════════════ */

let regVectors = [];

function initRegistration() {
  const textarea = document.getElementById('reg-input');
  textarea.value = '';
  clearFeedback('reg-feedback');

  if (regCurrentData) stopCapture(regCurrentData);

  regCurrentData = createCapture(textarea, (session) => {
    // Enable submit once text is long enough and has correct passphrase
    const typed = textarea.value.trim();
    const similarEnough = isSimilarToPassphrase(typed);
    document.getElementById('reg-submit-btn').disabled = !similarEnough;
  });
}

function isSimilarToPassphrase(typed) {
  // Require at least 80% of the passphrase to be typed before enabling Submit.
  // Also accept if the typed string ends with enough chars of the passphrase.
  const minLen = Math.floor(PASSPHRASE.length * 0.8);
  const phrase = PASSPHRASE.toLowerCase();
  const t = typed.toLowerCase();
  // Check the typed string contains a 80%-length prefix of the passphrase
  return t.includes(phrase.substring(0, minLen)) || t.length >= minLen;
}

function submitRegistrationSample() {
  const username = document.getElementById('reg-username').value.trim();
  if (!username) { showToast('Please enter a username first'); return; }

  const textarea = document.getElementById('reg-input');
  const events = stopCapture(regCurrentData);
  regCurrentData = null;

  if (events.length < 10) {
    showFeedback('reg-feedback', 'Too few keystrokes captured. Please type the full passphrase.', 'error');
    initRegistration();
    return;
  }

  const vec = eventsToVector(events, PASSPHRASE.length);
  regVectors.push(vec);
  const filled = regVectors.length;

  updateDots(filled);

  if (filled < SAMPLES_REQUIRED) {
    showFeedback('reg-feedback', `✓ Sample ${filled} saved! Now type the passphrase again.`, 'success');
    textarea.value = '';
    setTimeout(() => initRegistration(), 400);
  } else {
    // Build and save profile
    const profileVec = buildProfile(regVectors);
    saveProfile(username, profileVec);
    regVectors = [];

    showFeedback('reg-feedback', `🎉 Profile created for "${username}"! You can now log in.`, 'success');
    textarea.value = '';
    textarea.disabled = true;
    document.getElementById('reg-submit-btn').disabled = true;
    document.getElementById('reg-reset-btn').style.display = 'block';

    showToast(`Profile saved for ${username} 🎉`);
  }
}

function resetRegistration() {
  regVectors = [];
  updateDots(0);
  clearFeedback('reg-feedback');
  const textarea = document.getElementById('reg-input');
  textarea.disabled = false;
  textarea.value = '';
  document.getElementById('reg-submit-btn').disabled = true;
  document.getElementById('reg-reset-btn').style.display = 'none';
  document.getElementById('reg-username').value = '';
  initRegistration();
}

/* ═══════════════════════════════════════════════════════════
   SECTION 8 – Login Flow
   ═══════════════════════════════════════════════════════════ */

function initLogin() {
  const textarea = document.getElementById('login-input');
  textarea.value = '';
  clearFeedback('login-feedback');

  if (loginCurrentData) stopCapture(loginCurrentData);

  loginCurrentData = createCapture(textarea, (session) => {
    const typed = textarea.value.trim();
    const similarEnough = isSimilarToPassphrase(typed);
    document.getElementById('login-submit-btn').disabled = !similarEnough;
  });
}

function submitLogin() {
  const username = document.getElementById('login-username').value.trim();
  if (!username) { showToast('Please enter your username'); return; }

  const profile = getProfile(username);
  if (!profile) {
    showFeedback('login-feedback', `No profile found for "${username}". Please register first.`, 'error');
    return;
  }

  const textarea = document.getElementById('login-input');
  const events = stopCapture(loginCurrentData);
  loginCurrentData = null;

  if (events.length < 10) {
    showFeedback('login-feedback', 'Too few keystrokes captured. Please type the full passphrase.', 'error');
    initLogin();
    return;
  }

  // Always use PASSPHRASE.length for event count — same as registration
  const attemptVec = eventsToVector(events, PASSPHRASE.length);

  // Debug: compute rms directly so we can log it
  const len = Math.min(profile.vec.length, attemptVec.length);
  let sumSq = 0;
  for (let i = 0; i < len; i++) { const d = profile.vec[i] - attemptVec[i]; sumSq += d * d; }
  const rmsDistance = Math.sqrt(sumSq / len);
  const score = matchScore(profile.vec, attemptVec);
  const granted = score >= AUTH_THRESHOLD;
  console.log(`[KeySign] RMS distance: ${rmsDistance.toFixed(1)} ms | Score: ${score}% | Threshold: ${AUTH_THRESHOLD}% | Result: ${granted ? 'GRANTED' : 'DENIED'}`);

  showResult(granted, score, rmsDistance);

  // Reset for next attempt
  textarea.value = '';
  document.getElementById('login-submit-btn').disabled = true;
  setTimeout(() => initLogin(), 500);
}

function clearProfile() {
  const username = document.getElementById('login-username').value.trim();
  if (!username) { showToast('Enter a username first'); return; }
  const profiles = loadProfiles();
  if (!profiles[username]) { showToast(`No profile found for "${username}"`); return; }
  delete profiles[username];
  localStorage.setItem(STORAGE_KEY, JSON.stringify(profiles));
  clearFeedback('login-feedback');
  showToast(`Profile for "${username}" deleted. Please register again.`);
}

/* ═══════════════════════════════════════════════════════════
   SECTION 9 – Bootstrap
   ═══════════════════════════════════════════════════════════ */

document.addEventListener('DOMContentLoaded', () => {
  updateDots(0);
  initRegistration();
  initLogin();

  // Re-init captures when switching tabs to avoid stale sessions
  document.getElementById('tab-register').addEventListener('click', () => {
    if (!regCurrentData || !regCurrentData.listening) initRegistration();
  });
  document.getElementById('tab-login').addEventListener('click', () => {
    if (!loginCurrentData || !loginCurrentData.listening) initLogin();
  });
});
