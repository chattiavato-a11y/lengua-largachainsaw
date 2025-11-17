/* ---------- CONFIG (must match Worker) ---------- */
const INTEGRITY_VALUE   = (document.querySelector('meta[name="integrity-token"]')?.content||'').trim() || 'https://chattiavato-a11y.github.io';
const CF_WORKER_URL = 'https://withered-mouse-9aee.grabem-holdem-nuts-right.workers.dev/';
const INTEGRITY_GATEWAY = CF_WORKER_URL.replace(/\/$/, '');
const INTEGRITY_PROTOCOLS = 'CORS,CSP,OPS-CySec-Core,CISA,NIST,PCI-DSS,SHA-384,SHA-512';
const CHANNELLA_HEADER = 'X-OPS-Channella';
const CHANNELLA_CANONICAL = 'ops-channella-v1';

function randomHex(bytes = 16){
  try {
    const view = new Uint8Array(bytes);
    const cryptoObj = (typeof window !== 'undefined' && window.crypto)
      ? window.crypto
      : (typeof crypto !== 'undefined' ? crypto : null);
    if (cryptoObj?.getRandomValues) {
      cryptoObj.getRandomValues(view);
      return Array.from(view, b => b.toString(16).padStart(2,'0')).join('');
    }
  } catch {}
  let fallback = '';
  for (let i=0;i<bytes;i++) fallback += Math.floor(Math.random()*256).toString(16).padStart(2,'0');
  return fallback;
}
const SESSION_NONCE = randomHex(16);

const API_BASE = INTEGRITY_GATEWAY;           // single Worker handles auth+chat+stt
const CHAT_PATH = '/api/chat';
const STT_PATH  = '/api/stt';
const AUTH_URL  = `${API_BASE}/auth/issue`;
const ESCALATION_URL = `${API_BASE}/fallback/escalate`;

const STATUS_POLL_INTERVAL_MS = 30000;
const API_DEGRADE_MEMORY_MS = 90000;
const CONFIDENCE_THRESHOLD = 'low'; // escalate when server marks "low"

/* ---------- Shared headers ---------- */
const sharedIntegrityHeaders = Object.freeze({
  'X-Integrity': INTEGRITY_VALUE,
  'X-Integrity-Gateway': INTEGRITY_GATEWAY,
  'X-Integrity-Protocols': INTEGRITY_PROTOCOLS,
  'X-Integrity-Key': CHANNELLA_CANONICAL,
  [CHANNELLA_HEADER]: CHANNELLA_CANONICAL,
  'X-Session-Nonce': SESSION_NONCE
});

/* ---------- UI refs ---------- */
const titleEl = document.getElementById('titleEl');
const langCtrl = document.getElementById('langCtrl');
const themeCtrl = document.getElementById('themeCtrl');
const statusBanner = document.getElementById('status-banner');
const statusText = document.getElementById('statusText');
const logEl  = document.querySelector('#chat-log');
const form   = document.querySelector('#chatbot-input-row');
const input  = document.querySelector('#chatbot-input');
const send   = document.querySelector('#chatbot-send');
const honeyp = document.querySelector('#chatbot-company');
const tTok   = document.querySelector('#turnstile-token');

const state = { conversation:[], isSending:false };
const integrityState = { timer:null, focusBound:false, summary:null, apiDegradedUntil:0 };
const storage = (()=>{ try{return window.localStorage;}catch{return null;} })();
const securityState = { lastSweep:null };

const i18n = Object.freeze({
  en:{ title:'Chattia', input:'Type your message… [Enter]', sendLabel:'Send message',
      errors:{ unreachable:"Error: Can’t reach Chattia." },
      status:{ online:'Secure link active', offline:'Offline – storing messages locally', fallback:'Primary API unreachable – using local safeguard' },
      notes:{ verifying:'Verifying integrity…', gatewayReady:'Integrity synchronized (signature TTL {ttl}s)', gatewayDegraded:'Integrity gateway unreachable', apiDegraded:'Primary API unreachable', offlineQueue:'Offline – local queue' } },
  es:{ title:'Chattia', input:'Escribe tu mensaje… [Enter]', sendLabel:'Enviar mensaje',
      errors:{ unreachable:'Error: No puedo conectar con Chattia.' },
      status:{ online:'Canal seguro activo', offline:'Sin conexión – guardando localmente', fallback:'API principal inalcanzable – salvaguarda local' },
      notes:{ verifying:'Verificando integridad…', gatewayReady:'Pasarela sincronizada (TTL de firma {ttl}s)', gatewayDegraded:'Pasarela inalcanzable', apiDegraded:'API inalcanzable', offlineQueue:'Sin conexión – cola local' } }
});

function currentLang(){ const lng = (document.documentElement.lang || 'en').toLowerCase(); return lng.startsWith('es') ? 'es' : 'en'; }
function setLocale(locale){
  document.documentElement.lang = locale;
  const L = i18n[locale]||i18n.en;
  titleEl.textContent = L.title;
  input.placeholder = L.input;
  send.setAttribute('aria-label', L.sendLabel);
  langCtrl.textContent = locale==='es'?'EN':'ES';
  refreshStatusBanner();
  try{ localStorage.setItem('chattia:locale', locale); }catch{}
}
function cycleLocale(){ setLocale(currentLang()==='en'?'es':'en'); }

/* ---------- Theme ---------- */
const THEME_KEY = 'chattia-theme';
function applyTheme(theme){
  document.body.dataset.theme = theme;
  themeCtrl.textContent = theme === 'dark' ? 'Light' : 'Dark';
  try{ localStorage.setItem(THEME_KEY, theme); }catch{}
}
(function initTheme(){
  const stored = (()=>{ try{return localStorage.getItem(THEME_KEY);}catch{return null;} })();
  const prefersDark = window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches;
  applyTheme(stored || (prefersDark?'dark':'light'));
})();
themeCtrl.addEventListener('click', ()=> applyTheme(document.body.dataset.theme==='dark'?'light':'dark'));

/* ---------- Status / Integrity ---------- */
function getSummaryTtl(summary){
  const ttlRaw = Number(summary?.signature_ttl ?? summary?.signatureTtl ?? summary?.signatureTTL);
  return Number.isFinite(ttlRaw) ? ttlRaw : null;
}
function isApiDegraded(){ return Date.now() < (integrityState.apiDegradedUntil || 0); }
function markApiDegraded(ms=API_DEGRADE_MEMORY_MS){ integrityState.apiDegradedUntil = Date.now() + Math.max(0, ms); }
function clearApiDegraded(){ integrityState.apiDegradedUntil = 0; }

function formatStatusNote(locale, key, vars={}){
  if(!key) return '';
  const dict = i18n[locale]?.notes || i18n.en.notes || {};
  let template = dict[key]; if(!template) return '';
  return template.replace(/\{([^}]+)\}/g, (_, t)=> String(vars[t.trim()] ?? ''));
}
function refreshStatusBanner(noteKey=null, vars=null){
  const locale = currentLang();
  const statusCfg = i18n[locale]?.status || i18n.en.status;
  let mode = 'online';
  if(!navigator.onLine) mode = 'offline';
  else if (isApiDegraded()) mode = 'fallback';
  statusBanner.classList.remove('status-online','status-offline','status-fallback');
  statusBanner.classList.add(mode==='fallback'?'status-fallback':(mode==='offline'?'status-offline':'status-online'));
  const label = statusCfg[mode] || statusCfg.online;
  const note = noteKey ? formatStatusNote(locale, noteKey, vars||{}) : '';
  statusText.textContent = note ? `${label} — ${note}` : label;
}
async function pollIntegritySummary(){
  if(!navigator.onLine){ refreshStatusBanner('offlineQueue'); return null; }
  try{
    const res = await fetch(`${INTEGRITY_GATEWAY}/health/summary`, { headers: sharedIntegrityHeaders, cache:'no-store' });
    if(!res.ok) throw new Error('integrity_health_error:'+res.status);
    const data = await res.json();
    integrityState.summary = data;
    if(!isApiDegraded()){
      const ttl = getSummaryTtl(data);
      refreshStatusBanner('gatewayReady', { ttl: Number.isFinite(ttl) ? ttl : 'N/A' });
    }
    return data;
  }catch{
    integrityState.summary = null;
    if(!isApiDegraded()) refreshStatusBanner('gatewayDegraded');
    return null;
  }
}
function startIntegrityMonitor(){
  refreshStatusBanner('verifying');
  pollIntegritySummary();
  if(integrityState.timer) clearInterval(integrityState.timer);
  integrityState.timer = setInterval(pollIntegritySummary, STATUS_POLL_INTERVAL_MS);
  if(!integrityState.focusBound){
    window.addEventListener('focus', pollIntegritySummary);
    integrityState.focusBound = true;
  }
}

/* ---------- Memory ---------- */
const MEMORY_KEY = 'chattia.memory.v1';
const MEMORY_WINDOW = 40;
function validMemoryEntry(entry){ return entry && typeof entry === 'object' && typeof entry.role === 'string' && typeof entry.content === 'string'; }
function loadMemory(){
  try { const raw = localStorage.getItem(MEMORY_KEY); if(!raw) return []; const arr = JSON.parse(raw); return Array.isArray(arr)?arr.filter(validMemoryEntry).slice(-MEMORY_WINDOW):[]; } catch { return []; }
}
function persistMemory(){ try{ localStorage.setItem(MEMORY_KEY, JSON.stringify(state.conversation.slice(-MEMORY_WINDOW))); }catch{} }
function recordMessage(role, content, meta = {}){ state.conversation.push({ role, content, meta, ts: Date.now() }); if(state.conversation.length>MEMORY_WINDOW) state.conversation = state.conversation.slice(-MEMORY_WINDOW); persistMemory(); }

/* ---------- UI helpers ---------- */
function addMsg(text, who='bot'){
  const div = document.createElement('div');
  div.className = `chat-msg ${who==='user'?'user':'bot'}`;
  div.textContent = String(text||'').trim() || '…';
  logEl.appendChild(div);
  logEl.scrollTop = logEl.scrollHeight;
  return div;
}
function updateSend(){
  const disabled = state.isSending || !input.value.trim();
  send.disabled = disabled;
}

/* ---------- Integrity signing ---------- */
function hexNonce32(){ return randomHex(16); }
async function sha256Hex(input){
  const enc = typeof input==='string' ? new TextEncoder().encode(input) : (input instanceof Uint8Array ? input : new Uint8Array(input));
  const d = await crypto.subtle.digest('SHA-256', enc);
  return [...new Uint8Array(d)].map(b=>b.toString(16).padStart(2,'0')).join('');
}
async function mintSignature(path, method, bodySha){
  const ts = Math.floor(Date.now()/1000);
  const nonce = hexNonce32();
  const payload = { ts, nonce, method, path, body_sha256: bodySha };
  const r = await fetch(AUTH_URL, { method:'POST', headers:{...sharedIntegrityHeaders,'Content-Type':'application/json'}, body:JSON.stringify(payload) });
  if (!r.ok) throw new Error('auth_issue_failed');
  const j = await r.json();
  if (!j?.signature) throw new Error('signature_missing');
  return { signature:j.signature, ts:String(ts), nonce };
}
async function signedPost(path, json){
  const body = JSON.stringify(json);
  const bodySha = await sha256Hex(body);
  const {signature, ts, nonce} = await mintSignature(path, 'POST', bodySha);
  return fetch(`${API_BASE}${path}`, {
    method:'POST',
    headers:{ ...sharedIntegrityHeaders, 'Content-Type':'application/json','X-Request-Signature':signature,'X-Request-Timestamp':ts,'X-Request-Nonce':nonce },
    body
  });
}

/* ---------- Fallback reply ---------- */
function fallbackReply(userText){
  try { if (window.FallbackKB?.reply) return window.FallbackKB.reply(userText||'', currentLang()); } catch {}
  return currentLang()==='es' ? 'Estoy en modo local protegido. ¿En qué puedo ayudarte?' : 'I’m in safeguarded local mode. How can I help?';
}
/* ---------- Bootstrap ---------- */
function bootstrapConversation(){
  const saved = loadMemory();
  if (saved.length){
    state.conversation = saved;
    for (const msg of saved) addMsg(msg.content, msg.role === 'user' ? 'user' : 'bot');
    return;
  }
  const greeting = fallbackReply('hello');
  addMsg(greeting,'bot');
  recordMessage('assistant', greeting, { source:'fallback', reason:'greeting' });
}
setLocale((()=>{ try{ return localStorage.getItem('chattia:locale')||'en'; }catch{return 'en';} })());
langCtrl.addEventListener('click', cycleLocale);
bootstrapConversation();
startIntegrityMonitor();

/* ---------- Chat flow ---------- */
form.addEventListener('submit', async (e)=>{
  e.preventDefault();
  if (honeyp?.value.trim()) return; // honeypot

  const msg = input.value.trim();
  if (!msg) return;
  input.value=''; updateSend();

  state.isSending = true;
  updateSend();

  addMsg(msg,'user');
  recordMessage('user', msg, { source:'web' });

  const thinking = addMsg('…','bot');

  try{
    const payload = {
      messages: state.conversation.map(m => ({ role:m.role, content:m.content })),
      metadata:{ channel:'chattia-web', locale: currentLang() }
    };

    const r = await signedPost(CHAT_PATH, payload);
    if(!r.ok){
      markApiDegraded();
      throw new Error(`chat_failed:${r.status}`);
    }
    const j = await r.json();
    const reply = (j.reply||'').trim();

    // escalate if low confidence or empty
    const confidence = (j.confidence||'').toLowerCase();
    const shouldEscalate = !reply || confidence === 'low';
    if (shouldEscalate){
      const fb = fallbackReply(msg);
      thinking.textContent = fb;
      recordMessage('assistant', fb, { source:'fallback', reason:'low_confidence', upstreamReply: reply||null, confidence });
      // notify CF Worker for telemetry
      try{
        fetch(ESCALATION_URL, {
          method:'POST',
          headers:{ ...sharedIntegrityHeaders, 'Content-Type':'application/json' },
          body: JSON.stringify({ reason:'low_confidence', confidence, userText: msg, fallback: fb, timestamp: new Date().toISOString() })
        });
      }catch{}
    } else {
      thinking.textContent = reply;
      recordMessage('assistant', reply, { source:'api', confidence });
    }
    clearApiDegraded();
    refreshStatusBanner('gatewayReady', { ttl: getSummaryTtl(integrityState.summary) ?? 'N/A' });
  }catch(err){
    markApiDegraded();
    const fb = fallbackReply(msg);
    thinking.textContent = fb;
    recordMessage('assistant', fb, { source:'fallback', reason:'network_error', error: String(err?.message||'error') });
    refreshStatusBanner('apiDegraded');
    try{
      fetch(ESCALATION_URL, {
        method:'POST',
        headers:{ ...sharedIntegrityHeaders, 'Content-Type':'application/json' },
        body: JSON.stringify({ reason:'network_error', userText: msg, fallback: fb, timestamp: new Date().toISOString() })
      });
    }catch{}
  }finally{
    state.isSending = false;
    updateSend();
  }
});

input.addEventListener('input', updateSend);
updateSend();
