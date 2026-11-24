'use strict';

/* ========= Configuração ========= */
const DATA_PATH = 'data.json';      // arquivo criptografado no repositório
const ITERATIONS = 600000;          // PBKDF2 — deixa cada tentativa de PIN lenta
const LS_CFG = 'hub.cfg';           // token + repo (só neste navegador)
const LS_CACHE = 'hub.cache';       // cópia local do data.json criptografado

const $ = (s) => document.querySelector(s);
const te = new TextEncoder();
const td = new TextDecoder();

const state = {
  blob: null,      // conteúdo criptografado atual
  sha: null,       // sha do arquivo no GitHub
  key: null,       // chave AES derivada do PIN (só em memória)
  salt: null,
  iter: ITERATIONS,
  data: null,      // { title, links: [{ id, name, url, desc, icon }] }
  dirty: false,    // há alterações não enviadas ao GitHub
  editing: false,
};

/* ========= Base64 / criptografia ========= */
function toB64(buf) {
  const bytes = new Uint8Array(buf);
  let s = '';
  for (let i = 0; i < bytes.length; i += 0x8000) {
    s += String.fromCharCode.apply(null, bytes.subarray(i, i + 0x8000));
  }
  return btoa(s);
}
const fromB64 = (s) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));

async function deriveKey(pin, salt, iterations) {
  const base = await crypto.subtle.importKey('raw', te.encode(pin), 'PBKDF2', false, ['deriveKey']);
  return crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt, iterations, hash: 'SHA-256' },
    base,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );
}

async function encryptData(obj) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, state.key, te.encode(JSON.stringify(obj)));
  return { v: 1, kdf: 'PBKDF2-SHA256', iter: state.iter, salt: toB64(state.salt), iv: toB64(iv), data: toB64(ct) };
}

async function decryptBlob(blob, pin) {
  const salt = fromB64(blob.salt);
  const key = await deriveKey(pin, salt, blob.iter);
  const pt = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: fromB64(blob.iv) }, key, fromB64(blob.data));
  return { key, salt, iter: blob.iter, data: JSON.parse(td.decode(pt)) };
}

/* ========= Config / cache local ========= */
function detectRepo() {
  const host = location.hostname;
  if (!host.endsWith('.github.io')) return {};
  const owner = host.split('.')[0];
  const first = location.pathname.split('/').filter(Boolean)[0];
  const repo = first && !first.includes('.') ? first : host;
  return { owner, repo };
}

function readJSON(key) {
  try { return JSON.parse(localStorage.getItem(key)); } catch { return null; }
}

function getCfg() {
  const saved = readJSON(LS_CFG) || {};
  const det = detectRepo();
  return {
    token: saved.token || '',
    owner: saved.owner || det.owner || '',
    repo: saved.repo || det.repo || '',
    branch: saved.branch || 'main',
  };
}
const canSync = (c = getCfg()) => Boolean(c.token && c.owner && c.repo);

function writeCache() {
  localStorage.setItem(LS_CACHE, JSON.stringify({ blob: state.blob, sha: state.sha, dirty: state.dirty }));
}

/* ========= GitHub ========= */
function apiUrl(c) {
  return `https://api.github.com/repos/${encodeURIComponent(c.owner)}/${encodeURIComponent(c.repo)}/contents/${DATA_PATH}`;
}
function ghHeaders(c) {
  const h = { Accept: 'application/vnd.github+json' };
  if (c.token) h.Authorization = `Bearer ${c.token}`;
  return h;
}

async function loadRemote() {
  const c = getCfg();
  // 1) API do GitHub: sempre a versão mais nova (o Pages demora ~1 min para atualizar)
  if (c.owner && c.repo) {
    try {
      const r = await fetch(`${apiUrl(c)}?ref=${encodeURIComponent(c.branch)}&t=${Date.now()}`, {
        headers: ghHeaders(c), cache: 'no-store',
      });
      if (r.ok) {
        const j = await r.json();
        return { blob: JSON.parse(atob(j.content.replace(/\s/g, ''))), sha: j.sha };
      }
    } catch { /* cai para o Pages */ }
  }
  // 2) Arquivo servido pelo próprio GitHub Pages
  try {
    const r = await fetch(`${DATA_PATH}?t=${Date.now()}`, { cache: 'no-store' });
    if (r.ok) return { blob: await r.json() };
    if (r.status === 404) return { missing: true };
  } catch { /* offline */ }
  return { error: true };
}

async function fetchSha(c) {
  const r = await fetch(`${apiUrl(c)}?ref=${encodeURIComponent(c.branch)}&t=${Date.now()}`, {
    headers: ghHeaders(c), cache: 'no-store',
  });
  if (r.status === 404) return null;
  if (!r.ok) throw new Error(await ghError(r));
  return (await r.json()).sha;
}

async function ghError(r) {
  if (r.status === 401) return 'token inválido ou expirado';
  if (r.status === 403 || r.status === 404) return 'sem permissão ou repositório não encontrado';
  try { return (await r.json()).message || `HTTP ${r.status}`; } catch { return `HTTP ${r.status}`; }
}

function putFile(c, sha, message) {
  const body = {
    message,
    content: btoa(JSON.stringify(state.blob, null, 2)),
    branch: c.branch,
  };
  if (sha) body.sha = sha;
  return fetch(apiUrl(c), {
    method: 'PUT',
    headers: { ...ghHeaders(c), 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });
}

async function push(message) {
  const c = getCfg();
  if (!canSync(c)) return;
  try {
    let r = await putFile(c, state.sha, message);
    if (r.status === 409 || r.status === 422) {
      // sha desatualizado (alterado em outro dispositivo) ou ausente: pega o atual e tenta de novo
      r = await putFile(c, await fetchSha(c), message);
    }
    if (!r.ok) throw new Error(await ghError(r));
    state.sha = (await r.json()).content.sha;
    state.dirty = false;
    writeCache();
    toast('Salvo e sincronizado ✓', 'ok');
  } catch (e) {
    state.dirty = true;
    writeCache();
    toast(`Falha ao sincronizar: ${e.message}`, 'err');
  }
  updateBanner();
}

// Salvamentos em fila, um por vez
let queue = Promise.resolve();
function persist(message) {
  queue = queue.then(async () => {
    state.blob = await encryptData(state.data);
    state.dirty = true;
    writeCache();
    if (canSync()) await push(message);
    else toast('Salvo neste navegador. Configure o GitHub em ⚙️ para sincronizar.');
    updateBanner();
  });
  return queue;
}

/* ========= Tela de PIN ========= */
const pinForm = $('#pin-form');
const pinInput = $('#pin');
const pin2Input = $('#pin2');
const pinError = $('#pin-error');
const pinBtn = $('#pin-btn');

function setupMode() { return state.blob === null; }

function showLock() {
  $('#hub').hidden = true;
  $('#lock').hidden = false;
  pinBtn.disabled = false;
  if (setupMode()) {
    $('#lock-title').textContent = 'Criar PIN';
    $('#lock-sub').textContent = 'Primeiro acesso: escolha um PIN (mín. 4 caracteres)';
    pin2Input.hidden = false;
    pinBtn.textContent = 'Criar hub';
  } else {
    $('#lock-title').textContent = 'Hub';
    $('#lock-sub').textContent = 'Digite seu PIN';
    pin2Input.hidden = true;
    pinBtn.textContent = 'Entrar';
  }
  pinInput.focus();
}

function pinFail(msg) {
  pinError.textContent = msg;
  pinForm.classList.remove('shake');
  void pinForm.offsetWidth;
  pinForm.classList.add('shake');
}

pinForm.addEventListener('submit', async (e) => {
  e.preventDefault();
  pinError.textContent = '';
  const pin = pinInput.value;
  pinBtn.disabled = true;
  try {
    if (setupMode()) {
      if (pin.length < 4) return pinFail('O PIN precisa ter pelo menos 4 caracteres.');
      if (pin !== pin2Input.value) return pinFail('Os PINs não conferem.');
      state.salt = crypto.getRandomValues(new Uint8Array(16));
      state.iter = ITERATIONS;
      state.key = await deriveKey(pin, state.salt, state.iter);
      state.data = { title: 'Meus Projetos', links: [] };
      openHub();
      await persist('Cria hub');
    } else {
      pinBtn.textContent = 'Verificando…';
      try {
        const res = await decryptBlob(state.blob, pin);
        Object.assign(state, res);
        state.data.links ||= [];
        openHub();
      } catch {
        pinInput.value = '';
        pinFail('PIN incorreto.');
      }
    }
  } finally {
    pinBtn.disabled = false;
    if (!setupMode()) pinBtn.textContent = 'Entrar';
  }
});

/* ========= Hub ========= */
function openHub() {
  pinInput.value = '';
  pin2Input.value = '';
  $('#lock').hidden = true;
  $('#hub').hidden = false;
  render();
  updateBanner();
}

$('#btn-lock').addEventListener('click', () => location.reload());

$('#btn-edit').addEventListener('click', () => {
  state.editing = !state.editing;
  $('#btn-edit').classList.toggle('active', state.editing);
  $('#btn-edit').textContent = state.editing ? '✓ Concluir' : '✏️ Editar';
  render();
});

$('#search').addEventListener('input', render);

function colorFor(str) {
  let h = 0;
  for (const ch of str) h = (h * 31 + ch.codePointAt(0)) % 360;
  return `hsl(${h} 55% 42%)`;
}

function fillIcon(box, icon, url, name) {
  box.replaceChildren();
  box.style.background = '';
  const letter = () => {
    box.replaceChildren();
    box.textContent = (name || '?').trim().charAt(0).toUpperCase() || '?';
    box.style.background = colorFor(name || url || '?');
  };
  const img = (src) => {
    const i = new Image();
    i.alt = '';
    i.referrerPolicy = 'no-referrer';
    i.onerror = letter;
    i.src = src;
    box.append(i);
  };
  if (icon && /^(https?:|data:image\/)/i.test(icon)) img(icon);
  else if (icon) box.textContent = icon;               // emoji / texto curto
  else {
    try { img(`${new URL(url).origin}/favicon.ico`); } catch { letter(); }
  }
}

function el(tag, cls, text) {
  const e = document.createElement(tag);
  if (cls) e.className = cls;
  if (text != null) e.textContent = text;
  return e;
}

function toolBtn(label, title, cls, fn) {
  const b = el('button', `tool ${cls || ''}`, label);
  b.type = 'button';
  b.title = title;
  b.addEventListener('click', (e) => { e.preventDefault(); e.stopPropagation(); fn(); });
  return b;
}

function move(id, delta) {
  const links = state.data.links;
  const i = links.findIndex((l) => l.id === id);
  const j = i + delta;
  if (i < 0 || j < 0 || j >= links.length) return;
  [links[i], links[j]] = [links[j], links[i]];
  render();
  persist('Reordena projetos');
}

function removeLink(link) {
  if (!confirm(`Remover "${link.name}" do hub?`)) return false;
  state.data.links = state.data.links.filter((l) => l.id !== link.id);
  render();
  persist(`Remove ${link.name}`);
  return true;
}

function cardEl(link) {
  const a = el('a', 'card');
  a.href = link.url;
  a.target = '_blank';
  a.rel = 'noopener noreferrer';

  const box = el('div', 'icon-box');
  fillIcon(box, link.icon, link.url, link.name);

  const info = el('div', 'info');
  info.append(el('div', 'name', link.name));
  let host = link.url;
  try { host = new URL(link.url).host; } catch { /* mantém */ }
  info.append(el('div', link.desc ? 'desc' : 'host', link.desc || host));

  const tools = el('div', 'tools');
  tools.append(
    toolBtn('◀', 'Mover para trás', '', () => move(link.id, -1)),
    toolBtn('▶', 'Mover para frente', '', () => move(link.id, 1)),
    toolBtn('✎', 'Editar', '', () => openLinkDialog(link)),
    toolBtn('✕', 'Remover', 'del', () => removeLink(link)),
  );

  a.append(box, info, tools);
  a.addEventListener('click', (e) => {
    if (state.editing) { e.preventDefault(); openLinkDialog(link); }
  });
  return a;
}

function render() {
  const title = state.data.title || 'Meus Projetos';
  $('#hub-title').textContent = title;
  document.title = title;

  const q = $('#search').value.trim().toLowerCase();
  const list = state.data.links.filter((l) =>
    !q || `${l.name} ${l.desc || ''} ${l.url}`.toLowerCase().includes(q));

  const grid = $('#grid');
  grid.classList.toggle('editing', state.editing);
  grid.replaceChildren(...list.map(cardEl));
  $('#empty').hidden = state.data.links.length > 0;
  $('#search').hidden = state.data.links.length < 6;
}

function updateBanner() {
  const b = $('#banner');
  if (!state.dirty) { b.hidden = true; return; }
  b.hidden = false;
  b.replaceChildren();
  if (canSync()) {
    b.append('Há alterações que ainda não foram enviadas ao GitHub. ');
    const btn = el('button', 'btn small', 'Sincronizar agora');
    btn.addEventListener('click', () => { queue = queue.then(() => push('Sincroniza hub')); });
    b.append(btn);
  } else {
    b.append('As alterações estão salvas só neste navegador. Configure o GitHub em ⚙️ Configurações para publicar.');
  }
}

/* ========= Diálogo de link ========= */
const linkDlg = $('#link-dialog');
const lf = $('#link-form');
let editingId = null;
let iconData = null;   // imagem enviada (data URL)

const currentIcon = () => iconData || lf.icon.value.trim();
const updatePreview = () => fillIcon($('#icon-preview'), currentIcon(), normalizeUrl(lf.url.value) || '', lf.name.value);

function normalizeUrl(raw) {
  let v = (raw || '').trim();
  if (!v) return null;
  if (!/^[a-z][a-z0-9+.-]*:/i.test(v)) v = `https://${v}`;
  try {
    const u = new URL(v);
    return u.protocol === 'http:' || u.protocol === 'https:' ? u.href : null;
  } catch { return null; }
}

function openLinkDialog(link) {
  editingId = link ? link.id : null;
  lf.reset();
  iconData = null;
  if (link) {
    lf.name.value = link.name;
    lf.url.value = link.url;
    lf.desc.value = link.desc || '';
    if (link.icon && link.icon.startsWith('data:')) iconData = link.icon;
    else lf.icon.value = link.icon || '';
  }
  lf.icon.placeholder = iconData ? '(imagem enviada)' : 'https://…/logo.png ou 🚀';
  $('#link-dialog-title').textContent = link ? 'Editar projeto' : 'Adicionar projeto';
  $('#link-delete').hidden = !link;
  updatePreview();
  linkDlg.showModal();
  lf.name.focus();
}

$('#btn-add').addEventListener('click', () => openLinkDialog(null));

lf.name.addEventListener('input', updatePreview);
lf.url.addEventListener('change', updatePreview);
lf.icon.addEventListener('input', () => {
  iconData = null;
  lf.icon.placeholder = 'https://…/logo.png ou 🚀';
  updatePreview();
});

$('#icon-clear').addEventListener('click', () => {
  iconData = null;
  lf.icon.value = '';
  lf.icon.placeholder = 'https://…/logo.png ou 🚀';
  updatePreview();
});

$('#icon-file').addEventListener('change', async (e) => {
  const file = e.target.files[0];
  e.target.value = '';
  if (!file) return;
  try {
    iconData = await resizeImage(file, 128);
    lf.icon.value = '';
    lf.icon.placeholder = '(imagem enviada)';
    updatePreview();
  } catch {
    toast('Não foi possível ler essa imagem.', 'err');
  }
});

function resizeImage(file, size) {
  return new Promise((resolve, reject) => {
    const url = URL.createObjectURL(file);
    const img = new Image();
    img.onload = () => {
      const scale = Math.min(size / img.width, size / img.height, 1);
      const w = Math.max(1, Math.round(img.width * scale));
      const h = Math.max(1, Math.round(img.height * scale));
      const c = document.createElement('canvas');
      c.width = w; c.height = h;
      c.getContext('2d').drawImage(img, 0, 0, w, h);
      URL.revokeObjectURL(url);
      resolve(c.toDataURL('image/png'));
    };
    img.onerror = () => { URL.revokeObjectURL(url); reject(new Error('imagem inválida')); };
    img.src = url;
  });
}

lf.addEventListener('submit', (e) => {
  e.preventDefault();
  const url = normalizeUrl(lf.url.value);
  if (!url) { toast('Link inválido. Use um endereço http(s).', 'err'); lf.url.focus(); return; }
  const item = {
    name: lf.name.value.trim(),
    url,
    desc: lf.desc.value.trim(),
    icon: currentIcon(),
  };
  if (!item.name) { lf.name.focus(); return; }

  if (editingId) {
    const l = state.data.links.find((x) => x.id === editingId);
    Object.assign(l, item);
    persist(`Edita ${item.name}`);
  } else {
    state.data.links.push({ id: crypto.randomUUID(), ...item });
    persist(`Adiciona ${item.name}`);
  }
  linkDlg.close();
  render();
});

$('#link-delete').addEventListener('click', () => {
  const link = state.data.links.find((x) => x.id === editingId);
  if (link && removeLink(link)) linkDlg.close();
});

document.querySelectorAll('[data-close]').forEach((b) =>
  b.addEventListener('click', () => b.closest('dialog').close()));

/* ========= Configurações ========= */
const setDlg = $('#settings-dialog');
const sf = $('#settings-form');

$('#btn-settings').addEventListener('click', () => {
  const c = getCfg();
  sf.reset();
  sf.title.value = state.data.title || '';
  sf.token.value = c.token;
  sf.owner.value = c.owner;
  sf.repo.value = c.repo;
  sf.branch.value = c.branch;
  $('#sync-status').textContent = !canSync(c)
    ? 'Status: não configurado — alterações ficam só neste navegador.'
    : state.dirty ? 'Status: configurado, com alterações pendentes.' : 'Status: sincronizado ✓';
  setDlg.showModal();
});

sf.addEventListener('submit', async (e) => {
  e.preventDefault();
  const np = sf.newpin.value;
  if (np || sf.newpin2.value) {
    if (np.length < 4) { toast('O novo PIN precisa ter pelo menos 4 caracteres.', 'err'); return; }
    if (np !== sf.newpin2.value) { toast('Os novos PINs não conferem.', 'err'); return; }
  }

  localStorage.setItem(LS_CFG, JSON.stringify({
    token: sf.token.value.trim(),
    owner: sf.owner.value.trim(),
    repo: sf.repo.value.trim(),
    branch: sf.branch.value.trim() || 'main',
  }));

  let changed = false;
  const title = sf.title.value.trim() || 'Meus Projetos';
  if (title !== state.data.title) { state.data.title = title; changed = true; }
  if (np) {
    state.salt = crypto.getRandomValues(new Uint8Array(16));
    state.iter = ITERATIONS;
    state.key = await deriveKey(np, state.salt, state.iter);
    changed = true;
  }

  setDlg.close();
  render();
  if (changed) persist(np ? 'Troca PIN' : 'Atualiza título');
  else if (state.dirty && canSync()) queue = queue.then(() => push('Sincroniza hub'));
  else toast('Configurações salvas ✓', 'ok');
  updateBanner();
});

/* ========= Toast ========= */
let toastTimer;
function toast(msg, kind = '') {
  const t = $('#toast');
  t.textContent = msg;
  t.className = `toast ${kind}`;
  t.hidden = false;
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => { t.hidden = true; }, kind === 'err' ? 6000 : 3000);
}

/* ========= Início ========= */
async function init() {
  if (!window.crypto || !crypto.subtle) {
    $('#lock-sub').textContent = 'Abra o hub por HTTPS (ex.: GitHub Pages) — o navegador bloqueia a criptografia aqui.';
    pinBtn.disabled = true;
    return;
  }
  pinBtn.disabled = true;
  $('#lock-sub').textContent = 'Carregando…';

  const cache = readJSON(LS_CACHE);
  if (cache && cache.dirty && cache.blob) {
    // alterações locais ainda não enviadas têm prioridade
    Object.assign(state, { blob: cache.blob, sha: cache.sha || null, dirty: true });
  } else {
    const r = await loadRemote();
    if (r.blob) {
      state.blob = r.blob;
      state.sha = r.sha || null;
      writeCache();
    } else if (r.error && cache && cache.blob) {
      state.blob = cache.blob;
      state.sha = cache.sha || null;
      toast('Sem conexão — usando a última cópia salva neste navegador.');
    } else if (r.error) {
      // não cai no modo "criar PIN" por falha de rede, para não sobrescrever o hub existente
      $('#lock-sub').textContent = 'Não foi possível carregar o hub. Verifique a conexão e recarregue a página.';
      return;
    }
  }
  showLock();
}

init();
