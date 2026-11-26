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
  data: null,      // { title, links: [{ id, name, url, desc, thumb, thumbAuto }] }
  dirty: false,    // há alterações não enviadas ao GitHub
  editing: false,
  lockNote: '',    // aviso na tela de PIN
  generating: new Set(),   // ids com prévia sendo gerada
  thumbFailed: new Set(),  // ids cuja prévia falhou nesta sessão
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
    true,                       // exportável, para o "lembrar neste dispositivo"
    ['encrypt', 'decrypt']
  );
}

async function encryptData(obj) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, state.key, te.encode(JSON.stringify(obj)));
  return { v: 1, kdf: 'PBKDF2-SHA256', iter: state.iter, salt: toB64(state.salt), iv: toB64(iv), data: toB64(ct) };
}

async function decryptWith(blob, key) {
  const pt = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: fromB64(blob.iv) }, key, fromB64(blob.data));
  return JSON.parse(td.decode(pt));
}

async function decryptBlob(blob, pin) {
  const salt = fromB64(blob.salt);
  const key = await deriveKey(pin, salt, blob.iter);
  return { key, salt, iter: blob.iter, data: await decryptWith(blob, key) };
}

/* ========= Lembrar PIN por dispositivo + IP ========= */
const LS_REMEMBER = 'hub.remember';

async function getPublicIp() {
  try {
    const r = await fetch('https://api.ipify.org?format=json', { cache: 'no-store', signal: AbortSignal.timeout(5000) });
    return (await r.json()).ip || null;
  } catch { return null; }
}

async function rememberDevice() {
  const ip = await getPublicIp();
  if (!ip) { toast('Não consegui identificar seu IP — o PIN não foi lembrado.', 'err'); return; }
  const raw = await crypto.subtle.exportKey('raw', state.key);
  localStorage.setItem(LS_REMEMBER, JSON.stringify({ key: toB64(raw), salt: toB64(state.salt), ip }));
}

const forgetDevice = () => localStorage.removeItem(LS_REMEMBER);

// Desbloqueia sozinho se este navegador já guardou a chave e o IP atual é o mesmo de quando o PIN foi digitado
async function tryRemembered() {
  const rem = readJSON(LS_REMEMBER);
  if (!rem || !state.blob) return false;
  if (rem.salt !== state.blob.salt) { forgetDevice(); return false; }   // PIN foi trocado
  const ip = await getPublicIp();
  if (!ip) { state.lockNote = 'Não consegui verificar seu IP — digite o PIN.'; return false; }
  if (ip !== rem.ip) { state.lockNote = 'Você está em outra rede (IP diferente) — digite o PIN.'; return false; }
  try {
    const key = await crypto.subtle.importKey('raw', fromB64(rem.key), 'AES-GCM', true, ['encrypt', 'decrypt']);
    const data = await decryptWith(state.blob, key);
    Object.assign(state, { key, salt: fromB64(state.blob.salt), iter: state.blob.iter, data });
    return true;
  } catch {
    forgetDevice();
    return false;
  }
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
      // formato "raw": funciona mesmo com o arquivo acima de 1 MB (as prévias ocupam espaço)
      const r = await fetch(`${apiUrl(c)}?ref=${encodeURIComponent(c.branch)}&t=${Date.now()}`, {
        headers: { ...ghHeaders(c), Accept: 'application/vnd.github.raw+json' }, cache: 'no-store',
      });
      if (r.ok) return { blob: await r.json() };   // o sha é buscado na hora de salvar
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
    headers: { ...ghHeaders(c), Accept: 'application/vnd.github.object+json' }, cache: 'no-store',
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
    if (!state.sha) state.sha = await fetchSha(c);
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
    $('#lock-sub').textContent = state.lockNote || 'Digite seu PIN';
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
      applyRemember();
      openHub();
      await persist('Cria hub');
    } else {
      pinBtn.textContent = 'Verificando…';
      try {
        const res = await decryptBlob(state.blob, pin);
        Object.assign(state, res);
        state.data.links ||= [];
        applyRemember();
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

function applyRemember() {
  if ($('#remember').checked) rememberDevice();
  else forgetDevice();
}

/* ========= Hub ========= */
function openHub() {
  pinInput.value = '';
  pin2Input.value = '';
  $('#lock').hidden = true;
  $('#hub').hidden = false;
  state.data.links.forEach(migrateLink);
  render();
  updateBanner();
  // gera, em segundo plano, a prévia dos projetos que ainda não têm imagem
  generateThumbs(state.data.links.filter((l) => !l.thumb && !state.thumbFailed.has(l.id)));
}

// versões antigas guardavam "icon" (URL de imagem/emoji); imagens viram prévia, emoji vira reserva
function migrateLink(l) {
  if (l.icon && /^(https?:|data:image\/)/i.test(l.icon) && !l.thumb) {
    l.thumb = l.icon;
    l.thumbAuto = false;
    delete l.icon;
  }
}

$('#btn-lock').addEventListener('click', () => {
  forgetDevice();
  location.reload();
});

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

function el(tag, cls, text) {
  const e = document.createElement(tag);
  if (cls) e.className = cls;
  if (text != null) e.textContent = text;
  return e;
}

/* ========= Prévias (imagem gerada a partir do site) ========= */
const THUMB_W = 480;
const THUMB_H = 300;

// Mostra a prévia; sem imagem (ou se falhar), mostra a inicial/emoji num fundo colorido
function fillThumb(box, { thumb, icon, name, url }, busy) {
  box.replaceChildren();
  box.style.background = '';
  const busyTag = () => { if (busy) box.append(el('span', 'thumb-busy', 'Gerando prévia…')); };
  const fallback = () => {
    box.replaceChildren();
    const label = icon || (name || '?').trim().charAt(0).toUpperCase() || '?';
    box.append(el('span', 'thumb-letter', label));
    box.style.background = colorFor(name || url || '?');
    busyTag();
  };
  if (!thumb) { fallback(); return; }
  const img = new Image();
  img.alt = '';
  img.referrerPolicy = 'no-referrer';
  img.onerror = fallback;
  img.src = thumb;
  box.append(img);
  busyTag();
}

async function fetchBlob(url) {
  const r = await fetch(url, { signal: AbortSignal.timeout(45000) });
  if (!r.ok) throw new Error(`HTTP ${r.status}`);
  const b = await r.blob();
  if (!b.type.startsWith('image/')) throw new Error('resposta não é imagem');
  return b;
}

// Reduz/recorta para 480x300 em JPEG (fica salvo criptografado junto com os links)
async function blobToThumb(blob, alignTop = true) {
  const bmp = await createImageBitmap(blob);
  const scale = Math.max(THUMB_W / bmp.width, THUMB_H / bmp.height);
  const w = bmp.width * scale;
  const h = bmp.height * scale;
  const c = document.createElement('canvas');
  c.width = THUMB_W;
  c.height = THUMB_H;
  const ctx = c.getContext('2d');
  ctx.fillStyle = '#fff';
  ctx.fillRect(0, 0, THUMB_W, THUMB_H);
  ctx.drawImage(bmp, (THUMB_W - w) / 2, alignTop ? 0 : (THUMB_H - h) / 2, w, h);
  bmp.close();
  return c.toDataURL('image/jpeg', 0.72);
}

// Tira um "print" do site: Microlink e, se falhar, thum.io
async function captureSite(url, force = false) {
  const sources = [
    async () => {
      const q = new URLSearchParams({
        url, screenshot: 'true', meta: 'false',
        'viewport.width': '1280', 'viewport.height': '800', waitForTimeout: '2500',
      });
      if (force) q.set('force', 'true');
      const r = await fetch(`https://api.microlink.io/?${q}`, { signal: AbortSignal.timeout(60000) });
      const j = await r.json();
      const shot = j && j.data && j.data.screenshot && j.data.screenshot.url;
      if (!shot) throw new Error((j && j.message) || 'sem screenshot');
      return fetchBlob(shot);
    },
    () => fetchBlob(`https://image.thum.io/get/width/1280/crop/800/noanimate/${force ? 'maxAge/1/' : ''}${url}`),
  ];
  for (const source of sources) {
    try { return await blobToThumb(await source()); } catch { /* tenta o próximo */ }
  }
  throw new Error('não foi possível gerar a prévia');
}

async function generateThumbs(links, force = false) {
  const todo = links.filter((l) => !state.generating.has(l.id));
  if (!todo.length) return;
  todo.forEach((l) => state.generating.add(l.id));
  render();
  let ok = 0;
  let fail = 0;
  for (const l of todo) {
    try {
      l.thumb = await captureSite(l.url, force);
      l.thumbAuto = true;
      state.thumbFailed.delete(l.id);
      ok++;
    } catch {
      state.thumbFailed.add(l.id);
      fail++;
    }
    state.generating.delete(l.id);
    render();
  }
  const alive = todo.filter((l) => state.data.links.includes(l));   // ignora os removidos no meio do caminho
  if (ok && alive.length) persist(ok === 1 ? `Gera prévia de ${todo[0].name}` : `Gera ${ok} prévias`);
  if (fail) toast(`Não foi possível gerar ${fail} prévia(s). Use ⟳ no modo edição para tentar de novo.`, 'err');
}

/* ========= Cards ========= */
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

  const thumb = el('div', 'thumb');
  fillThumb(thumb, link, state.generating.has(link.id));

  const info = el('div', 'info');
  info.append(el('div', 'name', link.name));
  let host = link.url;
  try { host = new URL(link.url).host; } catch { /* mantém */ }
  info.append(el('div', link.desc ? 'desc' : 'host', link.desc || host));

  const tools = el('div', 'tools');
  tools.append(
    toolBtn('◀', 'Mover para trás', '', () => move(link.id, -1)),
    toolBtn('▶', 'Mover para frente', '', () => move(link.id, 1)),
    toolBtn('⟳', 'Gerar a prévia de novo', '', () => generateThumbs([link], true)),
    toolBtn('✎', 'Editar', '', () => openLinkDialog(link)),
    toolBtn('✕', 'Remover', 'del', () => removeLink(link)),
  );

  a.append(thumb, info, tools);
  a.addEventListener('click', (e) => {
    if (state.editing) { e.preventDefault(); openLinkDialog(link); }
  });
  return a;
}

function render() {
  if (!state.data) return;
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
let dlgThumb = '';        // imagem atual no diálogo
let dlgThumbAuto = true;  // true = gerada do site (refaz se o link mudar)
let dlgThumbUrl = '';     // link para o qual a imagem foi gerada
let dlgBusy = false;

function normalizeUrl(raw) {
  let v = (raw || '').trim();
  if (!v) return null;
  if (!/^[a-z][a-z0-9+.-]*:/i.test(v)) v = `https://${v}`;
  try {
    const u = new URL(v);
    return u.protocol === 'http:' || u.protocol === 'https:' ? u.href : null;
  } catch { return null; }
}

function updatePreview() {
  const box = $('#thumb-preview');
  fillThumb(box, { thumb: dlgThumb, name: lf.name.value, url: lf.url.value }, dlgBusy);
  if (!dlgThumb && !dlgBusy) box.append(el('span', 'thumb-busy', 'A imagem é gerada automaticamente ao salvar'));
  $('#thumb-gen').disabled = dlgBusy;
}

function openLinkDialog(link) {
  editingId = link ? link.id : null;
  lf.reset();
  dlgThumb = link && link.thumb ? link.thumb : '';
  dlgThumbAuto = link ? link.thumbAuto !== false : true;
  dlgThumbUrl = link ? link.url : '';
  dlgBusy = false;
  if (link) {
    lf.name.value = link.name;
    lf.url.value = link.url;
    lf.desc.value = link.desc || '';
  }
  $('#link-dialog-title').textContent = link ? 'Editar projeto' : 'Adicionar projeto';
  $('#link-delete').hidden = !link;
  updatePreview();
  linkDlg.showModal();
  lf.name.focus();
}

$('#btn-add').addEventListener('click', () => openLinkDialog(null));
lf.name.addEventListener('input', updatePreview);

$('#thumb-gen').addEventListener('click', async () => {
  const url = normalizeUrl(lf.url.value);
  if (!url) { toast('Preencha um link válido primeiro.', 'err'); lf.url.focus(); return; }
  dlgBusy = true;
  updatePreview();
  try {
    dlgThumb = await captureSite(url, true);
    dlgThumbAuto = true;
    dlgThumbUrl = url;
  } catch (e) {
    toast(`Falha: ${e.message}. O site pode estar fora do ar ou "dormindo".`, 'err');
  }
  dlgBusy = false;
  updatePreview();
});

$('#thumb-file').addEventListener('change', async (e) => {
  const file = e.target.files[0];
  e.target.value = '';
  if (!file) return;
  try {
    dlgThumb = await blobToThumb(file, false);
    dlgThumbAuto = false;
    updatePreview();
  } catch {
    toast('Não foi possível ler essa imagem.', 'err');
  }
});

$('#thumb-clear').addEventListener('click', () => {
  dlgThumb = '';
  dlgThumbAuto = true;
  updatePreview();
});

lf.addEventListener('submit', (e) => {
  e.preventDefault();
  if (dlgBusy) { toast('Aguarde a prévia terminar de gerar.'); return; }
  const url = normalizeUrl(lf.url.value);
  if (!url) { toast('Link inválido. Use um endereço http(s).', 'err'); lf.url.focus(); return; }
  const name = lf.name.value.trim();
  if (!name) { lf.name.focus(); return; }

  // imagem automática de outro link fica desatualizada: descarta para gerar de novo
  const stale = dlgThumbAuto && dlgThumb && dlgThumbUrl !== url;
  const item = {
    name,
    url,
    desc: lf.desc.value.trim(),
    thumb: stale ? '' : dlgThumb,
    thumbAuto: dlgThumbAuto,
  };

  let link;
  if (editingId) {
    link = state.data.links.find((x) => x.id === editingId);
    Object.assign(link, item);
    persist(`Edita ${name}`);
  } else {
    link = { id: crypto.randomUUID(), ...item };
    state.data.links.push(link);
    persist(`Adiciona ${name}`);
  }
  linkDlg.close();
  render();
  if (!link.thumb) generateThumbs([link]);
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
    if (readJSON(LS_REMEMBER)) rememberDevice();   // mantém este dispositivo lembrado com o PIN novo
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
  if (await tryRemembered()) { openHub(); return; }
  showLock();
}

init();
