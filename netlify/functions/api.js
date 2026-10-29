// Vehicle Inspection – Netlify function
// Sve tajne vrednosti dolaze iz Netlify environment variables (vidi README.md).

const crypto = require('crypto');

// ─── CONFIG ───────────────────────────────────────────────
function env(name, fallback) {
  const v = process.env[name];
  if (v === undefined || v === '') {
    if (fallback !== undefined) return fallback;
    throw new Error(`Server nije podešen: nedostaje ${name}`);
  }
  return v;
}

const cfg = {
  // Supabase – baza za vozače i izveštaje
  sbUrl: () => env('SUPABASE_URL').replace(/\/+$/, ''),
  sbKey: () => env('SUPABASE_SECRET_KEY'),
  // Cloudflare R2 – ovde se čuvaju nove slike
  r2Account: () => env('R2_ACCOUNT_ID'),
  r2KeyId: () => env('R2_ACCESS_KEY_ID'),
  r2Secret: () => env('R2_SECRET_ACCESS_KEY'),
  r2Bucket: () => env('R2_BUCKET'),
  r2PublicUrl: () => env('R2_PUBLIC_URL').replace(/\/+$/, ''),
  adminPassword: () => env('ADMIN_PASSWORD'),
  superAdminPassword: () => process.env.SUPER_ADMIN_PASSWORD || '',
  sessionSecret: () => env('SESSION_SECRET'),
  timeZone: () => env('APP_TIMEZONE', 'America/Chicago'),
};

const DRIVER_TOKEN_TTL = 30 * 60;       // 30 min za popunjavanje i slanje izveštaja
const ADMIN_TOKEN_TTL = 12 * 60 * 60;   // 12 h admin sesija
const MAX_PHOTOS_PER_GROUP = 60;
const MAX_IMAGE_BASE64 = 5_500_000;     // ~4 MB slika (Netlify limit za zahtev je 6 MB)

class HttpError extends Error {
  constructor(status, message) { super(message); this.status = status; }
}

// ─── HELPERS ──────────────────────────────────────────────
function base64url(input) {
  return Buffer.from(input).toString('base64')
    .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function hmac(data) {
  return base64url(crypto.createHmac('sha256', cfg.sessionSecret()).update(data).digest());
}

function safeEqual(a, b) {
  const ha = crypto.createHash('sha256').update(String(a)).digest();
  const hb = crypto.createHash('sha256').update(String(b)).digest();
  return crypto.timingSafeEqual(ha, hb);
}

function signToken(payload, ttl) {
  const body = base64url(JSON.stringify({ ...payload, exp: Math.floor(Date.now() / 1000) + ttl }));
  return `${body}.${hmac(body)}`;
}

function readToken(token, type) {
  if (typeof token !== 'string' || !token.includes('.')) throw new HttpError(401, 'Niste prijavljeni.');
  const [body, mac] = token.split('.');
  if (!safeEqual(mac, hmac(body))) throw new HttpError(401, 'Nevažeća sesija.');
  let payload;
  try {
    payload = JSON.parse(Buffer.from(body.replace(/-/g, '+').replace(/_/g, '/'), 'base64').toString());
  } catch { throw new HttpError(401, 'Nevažeća sesija.'); }
  if (payload.type !== type) throw new HttpError(401, 'Nevažeća sesija.');
  if (payload.exp < Math.floor(Date.now() / 1000)) throw new HttpError(401, 'Sesija je istekla. Pokušajte ponovo.');
  return payload;
}

function str(v, field, max, { required = true } = {}) {
  if (v === undefined || v === null) v = '';
  if (typeof v !== 'string') throw new HttpError(400, `Neispravno polje: ${field}`);
  v = v.trim();
  if (required && !v) throw new HttpError(400, `Obavezno polje: ${field}`);
  if (v.length > max) throw new HttpError(400, `Predugačko polje: ${field}`);
  return v;
}

// Ignoriše velika/mala slova i dijakritike (Đorđević = djordjevic)
function normalizeName(s) {
  return String(s).toLowerCase().replace(/đ/g, 'dj')
    .normalize('NFD').replace(/[\u0300-\u036f]/g, '')
    .split(/\s+/).filter(Boolean);
}

// Današnji datum u zoni aplikacije, oblik 2026-10-08
const todayISO = () => new Date().toLocaleDateString('en-CA', { timeZone: cfg.timeZone() });

function requireAdmin(token, { superOnly = false } = {}) {
  const p = readToken(token, 'admin');
  if (superOnly && p.role !== 'super') throw new HttpError(403, 'Samo super admin može ovo.');
  return p;
}

// ─── SUPABASE (REST) ──────────────────────────────────────
// Server koristi secret (ili stari service_role) ključ – zaobilazi RLS, pa tabele
// ostaju potpuno zaključane za sve ostale (vidi supabase/schema.sql).
async function db(path, { method = 'GET', body, prefer } = {}) {
  const key = cfg.sbKey();
  const headers = { apikey: key, Accept: 'application/json' };
  if (key.startsWith('eyJ')) headers.Authorization = 'Bearer ' + key;   // stari service_role JWT
  if (body !== undefined) headers['Content-Type'] = 'application/json';
  if (prefer) headers.Prefer = prefer;
  const res = await fetch(`${cfg.sbUrl()}/rest/v1/${path}`, {
    method, headers, body: body !== undefined ? JSON.stringify(body) : undefined,
  });
  const text = await res.text();
  let data = null;
  try { data = text ? JSON.parse(text) : null; } catch { data = text; }
  if (!res.ok) throw new Error('Supabase: ' + ((data && (data.message || data.msg || data.error)) || `HTTP ${res.status}`));
  return data;
}

const q = encodeURIComponent;

function cleanDriverInput(data, { partial = false } = {}) {
  const out = {};
  if (!partial || data.full_name !== undefined) {
    const name = str(data.full_name, 'Full Name', 100).replace(/\s+/g, ' ');
    if (name.length < 2) throw new HttpError(400, 'Ime je prekratko.');
    out.full_name = name;
  }
  if (!partial || data.driver_id !== undefined) {
    const id = str(data.driver_id, 'Driver ID', 4);
    if (!/^\d{4}$/.test(id)) throw new HttpError(400, 'Driver ID mora imati tačno 4 cifre.');
    out.driver_id = id;
  }
  if (data.active !== undefined) {
    if (typeof data.active !== 'boolean') throw new HttpError(400, 'Neispravno polje: active');
    out.active = data.active;
  }
  return out;
}

function driverIdParam(data) {
  const id = Number(data.id);
  if (!Number.isSafeInteger(id) || id < 1) throw new HttpError(400, 'Neispravan vozač.');
  return id;
}

// ─── CLOUDFLARE R2 ────────────────────────────────────────
const sha256hex = data => crypto.createHash('sha256').update(data).digest('hex');
const hmacRaw = (key, data) => crypto.createHmac('sha256', key).update(data).digest();

// Potpisan PUT zahtev ka R2 (S3-kompatibilan API, region "auto")
function signR2Put({ host, path, body, contentType, keyId, secret, now = new Date() }) {
  const amzDate = now.toISOString().replace(/[-:]/g, '').replace(/\.\d{3}/, '');   // 20261008T144500Z
  const dateStamp = amzDate.slice(0, 8);
  const payloadHash = sha256hex(body);
  const headers = { 'content-type': contentType, host, 'x-amz-content-sha256': payloadHash, 'x-amz-date': amzDate };
  const signedHeaders = Object.keys(headers).sort().join(';');
  const canonicalHeaders = Object.keys(headers).sort().map(k => `${k}:${headers[k]}\n`).join('');
  const canonicalRequest = ['PUT', path, '', canonicalHeaders, signedHeaders, payloadHash].join('\n');
  const scope = `${dateStamp}/auto/s3/aws4_request`;
  const stringToSign = ['AWS4-HMAC-SHA256', amzDate, scope, sha256hex(canonicalRequest)].join('\n');
  let k = hmacRaw('AWS4' + secret, dateStamp);
  for (const part of ['auto', 's3', 'aws4_request']) k = hmacRaw(k, part);
  const signature = crypto.createHmac('sha256', k).update(stringToSign).digest('hex');
  return {
    'Content-Type': contentType,
    'x-amz-content-sha256': payloadHash,
    'x-amz-date': amzDate,
    Authorization: `AWS4-HMAC-SHA256 Credential=${keyId}/${scope}, SignedHeaders=${signedHeaders}, Signature=${signature}`,
  };
}

async function uploadToR2(base64, mimeType, key) {
  const body = Buffer.from(base64, 'base64');
  const host = `${cfg.r2Account()}.r2.cloudflarestorage.com`;
  const path = `/${encodeURIComponent(cfg.r2Bucket())}/${key.split('/').map(encodeURIComponent).join('/')}`;
  const headers = signR2Put({ host, path, body, contentType: mimeType, keyId: cfg.r2KeyId(), secret: cfg.r2Secret() });
  const res = await fetch(`https://${host}${path}`, { method: 'PUT', headers, body });
  if (!res.ok) {
    const text = await res.text().catch(() => '');
    const msg = (text.match(/<Message>([^<]*)<\/Message>/) || [])[1] || `HTTP ${res.status}`;
    throw new Error('R2: ' + msg);
  }
  return `${cfg.r2PublicUrl()}/${key}`;
}

// Prihvataju se samo slike koje je ovaj server postavio na R2
function isOurImageUrl(url) {
  return typeof url === 'string' && url.length < 500 && url.startsWith(cfg.r2PublicUrl() + '/');
}

// ─── ACTIONS ──────────────────────────────────────────────
const actions = {
  // Vozač: provera imena i ID-a; vraća kratkotrajni token za slanje izveštaja
  async verify_driver(data) {
    const name = str(data.name, 'Full Name', 100);
    const driverid = str(data.driverid, 'Driver ID', 4);
    if (!/^\d{4}$/.test(driverid)) throw new HttpError(400, 'Driver ID mora imati tačno 4 cifre.');

    // Dovoljno je da se poklopi ime ILI prezime + tačan ID (samo aktivni vozači).
    // U izveštaj se upisuje puno ime iz baze.
    const nameWords = normalizeName(name);
    const rows = await db(`drivers?select=full_name,driver_id&driver_id=eq.${q(driverid)}&active=is.true`);
    const match = (rows || []).find(r => nameWords.some(w => normalizeName(r.full_name).includes(w)));
    if (!match) {
      await new Promise(r => setTimeout(r, 800)); // usporava pogađanje ID-a
      return { valid: false };
    }

    const officialName = match.full_name.trim();
    return { valid: true, officialName, token: signToken({ type: 'driver', name: officialName, driverid }, DRIVER_TOKEN_TTL) };
  },

  async upload_image(data, token) {
    readToken(token, 'driver');
    const kind = data.kind === 'trailer' ? 'trailer' : 'truck';
    const mimeType = str(data.mimeType, 'mimeType', 20);
    if (!['image/jpeg', 'image/png', 'image/webp'].includes(mimeType)) throw new HttpError(400, 'Nepodržan format slike.');
    if (typeof data.base64 !== 'string' || !data.base64 || data.base64.length > MAX_IMAGE_BASE64 ||
        !/^[A-Za-z0-9+/=]+$/.test(data.base64)) throw new HttpError(400, 'Neispravna ili prevelika slika.');

    const clean = v => String(v || '').replace(/[^A-Za-z0-9-]/g, '-').replace(/-+/g, '-').slice(0, 40);
    const label = clean(data.label) || 'unit';
    const shot = clean(data.shot); // npr. "LR-Tires" – admin panel ga prikazuje ispod slike
    const rand = `${Date.now()}_${crypto.randomBytes(3).toString('hex')}`;
    const publicId = shot ? `${kind}__${shot}__${label}__${rand}` : `${kind}_${label}_${rand}`;

    // inspections/2026-10-08/T-1042/truck__LR-Tires__T-1042__....jpg
    const day = todayISO();
    const ext = { 'image/jpeg': 'jpg', 'image/png': 'png', 'image/webp': 'webp' }[mimeType];
    return { url: await uploadToR2(data.base64, mimeType, `inspections/${day}/${label}/${publicId}.${ext}`) };
  },

  async append_row(data, token) {
    const driver = readToken(token, 'driver');
    const truck = str(data.truck, 'Truck Number', 40);
    const trailer = str(data.trailer, 'Trailer Number', 40);
    const notes = str(data.notes, 'Notes', 2000, { required: false });

    const checkUrls = (urls, label) => {
      if (!Array.isArray(urls) || urls.length < 1 || urls.length > MAX_PHOTOS_PER_GROUP || !urls.every(isOurImageUrl)) {
        throw new HttpError(400, `Neispravne fotografije: ${label}`);
      }
      return urls;
    };

    await db('reports', {
      method: 'POST', prefer: 'return=minimal',
      body: {
        report_date: todayISO(),            // samo datum, bez vremena
        driver_name: driver.name,
        driver_id: driver.driverid,
        truck, trailer, notes,
        truck_photos: checkUrls(data.truckUrls, 'truck'),
        trailer_photos: checkUrls(data.trailerUrls, 'trailer'),
      },
    });
    return { ok: true };
  },

  // Admin prijava: super admin (izveštaji + vozači) ili admin (izveštaji + komentari)
  async admin_login(data) {
    const password = typeof data.password === 'string' ? data.password : '';
    const superPw = cfg.superAdminPassword();
    let role = null;
    if (password && superPw && safeEqual(password, superPw)) role = 'super';
    else if (password && safeEqual(password, cfg.adminPassword())) role = 'admin';
    if (!role) {
      await new Promise(r => setTimeout(r, 800)); // usporava pogađanje lozinke
      throw new HttpError(401, 'Pogrešna lozinka.');
    }
    return { token: signToken({ type: 'admin', role }, ADMIN_TOKEN_TTL), role };
  },

  async get_reports(data, token) {
    const { role } = requireAdmin(token);
    const cols = 'id,report_date,driver_name,driver_id,truck,trailer,truck_photos,trailer_photos,notes,admin_comment';
    const reports = [];
    for (let offset = 0; ; offset += 1000) {           // Supabase vraća najviše 1000 redova odjednom
      const page = await db(`reports?select=${cols}&order=report_date.desc,id.desc&limit=1000&offset=${offset}`);
      reports.push(...page);
      if (page.length < 1000) break;
    }
    return { reports, today: todayISO(), role };
  },

  async update_comment(data, token) {
    requireAdmin(token);
    const id = Number(data.id);
    if (!Number.isSafeInteger(id) || id < 1) throw new HttpError(400, 'Neispravan izveštaj.');
    const comment = str(data.comment, 'Comment', 2000, { required: false });
    const rows = await db(`reports?id=eq.${id}`, { method: 'PATCH', prefer: 'return=representation', body: { admin_comment: comment } });
    if (!rows || !rows.length) throw new HttpError(404, 'Izveštaj ne postoji.');
    return { ok: true };
  },

  // ── Vozači (samo super admin) ──
  async list_drivers(data, token) {
    requireAdmin(token, { superOnly: true });
    const drivers = await db('drivers?select=id,full_name,driver_id,active,created_at&order=full_name.asc');
    return { drivers };
  },

  async add_driver(data, token) {
    requireAdmin(token, { superOnly: true });
    const d = cleanDriverInput(data);
    const same = await db(`drivers?select=id,full_name&driver_id=eq.${q(d.driver_id)}`);
    const key = normalizeName(d.full_name).join(' ');
    if (same.some(r => normalizeName(r.full_name).join(' ') === key)) {
      throw new HttpError(409, 'Vozač sa tim imenom i ID-jem već postoji.');
    }
    const [row] = await db('drivers', { method: 'POST', prefer: 'return=representation', body: { ...d, active: d.active ?? true } });
    return { driver: row };
  },

  async update_driver(data, token) {
    requireAdmin(token, { superOnly: true });
    const id = driverIdParam(data);
    const d = cleanDriverInput(data, { partial: true });
    if (!Object.keys(d).length) throw new HttpError(400, 'Nema izmena.');
    const rows = await db(`drivers?id=eq.${id}`, { method: 'PATCH', prefer: 'return=representation', body: d });
    if (!rows.length) throw new HttpError(404, 'Vozač ne postoji.');
    return { driver: rows[0] };
  },

  async delete_driver(data, token) {
    requireAdmin(token, { superOnly: true });
    const id = driverIdParam(data);
    // stari izveštaji ostaju – u njima je upisano ime i ID vozača
    const rows = await db(`drivers?id=eq.${id}`, { method: 'DELETE', prefer: 'return=representation' });
    if (!rows.length) throw new HttpError(404, 'Vozač ne postoji.');
    return { ok: true };
  },
};

// ─── HANDLER ──────────────────────────────────────────────
exports._test = { signR2Put };

exports.handler = async (event) => {
  const headers = { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' };
  const reply = (statusCode, body) => ({ statusCode, headers, body: JSON.stringify(body) });

  if (event.httpMethod !== 'POST') return reply(405, { error: 'Method not allowed' });

  try {
    let parsed;
    try { parsed = JSON.parse(event.body || '{}'); } catch { throw new HttpError(400, 'Neispravan zahtev.'); }
    const { action, data = {}, token } = parsed;

    if (!Object.prototype.hasOwnProperty.call(actions, action)) throw new HttpError(400, 'Nepoznata akcija.');
    if (typeof data !== 'object' || data === null) throw new HttpError(400, 'Neispravan zahtev.');

    return reply(200, await actions[action](data, token));
  } catch (err) {
    const status = err instanceof HttpError ? err.status : 500;
    if (status === 500) console.error(err);
    return reply(status, { error: err.message || 'Greška na serveru.' });
  }
};
