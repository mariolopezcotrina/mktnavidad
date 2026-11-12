// Cloudflare Worker + D1 — API de Navidad 2026
// Bindings requeridos: DB (D1) | Secretos: SESSION_SECRET, SETUP_KEY

const ORIGIN = 'https://mariolopezcotrina.github.io';
const CORS = {
  'Access-Control-Allow-Origin': ORIGIN,
  'Access-Control-Allow-Headers': 'Content-Type, Authorization, X-Setup-Key',
  'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS'
};
const ITER = 50000; // si ves error 1102 (CPU) bájalo a 10000

const enc = new TextEncoder();
const b64 = buf => btoa(String.fromCharCode(...new Uint8Array(buf)));
const unb64 = s => Uint8Array.from(atob(s), c => c.charCodeAt(0));

async function pbkdf2(pw, salt, iter) {
  const k = await crypto.subtle.importKey('raw', enc.encode(pw), 'PBKDF2', false, ['deriveBits']);
  return b64(await crypto.subtle.deriveBits({ name: 'PBKDF2', hash: 'SHA-256', salt, iterations: iter }, k, 256));
}
async function hashPw(pw) {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  return `${ITER}:${b64(salt)}:${await pbkdf2(pw, salt, ITER)}`;
}
async function checkPw(pw, stored) {
  const [iter, salt, hash] = stored.split(':');
  return (await pbkdf2(pw, unb64(salt), +iter)) === hash;
}

async function sign(env, payload) {
  const k = await crypto.subtle.importKey('raw', enc.encode(env.SESSION_SECRET), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  return b64(await crypto.subtle.sign('HMAC', k, enc.encode(payload)));
}
async function makeToken(env, username) {
  const p = btoa(unescape(encodeURIComponent(JSON.stringify({ u: username, exp: Date.now() + 7 * 864e5 }))));
  return p + '.' + await sign(env, p);
}
async function auth(req, env) {
  const [p, s] = (req.headers.get('Authorization') || '').replace('Bearer ', '').split('.');
  if (!p || !s || (await sign(env, p)) !== s) return null;
  const d = JSON.parse(decodeURIComponent(escape(atob(p))));
  if (d.exp < Date.now()) return null;
  return await env.DB.prepare('SELECT username,name,role FROM users WHERE username=?').bind(d.u).first();
}

const cleanGifts = g => [0, 1, 2].map(i => {
  const x = (g && g[i]) || {};
  return { detail: String(x.detail || '').slice(0, 200), imageUrl: String(x.imageUrl || '').slice(0, 400000), buyUrl: String(x.buyUrl || '').slice(0, 500) };
});
const giftStmts = (env, u, g) => cleanGifts(g).map((x, i) =>
  env.DB.prepare('INSERT OR REPLACE INTO gifts(username,position,detail,image_url,buy_url) VALUES(?,?,?,?,?)').bind(u, i, x.detail, x.imageUrl, x.buyUrl));
const bump = env => env.DB.prepare("UPDATE meta SET value=value+1 WHERE key='version'");
const version = async env => (await env.DB.prepare("SELECT value FROM meta WHERE key='version'").first()).value;

async function allData(env) {
  const us = (await env.DB.prepare('SELECT username,name,role,daily_gifts FROM users ORDER BY rowid').all()).results;
  const gs = (await env.DB.prepare('SELECT username,position,detail,image_url,buy_url FROM gifts').all()).results;
  return us.map(u => ({
    username: u.username, name: u.name, role: u.role, dailyGifts: u.daily_gifts || '',
    gifts: [0, 1, 2].map(i => {
      const g = gs.find(x => x.username === u.username && x.position === i);
      return { detail: g ? g.detail : '', imageUrl: g ? g.image_url : '', buyUrl: g ? g.buy_url : '' };
    })
  }));
}

export default {
  async fetch(req, env) {
    if (req.method === 'OPTIONS') return new Response(null, { headers: CORS });
    const out = (o, s = 200) => new Response(JSON.stringify(o), { status: s, headers: { ...CORS, 'Content-Type': 'application/json' } });
    const path = new URL(req.url).pathname.replace(/\/+$/, '');
    const m = req.method;
    const body = async () => { try { return await req.json(); } catch (e) { return {}; } };

    try {
      // ── Públicas ──
      if (m === 'POST' && path === '/login') {
        const b = await body();
        const u = await env.DB.prepare('SELECT * FROM users WHERE username=?').bind(String(b.username || '').trim().toLowerCase()).first();
        if (!u || !(await checkPw(String(b.password || ''), u.password_hash))) return out({ error: 'Usuario o contraseña incorrectos' }, 401);
        return out({ token: await makeToken(env, u.username), user: { username: u.username, name: u.name, role: u.role } });
      }

      // Importación inicial (una vez) desde data.json — protegida con SETUP_KEY
      if (m === 'POST' && path === '/import') {
        if (!env.SETUP_KEY || req.headers.get('X-Setup-Key') !== env.SETUP_KEY) return out({ error: 'No autorizado' }, 401);
        const b = await body();
        let n = 0;
        for (const u of (b.users || [])) {
          const ex = await env.DB.prepare('SELECT 1 FROM users WHERE username=?').bind(u.username).first();
          if (ex) continue;
          await env.DB.batch([
            env.DB.prepare('INSERT INTO users(username,name,role,password_hash,daily_gifts) VALUES(?,?,?,?,?)')
              .bind(u.username, u.name, u.role === 'admin' ? 'admin' : 'participant', await hashPw(u.password), String(u.dailyGifts || '')),
            ...giftStmts(env, u.username, u.gifts), bump(env)
          ]);
          n++;
        }
        return out({ ok: true, importados: n });
      }

      // ── Requieren sesión ──
      const me = await auth(req, env);
      if (!me) return out({ error: 'Sesión no válida' }, 401);

      if (m === 'GET' && path === '/version') return out({ v: await version(env) });
      if (m === 'GET' && path === '/data') return out({ v: await version(env), users: await allData(env) });

      if (m === 'PUT' && path === '/me') {
        const b = await body();
        await env.DB.batch([
          env.DB.prepare('UPDATE users SET daily_gifts=? WHERE username=?').bind(String(b.dailyGifts || '').slice(0, 300), me.username),
          ...giftStmts(env, me.username, b.gifts), bump(env)
        ]);
        return out({ ok: true });
      }

      if (m === 'POST' && path === '/me/password') {
        const b = await body();
        const row = await env.DB.prepare('SELECT password_hash FROM users WHERE username=?').bind(me.username).first();
        if (!(await checkPw(String(b.current || ''), row.password_hash))) return out({ error: 'La contraseña actual es incorrecta' }, 400);
        if (String(b.new || '').length < 6) return out({ error: 'Mínimo 6 caracteres' }, 400);
        await env.DB.batch([env.DB.prepare('UPDATE users SET password_hash=? WHERE username=?').bind(await hashPw(b.new), me.username), bump(env)]);
        return out({ ok: true });
      }

      // ── Solo administrador ──
      if (me.role !== 'admin') return out({ error: 'Solo el administrador puede hacer esto' }, 403);

      if (m === 'POST' && path === '/users') {
        const b = await body();
        const username = String(b.username || '').trim().toLowerCase();
        if (!username || !b.name || String(b.password || '').length < 1) return out({ error: 'Datos incompletos' }, 400);
        if (await env.DB.prepare('SELECT 1 FROM users WHERE username=?').bind(username).first()) return out({ error: 'Ese nombre de usuario ya existe' }, 409);
        await env.DB.batch([
          env.DB.prepare('INSERT INTO users(username,name,role,password_hash) VALUES(?,?,?,?)')
            .bind(username, String(b.name).slice(0, 100), b.role === 'admin' ? 'admin' : 'participant', await hashPw(String(b.password))),
          ...giftStmts(env, username, []), bump(env)
        ]);
        return out({ ok: true });
      }

      const mm = path.match(/^\/users\/([^/]+)(\/password)?$/);
      if (mm) {
        const target = decodeURIComponent(mm[1]);
        const row = await env.DB.prepare('SELECT role FROM users WHERE username=?').bind(target).first();
        if (!row) return out({ error: 'Usuario no encontrado' }, 404);

        if (m === 'POST' && mm[2]) {
          const b = await body();
          if (String(b.password || '').length < 6) return out({ error: 'Mínimo 6 caracteres' }, 400);
          await env.DB.batch([env.DB.prepare('UPDATE users SET password_hash=? WHERE username=?').bind(await hashPw(b.password), target), bump(env)]);
          return out({ ok: true });
        }

        if (m === 'PUT' && !mm[2]) {
          const b = await body();
          const nu = String(b.username || target).trim().toLowerCase();
          const role = b.role === 'admin' ? 'admin' : 'participant';
          if (target === me.username && role !== 'admin') return out({ error: 'No puedes quitarte el rol de administrador' }, 400);
          const st = [];
          if (nu !== target) st.push(env.DB.prepare('UPDATE users SET username=? WHERE username=?').bind(nu, target));
          st.push(env.DB.prepare('UPDATE users SET name=?, role=?, daily_gifts=? WHERE username=?')
            .bind(String(b.name || '').slice(0, 100), role, String(b.dailyGifts || '').slice(0, 300), nu));
          if (Array.isArray(b.gifts) && role === 'participant') st.push(...giftStmts(env, nu, b.gifts));
          st.push(bump(env));
          try { await env.DB.batch(st); }
          catch (e) { return out({ error: String(e.message).includes('UNIQUE') ? 'Ese nombre de usuario ya existe' : 'No se pudo guardar' }, 409); }
          return out({ ok: true });
        }

        if (m === 'DELETE' && !mm[2]) {
          if (row.role === 'admin') return out({ error: 'No se puede eliminar al administrador' }, 400);
          await env.DB.batch([
            env.DB.prepare('DELETE FROM gifts WHERE username=?').bind(target),
            env.DB.prepare('DELETE FROM users WHERE username=?').bind(target), bump(env)
          ]);
          return out({ ok: true });
        }
      }
      return out({ error: 'Ruta no encontrada' }, 404);
    } catch (e) {
      return out({ error: 'Error del servidor' }, 500);
    }
  }
};
