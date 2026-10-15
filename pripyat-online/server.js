#!/usr/bin/env node
/*
 * Припять · Сталкер — лёгкий сигнальный сервер.
 *
 * Что делает:
 *   • хранит список открытых лобби (имя, хост, игроки, есть ли пароль);
 *   • проверяет пароль лобби (хранится только хэш scrypt);
 *   • пересылает между игроком и хостом SDP/ICE-сообщения WebRTC.
 *
 * Чего НЕ делает: никакой игровой логики. Позиции игроков, предметы, время и чат
 * ходят напрямую между браузерами по WebRTC DataChannel; игровой «сервер» — это
 * вкладка браузера создателя лобби.
 *
 * Зависимостей нет: HTTP + минимальная реализация WebSocket (RFC 6455) на встроенных модулях.
 *
 * Переменные окружения:
 *   PORT         порт (по умолчанию 8080)
 *   HOST         адрес прослушивания (по умолчанию 0.0.0.0)
 *   ICE_SERVERS  JSON-массив RTCIceServer, например
 *                [{"urls":"stun:stun.l.google.com:19302"},{"urls":"turn:my.host:3478","username":"u","credential":"p"}]
 *   MAX_LOBBIES  максимум лобби одновременно (по умолчанию 100)
 *   NO_STATIC=1  не отдавать игру (только сигналинг)
 */
'use strict';
const http = require('http');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const zlib = require('zlib');

const PORT = +process.env.PORT || 8080;
const HOST = process.env.HOST || '0.0.0.0';
const MAX_LOBBIES = +process.env.MAX_LOBBIES || 100;
const MAX_MSG = 64 * 1024;          // максимум одного сообщения
const MAX_PER_IP = 12;              // одновременных соединений с одного адреса
const PROTO = 1;                    // версия протокола (клиент сверяет)
let ICE = [
  { urls: 'stun:stun.l.google.com:19302' }, { urls: 'stun:stun1.l.google.com:19302' },
  // общедоступный бесплатный TURN (Open Relay) — запасной вариант, чтобы соединялись и устройства, которые не видят друг друга напрямую
  { urls: ['turn:openrelay.metered.ca:80', 'turn:openrelay.metered.ca:443', 'turn:openrelay.metered.ca:443?transport=tcp', 'turns:openrelay.metered.ca:443?transport=tcp'], username: 'openrelayproject', credential: 'openrelayproject' }
];
try { if (process.env.ICE_SERVERS) ICE = JSON.parse(process.env.ICE_SERVERS); } catch (e) { console.error('ICE_SERVERS: некорректный JSON, используется STUN по умолчанию'); }

/* ───────────────────────── статика (сама игра) ───────────────────────── */
const GAME = path.join(__dirname, 'public', 'index.html');
let gameRaw = null, gameGz = null;
function loadGame() {
  try {
    gameRaw = fs.readFileSync(GAME);
    gameGz = zlib.gzipSync(gameRaw, { level: 9 });
  } catch (e) { gameRaw = gameGz = null; }
}
if (!process.env.NO_STATIC) loadGame();

const server = http.createServer((req, res) => {
  const url = (req.url || '/').split('?')[0];
  if (url === '/healthz') { res.writeHead(200, { 'Content-Type': 'text/plain' }); return res.end('ok'); }
  if (url === '/' || url === '/index.html') {
    if (!gameRaw) { res.writeHead(404, { 'Content-Type': 'text/plain; charset=utf-8' }); return res.end('public/index.html не найден (или отключён NO_STATIC)'); }
    const gz = /\bgzip\b/.test(req.headers['accept-encoding'] || '');
    res.writeHead(200, {
      'Content-Type': 'text/html; charset=utf-8',
      'Cache-Control': 'no-cache',
      'X-Content-Type-Options': 'nosniff',
      ...(gz ? { 'Content-Encoding': 'gzip', 'Vary': 'Accept-Encoding' } : {})
    });
    return res.end(gz ? gameGz : gameRaw);
  }
  res.writeHead(404, { 'Content-Type': 'text/plain' }); res.end('not found');
});

/* ───────────────────── минимальный WebSocket-сервер ───────────────────── */
const WS_GUID = '258EAFA5-E914-47DA-95CA-C5AB0DC85B11';
const clients = new Map();            // pid -> Client
const perIp = new Map();

class Client {
  constructor(socket, ip) {
    this.socket = socket; this.ip = ip;
    this.pid = crypto.randomBytes(6).toString('hex');
    this.buf = Buffer.alloc(0);
    this.frag = []; this.fragLen = 0; this.fragOp = 0;
    this.alive = true; this.closed = false;
    this.sub = false;                 // подписан на обновления списка лобби
    this.lobby = null;                // id лобби, где он хост
    this.inLobby = null;              // id лобби, где он гость
    this.name = 'Сталкер';
    this.badPw = 0; this.lastPwFail = 0;
    this.rate = { t: Date.now(), n: 0 };
  }
  sendFrame(op, payload) {
    if (this.closed || this.socket.destroyed) return;
    const len = payload.length;
    let head;
    if (len < 126) { head = Buffer.alloc(2); head[1] = len; }
    else if (len < 65536) { head = Buffer.alloc(4); head[1] = 126; head.writeUInt16BE(len, 2); }
    else { head = Buffer.alloc(10); head[1] = 127; head.writeBigUInt64BE(BigInt(len), 2); }
    head[0] = 0x80 | op;
    this.socket.write(Buffer.concat([head, payload]));
  }
  send(obj) { this.sendFrame(0x1, Buffer.from(JSON.stringify(obj))); }
  close(code = 1000) {
    if (this.closed) return;
    const b = Buffer.alloc(2); b.writeUInt16BE(code);
    this.sendFrame(0x8, b);
    this.socket.end();
  }
  onData(chunk) {
    this.buf = this.buf.length ? Buffer.concat([this.buf, chunk]) : chunk;
    for (;;) {
      if (this.buf.length < 2) return;
      const b0 = this.buf[0], b1 = this.buf[1];
      const fin = !!(b0 & 0x80), op = b0 & 0x0f, masked = !!(b1 & 0x80);
      let len = b1 & 0x7f, off = 2;
      if (len === 126) { if (this.buf.length < 4) return; len = this.buf.readUInt16BE(2); off = 4; }
      else if (len === 127) {
        if (this.buf.length < 10) return;
        const big = this.buf.readBigUInt64BE(2);
        if (big > BigInt(MAX_MSG)) return this.close(1009);
        len = Number(big); off = 10;
      }
      if (!masked) return this.close(1002);           // клиент обязан маскировать
      if (len > MAX_MSG) return this.close(1009);
      if (this.buf.length < off + 4 + len) return;
      const mask = this.buf.subarray(off, off + 4);
      const data = Buffer.from(this.buf.subarray(off + 4, off + 4 + len));
      for (let i = 0; i < len; i++) data[i] ^= mask[i & 3];
      this.buf = this.buf.subarray(off + 4 + len);
      if (op >= 0x8) {                                 // управляющие кадры
        if (op === 0x8) { this.close(1000); return; }
        if (op === 0x9) this.sendFrame(0xA, data);
        else if (op === 0xA) this.alive = true;
        continue;
      }
      if (op !== 0x0) { this.fragOp = op; this.frag = []; this.fragLen = 0; }
      this.frag.push(data); this.fragLen += data.length;
      if (this.fragLen > MAX_MSG) return this.close(1009);
      if (fin) {
        const full = Buffer.concat(this.frag); this.frag = []; this.fragLen = 0;
        if (this.fragOp === 0x1) handle(this, full.toString('utf8'));
      }
    }
  }
}

server.on('upgrade', (req, socket) => {
  const key = req.headers['sec-websocket-key'];
  const ip = (req.socket.remoteAddress || '').replace('::ffff:', '');
  if (!key || (req.headers.upgrade || '').toLowerCase() !== 'websocket') { socket.destroy(); return; }
  if ((perIp.get(ip) || 0) >= MAX_PER_IP) { socket.write('HTTP/1.1 429 Too Many Requests\r\n\r\n'); socket.destroy(); return; }
  const accept = crypto.createHash('sha1').update(key + WS_GUID).digest('base64');
  socket.write('HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: ' + accept + '\r\n\r\n');
  socket.setNoDelay(true);
  perIp.set(ip, (perIp.get(ip) || 0) + 1);
  const c = new Client(socket, ip);
  clients.set(c.pid, c);
  socket.on('data', d => { try { c.onData(d); } catch (e) { c.close(1011); } });
  socket.on('error', () => { });
  socket.on('close', () => {
    c.closed = true;
    perIp.set(ip, Math.max(0, (perIp.get(ip) || 1) - 1));
    clients.delete(c.pid);
    dropClient(c);
  });
  c.send({ t: 'hello', pid: c.pid, proto: PROTO, iceServers: ICE });
});

/* ──────────────────────────── лобби ──────────────────────────── */
const lobbies = new Map();   // id -> {id,name,hostName,hostPid,max,members:Set,salt,hash,created}

const clean = (s, n) => String(s == null ? '' : s).replace(/[\u0000-\u001f\u007f<>]/g, '').trim().slice(0, n);
const pwHash = (pw, salt) => crypto.scryptSync(pw, salt, 32);

function publicList() {
  return [...lobbies.values()].map(l => ({
    id: l.id, name: l.name, host: l.hostName, players: 1 + l.members.size, max: l.max, locked: !!l.hash
  }));
}
function broadcastList() {
  const msg = { t: 'lobbies', list: publicList() };
  for (const c of clients.values()) if (c.sub) c.send(msg);
}
function dropClient(c) {
  if (c.lobby) {                                       // хост ушёл → лобби закрывается
    const l = lobbies.get(c.lobby);
    if (l) {
      lobbies.delete(l.id);
      for (const pid of l.members) { const g = clients.get(pid); if (g) { g.inLobby = null; g.send({ t: 'closed', reason: 'host-left' }); } }
    }
    c.lobby = null; broadcastList();
  }
  if (c.inLobby) {                                     // гость ушёл
    const l = lobbies.get(c.inLobby);
    if (l) {
      l.members.delete(c.pid);
      const h = clients.get(l.hostPid); if (h) h.send({ t: 'peer-left', pid: c.pid });
      broadcastList();
    }
    c.inLobby = null;
  }
}

function handle(c, text) {
  const now = Date.now();
  if (now - c.rate.t > 1000) { c.rate.t = now; c.rate.n = 0; }
  if (++c.rate.n > 80) return c.close(1008);           // не больше 80 сообщений/с
  let m; try { m = JSON.parse(text); } catch (e) { return; }
  if (!m || typeof m.t !== 'string') return;

  switch (m.t) {
    case 'list':
      c.sub = true; c.send({ t: 'lobbies', list: publicList() }); break;

    case 'create': {
      if (c.lobby || c.inLobby) return c.send({ t: 'error', code: 'busy', msg: 'Вы уже в лобби' });
      if (lobbies.size >= MAX_LOBBIES) return c.send({ t: 'error', code: 'full-server', msg: 'Сервер переполнен лобби' });
      const name = clean(m.name, 32) || 'Лобби';
      const max = Math.min(16, Math.max(2, parseInt(m.max, 10) || 8));
      const pw = typeof m.password === 'string' ? m.password.slice(0, 64) : '';
      c.name = clean(m.hostName, 16) || 'Сталкер';
      const l = { id: crypto.randomBytes(4).toString('hex'), name, hostName: c.name, hostPid: c.pid, max, members: new Set(), salt: null, hash: null, created: now };
      if (pw) { l.salt = crypto.randomBytes(16); l.hash = pwHash(pw, l.salt); }
      lobbies.set(l.id, l); c.lobby = l.id;
      c.send({ t: 'created', id: l.id, pid: c.pid, name: l.name, max: l.max, locked: !!l.hash });
      broadcastList();
      break;
    }

    case 'join': {
      if (c.lobby || c.inLobby) return c.send({ t: 'error', code: 'busy', msg: 'Вы уже в лобби' });
      const l = lobbies.get(String(m.id));
      if (!l) return c.send({ t: 'error', code: 'gone', msg: 'Лобби не найдено (возможно, уже закрыто)' });
      if (1 + l.members.size >= l.max) return c.send({ t: 'error', code: 'full', msg: 'Лобби заполнено' });
      if (l.hash) {
        if (now - c.lastPwFail < 1200) return c.send({ t: 'error', code: 'slow', msg: 'Слишком быстро. Подождите секунду' });
        if (c.badPw >= 8) return c.close(1008);
        const given = typeof m.password === 'string' ? m.password.slice(0, 64) : '';
        const ok = crypto.timingSafeEqual(pwHash(given, l.salt), l.hash);
        if (!ok) { c.badPw++; c.lastPwFail = now; return c.send({ t: 'error', code: 'password', msg: given ? 'Неверный пароль' : 'Нужен пароль' }); }
      }
      c.name = clean(m.name, 16) || 'Сталкер';
      const host = clients.get(l.hostPid);
      if (!host) return c.send({ t: 'error', code: 'gone', msg: 'Хост недоступен' });
      l.members.add(c.pid); c.inLobby = l.id;
      c.send({ t: 'joined', id: l.id, host: l.hostPid, pid: c.pid, name: l.name });
      host.send({ t: 'peer', pid: c.pid, name: c.name });
      broadcastList();
      break;
    }

    case 'signal': {                                    // SDP / ICE только между гостем и хостом его лобби
      const to = clients.get(String(m.to));
      if (!to || m.data == null) return;
      const lid = c.lobby || c.inLobby;
      const l = lid && lobbies.get(lid);
      if (!l) return;
      const ok = (c.pid === l.hostPid && l.members.has(to.pid)) || (to.pid === l.hostPid && l.members.has(c.pid));
      if (ok) to.send({ t: 'signal', from: c.pid, data: m.data });
      break;
    }

    case 'kick': {                                      // хост убирает гостя (не удалось соединиться / нарушение)
      const l = c.lobby && lobbies.get(c.lobby);
      const g = l && clients.get(String(m.pid));
      if (!l || !g || !l.members.has(g.pid)) return;
      l.members.delete(g.pid); g.inLobby = null;
      g.send({ t: 'closed', reason: m.reason === 'full' ? 'full' : 'kicked' });
      broadcastList();
      break;
    }

    case 'leave':
      dropClient(c); c.send({ t: 'left' }); break;

    case 'ping': c.send({ t: 'pong' }); break;
  }
}

// keep-alive: убираем «мёртвые» соединения (например, закрытый ноутбук)
setInterval(() => {
  for (const c of clients.values()) {
    if (!c.alive) { c.socket.destroy(); continue; }
    c.alive = false; c.sendFrame(0x9, Buffer.alloc(0));
  }
}, 25000).unref();

server.listen(PORT, HOST, () => {
  const os = require('os');
  const ips = [];
  for (const list of Object.values(os.networkInterfaces())) for (const i of list || []) if (i.family === 'IPv4' && !i.internal) ips.push(i.address);
  console.log('Припять · Сталкер — сигнальный сервер запущен');
  console.log('  Локально:        http://localhost:' + PORT);
  for (const ip of ips) console.log('  По сети (LAN):   http://' + ip + ':' + PORT);
  console.log('  Игра отдаётся:   ' + (gameRaw ? 'да (public/index.html)' : 'нет'));
  console.log('  ICE-серверы:     ' + ICE.map(s => [].concat(s.urls).join(',')).join(' | '));
});
