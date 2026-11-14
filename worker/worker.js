/* =====================================================================
   PopZin — servidor de pagamentos (Cloudflare Worker)
   ---------------------------------------------------------------------
   Rotas:
     POST /pix            cria o pedido + cobrança Pix no Mercado Pago
     GET  /pedido/:id?t=  status do pedido para o cliente (link secreto)
     POST /webhook        aviso do Mercado Pago (pagamento aprovado)
     (cron)               a cada 5 min: expira pedidos não pagos

   Variáveis (Cloudflare → Worker → Settings → Variables and Secrets):
     MP_ACCESS_TOKEN   (secret) Access Token do Mercado Pago
     FIREBASE_SA       (secret) JSON inteiro da conta de serviço do Firebase
     FIREBASE_PROJECT  popzin
     ORIGENS           https://popzin.com.br,https://www.popzin.com.br,https://viniverk.github.io
   Opcionais: MP_API (padrão https://api.mercadopago.com), MINUTOS_PIX (padrão 5)
   ===================================================================== */

const UF_NORTE_NORDESTE = ["AC","AP","AM","PA","RO","RR","TO","AL","BA","CE","MA","PB","PE","PI","RN","SE"];

export default {
  async fetch(req, env, ctx) {
    const url = new URL(req.url);
    const cors = corsHeaders(req, env);
    if (req.method === "OPTIONS") return new Response(null, { status: 204, headers: cors });
    try {
      if (req.method === "POST" && url.pathname === "/pix") return json(await criarPix(req, env, url), 200, cors);
      const m = url.pathname.match(/^\/pedido\/([a-z0-9]{6,40})$/);
      if (req.method === "GET" && m) return json(await statusPedido(m[1], url.searchParams.get("t") || "", env), 200, cors);
      if (url.pathname === "/webhook") { ctx?.waitUntil ? ctx.waitUntil(webhook(req, url, env)) : await webhook(req, url, env); return new Response("ok"); }
      if (url.pathname === "/") return json({ ok: true, servico: "PopZin pagamentos" }, 200, cors);
      return json({ erro: "Rota não encontrada" }, 404, cors);
    } catch (e) {
      const status = e.status || 500;
      if (status >= 500) console.error(e.stack || e.message);
      return json({ erro: e.publico || "Não foi possível concluir agora. Tente de novo em instantes." }, status, cors);
    }
  },
  async scheduled(_evt, env, ctx) { ctx.waitUntil(expirarPendentes(env)); },
};

/* ---------------------------------------------------------------- util */
function json(obj, status = 200, headers = {}) {
  return new Response(JSON.stringify(obj), { status, headers: { "Content-Type": "application/json; charset=utf-8", ...headers } });
}
function corsHeaders(req, env) {
  const origem = req.headers.get("Origin") || "";
  const ok = (env.ORIGENS || "").split(",").map(s => s.trim()).filter(Boolean);
  return origem && ok.includes(origem)
    ? { "Access-Control-Allow-Origin": origem, "Access-Control-Allow-Methods": "GET,POST,OPTIONS", "Access-Control-Allow-Headers": "Content-Type", "Vary": "Origin" }
    : {};
}
function erroPublico(msg, status = 400) { const e = new Error(msg); e.publico = msg; e.status = status; return e; }
const r2 = v => Math.round(v * 100) / 100;
const so = (s, n) => String(s ?? "").trim().slice(0, n);
const digitos = s => String(s ?? "").replace(/\D/g, "");
function cpfValido(c) {
  c = digitos(c); if (c.length !== 11 || /^(\d)\1+$/.test(c)) return false;
  for (const t of [9, 10]) { let s = 0; for (let i = 0; i < t; i++) s += +c[i] * (t + 1 - i); if (((s * 10) % 11) % 10 !== +c[t]) return false; }
  return true;
}
const hex = n => [...crypto.getRandomValues(new Uint8Array(n))].map(b => b.toString(16).padStart(2, "0")).join("");
function isoBrasilia(d) {           // 2026-11-14T10:30:00.000-03:00 (formato aceito pelo Mercado Pago)
  const t = new Date(d.getTime() - 3 * 3600e3).toISOString().replace("Z", "");
  return `${t}-03:00`;
}

/* ------------------------------------------------- Firestore (admin) */
let tokenCache = { valor: "", ate: 0 };
function b64url(bytes) { let s = ""; bytes.forEach(b => s += String.fromCharCode(b)); return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, ""); }
async function googleToken(env) {
  if (tokenCache.valor && Date.now() < tokenCache.ate - 60e3) return tokenCache.valor;
  const sa = JSON.parse(env.FIREBASE_SA);
  const agora = Math.floor(Date.now() / 1000);
  const enc = o => b64url(new TextEncoder().encode(JSON.stringify(o)));
  const corpo = `${enc({ alg: "RS256", typ: "JWT" })}.${enc({ iss: sa.client_email, scope: "https://www.googleapis.com/auth/datastore", aud: sa.token_uri || "https://oauth2.googleapis.com/token", iat: agora, exp: agora + 3600 })}`;
  const pem = sa.private_key.replace(/-----[^-]+-----/g, "").replace(/\s+/g, "");
  const chave = await crypto.subtle.importKey("pkcs8", Uint8Array.from(atob(pem), c => c.charCodeAt(0)), { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" }, false, ["sign"]);
  const assinatura = new Uint8Array(await crypto.subtle.sign("RSASSA-PKCS1-v1_5", chave, new TextEncoder().encode(corpo)));
  const r = await fetch(sa.token_uri || "https://oauth2.googleapis.com/token", {
    method: "POST", headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: `grant_type=${encodeURIComponent("urn:ietf:params:oauth:grant-type:jwt-bearer")}&assertion=${corpo}.${b64url(assinatura)}`,
  });
  const j = await r.json();
  if (!r.ok) throw new Error("Google token: " + JSON.stringify(j));
  tokenCache = { valor: j.access_token, ate: Date.now() + (j.expires_in || 3600) * 1000 };
  return tokenCache.valor;
}
const fsBase = env => `https://firestore.googleapis.com/v1/projects/${env.FIREBASE_PROJECT}/databases/(default)/documents`;
async function fs(env, caminho, opts = {}) {
  const r = await fetch(`${fsBase(env)}${caminho}`, { ...opts, headers: { Authorization: `Bearer ${await googleToken(env)}`, "Content-Type": "application/json", ...(opts.headers || {}) } });
  if (r.status === 404 && (!opts.method || opts.method === "GET")) return null;
  const t = await r.text();
  if (!r.ok) { const e = new Error(`Firestore ${r.status}: ${t.slice(0, 300)}`); e.fsStatus = r.status; throw e; }
  return t ? JSON.parse(t) : {};
}
const lerJson = d => { try { return JSON.parse(d.fields.json.stringValue); } catch { return null; } };
async function listarProdutos(env) {
  let out = [], token = "";
  do {
    const j = await fs(env, `/produtos?pageSize=300${token ? `&pageToken=${encodeURIComponent(token)}` : ""}`);
    (j?.documents || []).forEach(d => { const o = lerJson(d); if (o) out.push({ ...o, _nome: d.name }); });
    token = j?.nextPageToken || "";
  } while (token);
  return out;
}
async function lerConfig(env) { const d = await fs(env, "/config/loja"); return (d && lerJson(d)) || {}; }
async function lerPedido(env, id) { const d = await fs(env, `/pedidos/${id}`); return d ? { doc: d, dados: lerJson(d) || {}, status: d.fields.status?.stringValue } : null; }
function camposPedido(dados, status, extra = {}) {
  return { criado: { timestampValue: dados.criado }, status: { stringValue: status }, json: { stringValue: JSON.stringify(dados) }, ...extra };
}
/* grava o pedido só se ninguém mexeu nele desde a leitura (evita contar duas vezes) */
async function gravarPedidoSe(env, ped, dados, status) {
  const campos = camposPedido(dados, status, ped.doc.fields.expira ? { expira: ped.doc.fields.expira } : {});
  for (const k of ["mpId", "token"]) if (ped.doc.fields[k]) campos[k] = ped.doc.fields[k];
  const id = ped.doc.name.split("/").pop();
  try {
    await fs(env, `/pedidos/${id}?currentDocument.updateTime=${encodeURIComponent(ped.doc.updateTime)}`, { method: "PATCH", body: JSON.stringify({ fields: campos }) });
    return true;
  } catch (e) { if (e.fsStatus === 400 || e.fsStatus === 409 || e.fsStatus === 412) return false; throw e; }
}

/* ------------------------------------------------------ preço e frete */
function regiaoPorUF(fretes, uf) {
  const chaves = Object.keys(fretes || {});
  const nne = UF_NORTE_NORDESTE.includes(String(uf).toUpperCase());
  return chaves.find(k => nne ? /norte|nordeste/i.test(k) : /sul|sudeste|centro/i.test(k)) || chaves[0];
}
function calcular(itensPedidos, produtos, cfg, uf) {
  if (!Array.isArray(itensPedidos) || !itensPedidos.length) throw erroPublico("Carrinho vazio.");
  const precoChav = +(cfg.precoChaveiro ?? 1) || 0;
  const porProduto = {};
  for (const it of itensPedidos) porProduto[+it.id] = (porProduto[+it.id] || 0) + Math.max(0, Math.floor(+it.q || 0));
  const itens = [];
  for (const it of itensPedidos) {
    const q = Math.floor(+it.q || 0);
    if (q < 1 || q > 50) throw erroPublico("Quantidade inválida.");
    const p = produtos.find(x => +x.id === +it.id);
    if (!p) throw erroPublico("Um produto do carrinho não existe mais. Atualize a página.");
    const total = porProduto[+p.id];
    if (total > (+p.estoque || 0)) throw erroPublico(`Estoque insuficiente de ${p.nome} (disponível: ${+p.estoque || 0}).`);
    const combo = +p.promoQtd >= 2 && +p.promoPreco > 0 && +p.promoPreco < +p.preco && total >= +p.promoQtd;
    const chav = !!it.chaveiro && precoChav > 0 && !p.semChaveiro;
    const un = r2((combo ? +p.promoPreco : +p.preco) + (chav ? precoChav : 0));
    itens.push({ id: +p.id, nome: p.nome, q, chaveiro: chav, combo, un });
  }
  const sub = r2(itens.reduce((s, i) => s + i.un * i.q, 0));
  const regiao = regiaoPorUF(cfg.fretes, uf);
  const freteGratis = sub >= (+cfg.freteGratisAcima || Infinity);
  const frete = freteGratis ? 0 : r2(+(cfg.fretes || {})[regiao] || 0);
  const desconto = +cfg.descontoPix || 0;
  const total = r2(sub + frete);
  const totalPix = r2(sub * (1 - desconto) + frete);
  if (totalPix <= 0 || totalPix > 5000) throw erroPublico("Valor do pedido inválido.");
  return { itens, qtd: itens.reduce((s, i) => s + i.q, 0), sub, frete, freteGratis, regiao, total, totalPix, descontoPix: desconto };
}

/* ------------------------------------------------------- Mercado Pago */
async function mp(env, caminho, opts = {}) {
  const r = await fetch(`${env.MP_API || "https://api.mercadopago.com"}${caminho}`, {
    ...opts, headers: { Authorization: `Bearer ${env.MP_ACCESS_TOKEN}`, "Content-Type": "application/json", ...(opts.headers || {}) },
  });
  const j = await r.json().catch(() => ({}));
  if (!r.ok) { const e = new Error(`Mercado Pago ${r.status}: ${JSON.stringify(j).slice(0, 300)}`); e.mpStatus = r.status; e.mp = j; throw e; }
  return j;
}

/* ------------------------------------------------------------ rotas */
async function criarPix(req, env, url) {
  const b = await req.json().catch(() => null);
  if (!b) throw erroPublico("Dados inválidos.");
  const c = b.cliente || {};
  const cliente = {
    nome: so(c.nome, 80), email: so(c.email, 120).toLowerCase(), cpf: digitos(c.cpf), telefone: digitos(c.telefone).slice(0, 13),
    cep: digitos(c.cep).slice(0, 8), rua: so(c.rua, 120), numero: so(c.numero, 15), complemento: so(c.complemento, 60),
    bairro: so(c.bairro, 60), cidade: so(c.cidade, 60), uf: so(c.uf, 2).toUpperCase(),
  };
  if (cliente.nome.split(/\s+/).length < 2) throw erroPublico("Informe nome e sobrenome.");
  if (!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(cliente.email)) throw erroPublico("E-mail inválido.");
  if (!cpfValido(cliente.cpf)) throw erroPublico("CPF inválido.");
  if (cliente.telefone.length < 10) throw erroPublico("Telefone inválido.");
  if (cliente.cep.length !== 8 || !cliente.rua || !cliente.numero || !cliente.cidade || cliente.uf.length !== 2) throw erroPublico("Endereço incompleto.");

  const [produtos, cfg] = await Promise.all([listarProdutos(env), lerConfig(env)]);
  const calc = calcular(b.itens, produtos, cfg, cliente.uf);

  const id = "pz" + Date.now().toString(36) + hex(2);
  const token = hex(12);
  const agora = new Date(), minutos = +env.MINUTOS_PIX || 5;
  const expira = new Date(agora.getTime() + minutos * 60e3);
  const [nome1, ...resto] = cliente.nome.split(/\s+/);

  const pg = await mp(env, "/v1/payments", {
    method: "POST", headers: { "X-Idempotency-Key": id },
    body: JSON.stringify({
      transaction_amount: calc.totalPix, payment_method_id: "pix",
      description: `PopZin — pedido ${id.toUpperCase()}`, external_reference: id,
      notification_url: `${url.origin}/webhook`,
      date_of_expiration: isoBrasilia(new Date(agora.getTime() + 31 * 60e3)),   // mínimo do MP é 30 min; a loja cancela aos 5
      payer: { email: cliente.email, first_name: nome1, last_name: resto.join(" "), identification: { type: "CPF", number: cliente.cpf } },
    }),
  });
  const td = pg.point_of_interaction?.transaction_data || {};
  const dados = { id, origem: "site", criado: agora.toISOString(), expiraEm: expira.toISOString(), pagamento: "pix", mpId: String(pg.id),
                  cliente, obs: so(b.obs, 300), ...calc, total: calc.totalPix, totalSemPix: calc.total,
                  qr: td.qr_code || "", qrImg: td.qr_code_base64 || "", ticket: td.ticket_url || "", historico: [{ status: "aguardando", em: agora.toISOString() }] };
  await fs(env, `/pedidos?documentId=${id}`, { method: "POST", body: JSON.stringify({ fields: camposPedido(dados, "aguardando", {
    expira: { timestampValue: expira.toISOString() }, mpId: { stringValue: String(pg.id) }, token: { stringValue: token } }) }) });

  return { id, token, total: calc.totalPix, itens: calc.itens, frete: calc.frete, regiao: calc.regiao, expiraEm: dados.expiraEm,
           qr: dados.qr, qrImg: dados.qrImg, ticket: dados.ticket };
}

async function statusPedido(id, t, env) {
  let ped = await lerPedido(env, id);
  if (!ped || !t || ped.doc.fields.token?.stringValue !== t) throw erroPublico("Pedido não encontrado.", 404);
  if (ped.status === "aguardando") { await sincronizar(env, ped); ped = await lerPedido(env, id); }
  const d = ped.dados;
  return {
    id, status: ped.status, criado: d.criado, expiraEm: d.expiraEm, total: d.total, frete: d.frete, regiao: d.regiao,
    itens: (d.itens || []).map(i => ({ nome: i.nome, q: i.q, chaveiro: i.chaveiro, un: i.un })),
    rastreio: d.rastreio || "", historico: d.historico || [], primeiroNome: (d.cliente?.nome || "").split(" ")[0],
    ...(ped.status === "aguardando" ? { qr: d.qr, qrImg: d.qrImg } : {}),
  };
}

async function webhook(req, url, env) {
  let id = url.searchParams.get("data.id") || url.searchParams.get("id");
  let tipo = url.searchParams.get("type") || url.searchParams.get("topic");
  if (req.method === "POST") {
    const b = await req.json().catch(() => ({}));
    id = b?.data?.id || id; tipo = b?.type || tipo;
  }
  if (!id || (tipo && tipo !== "payment")) return;
  const pg = await mp(env, `/v1/payments/${encodeURIComponent(id)}`);    // consulta direto no MP: aviso falso não aprova nada
  const ref = pg.external_reference;
  if (!ref || !/^pz[a-z0-9]+$/.test(ref)) return;
  const ped = await lerPedido(env, ref);
  if (ped) await aplicarPagamento(env, ped, pg);
}

/* --------------------------------------- confirmação e expiração */
async function sincronizar(env, ped) {
  const mpId = ped.doc.fields.mpId?.stringValue || ped.dados.mpId;
  if (!mpId) return;
  const pg = await mp(env, `/v1/payments/${mpId}`);
  if (pg.status === "approved") return aplicarPagamento(env, ped, pg);
  if (Date.now() > Date.parse(ped.dados.expiraEm)) {
    try { await mp(env, `/v1/payments/${mpId}`, { method: "PUT", body: JSON.stringify({ status: "cancelled" }) }); }
    catch (e) { const de = await mp(env, `/v1/payments/${mpId}`); if (de.status === "approved") return aplicarPagamento(env, ped, de); }
    const dados = { ...ped.dados, historico: [...(ped.dados.historico || []), { status: "expirado", em: new Date().toISOString() }], qr: "", qrImg: "" };
    await gravarPedidoSe(env, ped, dados, "expirado");
  }
}

async function aplicarPagamento(env, ped, pg) {
  if (pg.status !== "approved") return;
  if (!["aguardando", "expirado"].includes(ped.status)) return;              // já processado
  if (Math.abs(+pg.transaction_amount - +ped.dados.total) > 0.01) { console.error("valor divergente", ped.dados.id); return; }
  const agora = new Date().toISOString();
  const dados = { ...ped.dados, pagoEm: pg.date_approved || agora, qr: "", qrImg: "",
                  historico: [...(ped.dados.historico || []), { status: "pago", em: agora }] };
  if (!(await gravarPedidoSe(env, ped, dados, "pago"))) return;              // outro processo chegou antes
  // baixa de estoque e soma de vendidos
  const produtos = await listarProdutos(env);
  const soma = {};
  for (const it of ped.dados.itens || []) soma[it.id] = (soma[it.id] || 0) + it.q;
  for (const [pid, q] of Object.entries(soma)) {
    const p = produtos.find(x => +x.id === +pid); if (!p) continue;
    const { _nome, ...limpo } = p;
    limpo.estoque = Math.max(0, (+p.estoque || 0) - q);
    limpo.vendidos = (+p.vendidos || 0) + q;
    await fs(env, `/produtos/${+pid}`, { method: "PATCH", body: JSON.stringify({ fields: { json: { stringValue: JSON.stringify(limpo) } } }) });
  }
}

async function expirarPendentes(env) {
  const r = await fs(env, ":runQuery", { method: "POST", body: JSON.stringify({ structuredQuery: {
    from: [{ collectionId: "pedidos" }], where: { fieldFilter: { field: { fieldPath: "status" }, op: "EQUAL", value: { stringValue: "aguardando" } } }, limit: 200 } }) });
  for (const x of r || []) {
    if (!x.document) continue;
    const ped = { doc: x.document, dados: lerJson(x.document) || {}, status: "aguardando" };
    try { await sincronizar(env, ped); } catch (e) { console.error("expirar", ped.dados.id, e.message); }
  }
}
