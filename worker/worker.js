/* =====================================================================
   PopZin — servidor de pagamentos (Cloudflare Worker)
   ---------------------------------------------------------------------
   Rotas:
     POST /pix            cria o pedido + cobrança Pix no Mercado Pago
     GET  /pedido/:id?t=  status do pedido para o cliente (link secreto)
     POST /webhook        aviso do Mercado Pago (pagamento aprovado)
     POST /notificar      painel avisa mudança de status → e-mail ao cliente
     (cron)               a cada 5 min: expira pedidos não pagos

   Variáveis (Cloudflare → Worker → Settings → Variables and Secrets):
     MP_ACCESS_TOKEN   (secret) Access Token do Mercado Pago
     FIREBASE_SA       (secret) JSON inteiro da conta de serviço do Firebase
     FIREBASE_PROJECT  popzin
     ORIGENS           https://popzin.com.br,https://www.popzin.com.br,https://viniverk.github.io
     RESEND_API_KEY    (secret) chave do Resend para enviar e-mails (sem ela, nada é enviado)
     SITE_URL          https://popzin.com.br   ·   EMAIL_DE  PopZin <pedidos@popzin.com.br>
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
      if (req.method === "POST" && url.pathname === "/notificar") return json(await notificar(req, env), 200, { ...cors, "Access-Control-Allow-Headers": "Content-Type, Authorization" });
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
    ? { "Access-Control-Allow-Origin": origem, "Access-Control-Allow-Methods": "GET,POST,OPTIONS", "Access-Control-Allow-Headers": "Content-Type, Authorization", "Vary": "Origin" }
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
  const chaveEmail = chaveEmailDe("pago", dados);
  dados.emails = { ...(dados.emails || {}), [chaveEmail]: agora };
  if (!(await gravarPedidoSe(env, ped, dados, "pago"))) return;              // outro processo chegou antes
  try { await enviarEmailStatus(env, dados, ped.doc.fields.token?.stringValue, "pago"); } catch (e) { console.error("email pago", dados.id, e.message); }
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


/* ---------------------------------------------------- e-mails (Resend) */
const chaveEmailDe = (status, d) => status === "enviado" && d.rastreio ? `enviado:${d.rastreio}` : status;
const escE = t => String(t ?? "").replace(/[&<>"']/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const brlE = v => "R$ " + (+v || 0).toFixed(2).replace(".", ",");
const TEXTOS = {
  pago:      ["✅ Pagamento confirmado", "Recebemos o seu pagamento! Agora é com a gente: vamos preparar seus bichinhos com carinho."],
  preparo:   ["🛠️ Seu pedido está em preparo", "Seus bichinhos já estão sendo impressos e embalados."],
  enviado:   ["📦 Seu pedido foi enviado", "Seu pedido saiu para entrega."],
  entregue:  ["🏠 Pedido entregue", "Seu pedido foi entregue. Esperamos que você ame seus bichinhos! 🐾"],
  cancelado: ["Pedido cancelado", "Seu pedido foi cancelado. Se tiver qualquer dúvida, é só responder este e-mail ou falar com a gente pelo WhatsApp."],
};
function htmlEmail(env, d, token, status) {
  const [titulo, texto] = TEXTOS[status];
  const site = (env.SITE_URL || "https://popzin.com.br").replace(/\/+$/, "");
  const link = `${site}/pedido.html?id=${encodeURIComponent(d.id)}&t=${encodeURIComponent(token)}`;
  const nome = escE((d.cliente?.nome || "").split(" ")[0]);
  const itens = (d.itens || []).map(i => `<tr><td style="padding:6px 0;border-bottom:1px solid #eee">${i.q}× ${escE(i.nome)}${i.chaveiro ? " 🔑" : ""}</td><td style="padding:6px 0;border-bottom:1px solid #eee;text-align:right">${brlE(i.un * i.q)}</td></tr>`).join("");
  const rastreio = status === "enviado" && d.rastreio
    ? `<div style="background:#e3f0ff;border-radius:10px;padding:12px;margin:16px 0">Código de rastreio: <b style="font-size:16px">${escE(d.rastreio)}</b><br><a href="https://rastreamento.correios.com.br/app/index.php?objetos=${encodeURIComponent(d.rastreio)}" style="color:#0784b0">Rastrear nos Correios</a></div>` : "";
  return { link, html: `<!DOCTYPE html><html><body style="margin:0;background:#f6f3ff;font-family:Arial,Helvetica,sans-serif;color:#1d1838">
<table role="presentation" width="100%" cellpadding="0" cellspacing="0"><tr><td align="center" style="padding:24px 12px">
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="max-width:560px;background:#ffffff;border-radius:16px;overflow:hidden">
<tr><td style="background:#0b1030;padding:18px 24px"><img src="${site}/img/marca/logo-texto.png" alt="PopZin" height="44" style="display:block;height:44px"></td></tr>
<tr><td style="padding:24px">
<h1 style="font-size:22px;margin:0 0 8px">${titulo}</h1>
<p style="margin:0 0 4px">${nome ? `Olá, ${nome}! ` : ""}${texto}</p>
<p style="margin:0 0 16px;color:#77729a;font-size:13px">Pedido <b>${escE(d.id.toUpperCase())}</b></p>
${rastreio}
<a href="${link}" style="display:inline-block;background:#7b2ff7;color:#ffffff;text-decoration:none;font-weight:bold;padding:12px 20px;border-radius:10px">Acompanhar meu pedido</a>
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="margin-top:20px;font-size:14px">${itens}
<tr><td style="padding:6px 0">Frete</td><td style="padding:6px 0;text-align:right">${d.frete ? brlE(d.frete) : "Grátis"}</td></tr>
<tr><td style="padding:6px 0"><b>Total</b></td><td style="padding:6px 0;text-align:right"><b>${brlE(d.total)}</b></td></tr></table>
<p style="color:#77729a;font-size:12px;margin-top:20px">Guarde este e-mail: pelo botão acima você acompanha o andamento a qualquer momento.</p>
</td></tr>
<tr><td style="background:#f6f3ff;padding:14px 24px;font-size:12px;color:#77729a;text-align:center">PopZin · Seu mundo em miniatura · <a href="${site}" style="color:#7b2ff7">popzin.com.br</a></td></tr>
</table></td></tr></table></body></html>` };
}
async function enviarEmailStatus(env, d, token, status) {
  if (!env.RESEND_API_KEY || !TEXTOS[status] || !d.cliente?.email || !token) return false;
  const { html, link } = htmlEmail(env, d, token, status);
  const r = await fetch("https://api.resend.com/emails", {
    method: "POST", headers: { Authorization: `Bearer ${env.RESEND_API_KEY}`, "Content-Type": "application/json", "Idempotency-Key": `${d.id}-${chaveEmailDe(status, d)}` },
    body: JSON.stringify({ from: env.EMAIL_DE || "PopZin <pedidos@popzin.com.br>", to: [d.cliente.email], subject: `${TEXTOS[status][0]} — pedido ${d.id.toUpperCase()}`,
      html, text: `${TEXTOS[status][0]}\n\n${TEXTOS[status][1]}\n\nAcompanhe seu pedido: ${link}${status === "enviado" && d.rastreio ? `\nRastreio: ${d.rastreio}` : ""}` }),
  });
  if (!r.ok) throw new Error(`Resend ${r.status}: ${(await r.text()).slice(0, 200)}`);
  return true;
}

/* o painel chama depois de mudar o status / salvar o rastreio.
   Quem chama prova que é o administrador lendo o pedido no Firestore com o próprio login
   (as regras só deixam o administrador ler pedidos). */
async function notificar(req, env) {
  const tokenAdmin = (req.headers.get("Authorization") || "").replace(/^Bearer\s+/i, "");
  const { id } = await req.json().catch(() => ({}));
  if (!tokenAdmin || !/^pz[a-z0-9]+$/.test(id || "")) throw erroPublico("Requisição inválida.");
  const prova = await fetch(`${fsBase(env)}/pedidos/${id}`, { headers: { Authorization: `Bearer ${tokenAdmin}` } });
  if (!prova.ok) throw erroPublico("Sem permissão.", 403);
  for (let tentativa = 0; tentativa < 2; tentativa++) {
    const ped = await lerPedido(env, id);
    if (!ped) throw erroPublico("Pedido não encontrado.", 404);
    const d = ped.dados, status = ped.status, chave = chaveEmailDe(status, d);
    if (!TEXTOS[status] || !d.cliente?.email) return { enviado: false, motivo: "sem e-mail para este status" };
    if ((d.emails || {})[chave]) return { enviado: false, motivo: "já enviado" };
    if (!env.RESEND_API_KEY) return { enviado: false, motivo: "e-mail não configurado" };
    const novo = { ...d, emails: { ...(d.emails || {}), [chave]: new Date().toISOString() } };
    if (!(await gravarPedidoSe(env, ped, novo, status))) continue;            // mudou no meio: tenta de novo
    await enviarEmailStatus(env, novo, ped.doc.fields.token?.stringValue, status);
    return { enviado: true, para: d.cliente.email.replace(/^(.).*(@.*)$/, "$1***$2") };
  }
  return { enviado: false, motivo: "tente de novo" };
}
