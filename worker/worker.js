/* =====================================================================
   PopZin — servidor de pagamentos (Cloudflare Worker)
   ---------------------------------------------------------------------
   Rotas:
     POST /pix            cria o pedido + cobrança Pix no Mercado Pago
     POST /cartao         paga com cartão (token do formulário seguro do Mercado Pago)
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
      if (req.method === "POST" && url.pathname === "/pix") { await limitar(env.LIMITE_PIX, req, "Muitas tentativas. Aguarde um minuto e tente de novo.");
        return json(await criarPix(req, env, url), 200, cors); }
      if (req.method === "POST" && url.pathname === "/cartao") { await limitar(env.LIMITE_CARTAO, req, "Muitas tentativas com cartão. Aguarde um minuto ou pague com Pix.");
        return json(await pagarCartao(req, env, url), 200, cors); }
      const m = url.pathname.match(/^\/pedido\/([a-z0-9]{6,40})$/);
      if (req.method === "GET" && m) return json(await statusPedido(m[1], url.searchParams.get("t") || "", env), 200, cors);
      if (req.method === "POST" && url.pathname === "/notificar") return json(await notificar(req, env), 200, { ...cors, "Access-Control-Allow-Headers": "Content-Type, Authorization" });
      if (url.pathname === "/webhook") {
        if (!(await assinaturaValida(req, url, env))) return new Response("assinatura inválida", { status: 401 });
        ctx?.waitUntil ? ctx.waitUntil(webhook(req, url, env)) : await webhook(req, url, env); return new Response("ok"); }
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
/* ---------------------------------------------------- proteção contra robôs */
const ipDe = req => req.headers.get("CF-Connecting-IP") || req.headers.get("X-Forwarded-For")?.split(",")[0].trim() || "sem-ip";
// limite de tentativas por IP (Rate Limiting do Cloudflare, configurado no wrangler.toml)
async function limitar(limitador, req, msg) {
  if (!limitador) return;
  const { success } = await limitador.limit({ key: ipDe(req) }).catch(() => ({ success: true }));
  if (!success) throw erroPublico(msg, 429);
}
// "não sou robô" (Cloudflare Turnstile) — só exige depois que TURNSTILE_SECRET for cadastrado
async function conferirHumano(env, req, tokenTs) {
  if (!env.TURNSTILE_SECRET) return;
  if (!tokenTs) throw erroPublico("Confirme a verificação de segurança e tente de novo.", 403);
  const form = new FormData();
  form.append("secret", env.TURNSTILE_SECRET); form.append("response", String(tokenTs).slice(0, 2048)); form.append("remoteip", ipDe(req));
  const r = await fetch("https://challenges.cloudflare.com/turnstile/v0/siteverify", { method: "POST", body: form }).then(x => x.json()).catch(() => null);
  if (!r?.success) throw erroPublico("A verificação de segurança expirou. Tente de novo.", 403);
}

// 3 cartões recusados em 1 minuto no mesmo IP → cartão bloqueado por 30 min para esse IP (o Pix continua)
const MIN_BLOQUEIO = 30;
const idIp = async req => "ip" + hexDe(await crypto.subtle.digest("SHA-256", new TextEncoder().encode("popzin:" + ipDe(req)))).slice(0, 32);
const hexDe = buf => [...new Uint8Array(buf)].map(b => b.toString(16).padStart(2, "0")).join("");
async function conferirBloqueio(env, req) {
  const doc = await fs(env, `/bloqueios/${await idIp(req)}`).catch(() => null);
  const ate = doc?.fields?.ate?.stringValue;
  if (ate && Date.parse(ate) > Date.now()) throw erroPublico("Por segurança, o pagamento com cartão foi pausado por alguns minutos. Você pode pagar com Pix agora.", 429);
}
async function registrarRecusa(env, req) {
  if (!env.LIMITE_RECUSAS) return;
  const { success } = await env.LIMITE_RECUSAS.limit({ key: ipDe(req) }).catch(() => ({ success: true }));
  if (success) return;
  const ate = new Date(Date.now() + MIN_BLOQUEIO * 60000).toISOString();
  await fs(env, `/bloqueios/${await idIp(req)}`, { method: "PATCH", body: JSON.stringify({ fields: { ate: { stringValue: ate } } }) }).catch(e => console.error("bloqueio", e.message));
  console.warn("cartão bloqueado para um IP até", ate);
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
function lerCliente(b) {
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
  return cliente;
}
/* dados extras que aumentam a aprovação no Mercado Pago (itens, comprador, entrega) */
function infoAdicional(calc, cliente) {
  const [nome1, ...resto] = cliente.nome.split(/\s+/);
  return {
    items: calc.itens.map(i => ({ id: String(i.id), title: i.nome + (i.chaveiro ? " + chaveiro" : ""), quantity: i.q, unit_price: i.un, category_id: "toys" })),
    payer: { first_name: nome1, last_name: resto.join(" "), phone: { area_code: cliente.telefone.slice(0, 2), number: cliente.telefone.slice(2) },
             address: { zip_code: cliente.cep, street_name: cliente.rua, street_number: cliente.numero } },
    shipments: { receiver_address: { zip_code: cliente.cep, state_name: cliente.uf, city_name: cliente.cidade, street_name: cliente.rua, street_number: cliente.numero } },
  };
}

async function criarPix(req, env, url) {
  const b = await req.json().catch(() => null);
  if (!b) throw erroPublico("Dados inválidos.");
  const cliente = lerCliente(b);

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
      additional_info: infoAdicional(calc, cliente), statement_descriptor: "POPZIN",
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

const MOTIVOS_RECUSA = {
  cc_rejected_bad_filled_card_number: "Confira o número do cartão.",
  cc_rejected_bad_filled_date: "Confira a data de validade.",
  cc_rejected_bad_filled_security_code: "Confira o código de segurança (CVV).",
  cc_rejected_bad_filled_other: "Confira os dados do cartão.",
  cc_rejected_insufficient_amount: "O cartão não tem limite suficiente.",
  cc_rejected_call_for_authorize: "O banco pediu autorização: ligue para o banco e tente de novo.",
  cc_rejected_card_disabled: "Cartão desativado: ligue para o banco para ativá-lo.",
  cc_rejected_duplicated_payment: "Você já fez um pagamento com esse valor. Se precisar pagar de novo, use outro cartão ou o Pix.",
  cc_rejected_high_risk: "Pagamento recusado por segurança. Tente outro cartão ou pague com Pix.",
  cc_rejected_max_attempts: "Limite de tentativas atingido. Tente outro cartão ou pague com Pix.",
  cc_rejected_blacklist: "Não foi possível processar este cartão. Tente outro ou pague com Pix.",
  cc_rejected_other_reason: "O banco recusou o pagamento. Tente outro cartão ou pague com Pix.",
};
async function pagarCartao(req, env, url) {
  const b = await req.json().catch(() => null);
  if (!b || !b.cartao?.token) throw erroPublico("Dados do cartão incompletos.");
  await conferirHumano(env, req, b.turnstile);
  await conferirBloqueio(env, req);
  const cliente = lerCliente(b);
  const [produtos, cfg] = await Promise.all([listarProdutos(env), lerConfig(env)]);
  const calc = calcular(b.itens, produtos, cfg, cliente.uf);
  const total = calc.total;                                    // cartão: sem o desconto do Pix
  const maxParc = Math.max(1, Math.min(12, +cfg.maxParcelas || 6));
  const parcelas = Math.max(1, Math.min(maxParc, Math.floor(+b.cartao.installments || 1)));
  const id = "pz" + Date.now().toString(36) + hex(2);
  const token = hex(12);
  const agora = new Date();
  const doc = b.cartao.payer?.identification?.number ? b.cartao.payer.identification : { type: "CPF", number: cliente.cpf };
  const [nome1, ...resto] = cliente.nome.split(/\s+/);

  const pg = await mp(env, "/v1/payments", {
    method: "POST", headers: { "X-Idempotency-Key": id, ...(b.deviceId ? { "X-meli-session-id": so(b.deviceId, 100) } : {}) },
    body: JSON.stringify({
      transaction_amount: total, token: b.cartao.token, installments: parcelas,
      payment_method_id: so(b.cartao.payment_method_id, 30), ...(b.cartao.issuer_id ? { issuer_id: String(b.cartao.issuer_id) } : {}),
      description: `PopZin — pedido ${id.toUpperCase()}`, external_reference: id, statement_descriptor: "POPZIN",
      notification_url: `${url.origin}/webhook`,
      payer: { email: cliente.email, first_name: nome1, last_name: resto.join(" "), identification: { type: so(doc.type, 10) || "CPF", number: digitos(doc.number) } },
      additional_info: infoAdicional(calc, cliente),
    }),
  }).catch(e => { if (e.mpStatus && e.mpStatus < 500) throw erroPublico("Não foi possível processar o cartão. Confira os dados ou pague com Pix."); throw e; });

  if (pg.status === "rejected" || pg.status === "cancelled") {
    await registrarRecusa(env, req);
    throw erroPublico(MOTIVOS_RECUSA[pg.status_detail] || "Pagamento recusado. Tente outro cartão ou pague com Pix.", 402);
  }

  const cartaoInfo = { bandeira: pg.payment_method_id, tipo: pg.payment_type_id, parcelas: pg.installments || parcelas, final: pg.card?.last_four_digits || "" };
  const dados = { id, origem: "site", criado: agora.toISOString(), pagamento: "cartao", mpId: String(pg.id), cartao: cartaoInfo,
                  cliente, obs: so(b.obs, 300), ...calc, total, totalSemPix: total, historico: [{ status: "aguardando", em: agora.toISOString() }] };
  await fs(env, `/pedidos?documentId=${id}`, { method: "POST", body: JSON.stringify({ fields: camposPedido(dados, "aguardando", {
    mpId: { stringValue: String(pg.id) }, token: { stringValue: token } }) }) });
  if (pg.status === "approved") { const ped = await lerPedido(env, id); if (ped) await aplicarPagamento(env, ped, pg); }
  return { id, token, total, status: pg.status === "approved" ? "pago" : "analise", parcelas: cartaoInfo.parcelas };
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
    pagamento: d.pagamento || "pix", cartao: d.cartao ? { parcelas: d.cartao.parcelas, final: d.cartao.final, tipo: d.cartao.tipo } : null,
    ...(ped.status === "aguardando" ? { qr: d.qr, qrImg: d.qrImg } : {}),
  };
}

/* confere a assinatura x-signature do Mercado Pago (HMAC-SHA256 com o segredo MP_WEBHOOK_SECRET).
   Sem o segredo cadastrado, ou aviso sem assinatura: segue, porque o pagamento é sempre reconsultado no MP. */
async function assinaturaValida(req, url, env) {
  const segredo = env.MP_WEBHOOK_SECRET, xs = req.headers.get("x-signature");
  if (!segredo) return true;
  if (!xs) { console.warn("webhook sem assinatura"); return true; }
  let ts = "", v1 = "";
  for (const parte of xs.split(",")) { const i = parte.indexOf("="); if (i < 0) continue; const k = parte.slice(0, i).trim(), v = parte.slice(i + 1).trim(); if (k === "ts") ts = v; if (k === "v1") v1 = v; }
  if (!ts || !v1) return false;
  const dataId = (url.searchParams.get("data.id") || "").toLowerCase(), reqId = req.headers.get("x-request-id") || "";
  const manifest = (dataId ? `id:${dataId};` : "") + (reqId ? `request-id:${reqId};` : "") + `ts:${ts};`;
  const chave = await crypto.subtle.importKey("raw", new TextEncoder().encode(segredo), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const calc = hexDe(await crypto.subtle.sign("HMAC", chave, new TextEncoder().encode(manifest)));
  if (calc.length !== v1.length) return false;
  let dif = 0; for (let i = 0; i < calc.length; i++) dif |= calc.charCodeAt(i) ^ v1.toLowerCase().charCodeAt(i);
  if (dif) console.warn("webhook com assinatura inválida");
  return dif === 0;
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
  if (!ped) return;
  if (pg.status === "approved") await aplicarPagamento(env, ped, pg);
  else if (ped.status === "aguardando") await sincronizar(env, ped);
}

/* --------------------------------------- confirmação e expiração */
async function sincronizar(env, ped) {
  const mpId = ped.doc.fields.mpId?.stringValue || ped.dados.mpId;
  if (!mpId) return;
  const pg = await mp(env, `/v1/payments/${mpId}`);
  if (pg.status === "approved") return aplicarPagamento(env, ped, pg);
  if (ped.dados.pagamento === "cartao") {                                    // cartão em análise: espera o Mercado Pago decidir
    if (["rejected", "cancelled", "refunded", "charged_back"].includes(pg.status)) {
      const dados = { ...ped.dados, historico: [...(ped.dados.historico || []), { status: "cancelado", em: new Date().toISOString() }] };
      await gravarPedidoSe(env, ped, dados, "cancelado");
    }
    return;
  }
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
  try { await avisarDono(env, dados); } catch (e) { console.error("aviso dono", dados.id, e.message); }
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

/* aviso para a loja quando entra um pedido pago.
   O(s) e-mail(s) ficam no segredo AVISO_EMAIL do Cloudflare (separe vários por vírgula). */
async function avisarDono(env, d) {
  const para = String(env.AVISO_EMAIL || "").split(",").map(x => x.trim()).filter(x => /@/.test(x));
  if (!env.RESEND_API_KEY || !para.length) return false;
  const c = d.cliente || {};
  const forma = d.pagamento === "cartao" ? `💳 Cartão${d.cartao?.tipo === "debit_card" ? " débito" : ` ${d.cartao?.parcelas || 1}x`}` : "⚡ Pix";
  const linhas = (d.itens || []).map(i => `<tr><td style="padding:4px 8px">${i.q}× ${escE(i.nome)}${i.chaveiro ? " + chaveiro" : ""}</td><td style="padding:4px 8px;text-align:right">${brlE(i.un * i.q)}</td></tr>`).join("");
  const painel = `${(env.SITE_URL || "https://popzin.com.br").replace(/\/$/, "")}/admin.html`;
  const html = `<div style="font-family:Arial,sans-serif;max-width:520px;margin:auto;color:#1d1640">
    <h2 style="color:#7b2ff7;margin:0 0 6px">🎉 Novo pedido pago!</h2>
    <p style="margin:0 0 14px">Pedido <b>${escE(d.id.toUpperCase())}</b> · ${forma} · <b>${brlE(d.total)}</b></p>
    <table style="width:100%;border-collapse:collapse;background:#faf7ff;border-radius:10px">${linhas}
      <tr><td style="padding:4px 8px">Frete</td><td style="padding:4px 8px;text-align:right">${d.frete ? brlE(d.frete) : "Grátis"}</td></tr></table>
    <p style="margin:14px 0 4px"><b>${escE(c.nome)}</b> · ${escE(c.telefone)}<br>${escE(c.rua)}, ${escE(c.numero)}${c.complemento ? " - " + escE(c.complemento) : ""} · ${escE(c.bairro)}<br>${escE(c.cidade)}/${escE(c.uf)} · CEP ${escE(c.cep)}</p>
    ${d.obs ? `<p style="background:#fff6d6;padding:8px;border-radius:8px">📝 ${escE(d.obs)}</p>` : ""}
    <p><a href="${painel}" style="background:#7b2ff7;color:#fff;padding:10px 16px;border-radius:10px;text-decoration:none;font-weight:bold">Abrir o painel</a></p></div>`;
  const r = await fetch("https://api.resend.com/emails", {
    method: "POST", headers: { Authorization: `Bearer ${env.RESEND_API_KEY}`, "Content-Type": "application/json", "Idempotency-Key": `${d.id}-aviso-dono` },
    body: JSON.stringify({ from: env.EMAIL_DE || "PopZin <pedidos@popzin.com.br>", to: para, subject: `🎉 Novo pedido pago — ${d.id.toUpperCase()} — ${brlE(d.total)}`,
      html, text: `Novo pedido pago ${d.id.toUpperCase()} — ${brlE(d.total)} (${forma})\n${(d.itens || []).map(i => `${i.q}x ${i.nome}`).join("\n")}\n${c.nome} · ${c.cidade}/${c.uf}\nPainel: ${painel}` }),
  });
  if (!r.ok) throw new Error(`Resend ${r.status}`);
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
