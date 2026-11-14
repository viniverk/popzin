# Servidor de pagamentos (Cloudflare Worker)

`worker.js` gera o Pix no Mercado Pago, grava o pedido no Firestore, recebe o aviso de pagamento
e expira pedidos não pagos (relógio de 5 minutos).

## Publicação automática
O worker `popzin-api` está ligado a este repositório (Cloudflare → Workers Builds, pasta `/worker`).
Todo push na branch `main` publica de novo, usando `wrangler.toml` (variáveis públicas e o cron de 5 min).
Só os dois segredos ficam no painel: `MP_ACCESS_TOKEN` e `FIREBASE_SA` (Settings → Variables and Secrets → tipo Secret).

Endereço: https://popzin-api.discipulos-pagamento.workers.dev

## Publicar manualmente (alternativa)
1. Cloudflare → Workers & Pages → Create → Worker → nome `popzin-api` → Deploy → **Edit code**.
2. Apague o código de exemplo, cole todo o `worker.js` → **Deploy**.
3. Settings → **Variables and Secrets** → Add:
   - `MP_ACCESS_TOKEN` (Secret): Access Token do Mercado Pago (`APP_USR-...`; para testar, o de teste `TEST-...`)
   - `FIREBASE_SA` (Secret): o conteúdo inteiro do arquivo .json da conta de serviço do Firebase
   - `FIREBASE_PROJECT` (Text): `popzin`
   - `ORIGENS` (Text): `https://popzin.com.br,https://www.popzin.com.br,https://viniverk.github.io`
4. Settings → **Triggers** → Cron Triggers → Add → `*/5 * * * *`.
5. Copie o endereço do worker (ex.: `https://popzin-api.SEUNOME.workers.dev`) e coloque em `config.js` → `POPZIN_CHECKOUT.api`.

Nunca coloque o Access Token nem a conta de serviço no GitHub: só nas variáveis secretas do Cloudflare.
