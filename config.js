/* Conexão com o Firebase (banco de dados dos produtos).
   Preencha com o apiKey e o projectId do app Web do seu projeto
   (Firebase → Configurações do projeto → Seus apps → firebaseConfig).
   Esses dados são públicos por natureza; quem protege o banco são as regras do Firestore.
   Deixando em branco, o site e o painel usam os arquivos produtos.json/loja.json do GitHub. */
window.POPZIN_FIREBASE = {
  apiKey: "AIzaSyCcgGT2fx61b_nGnDn1wVeMxYxUZ-C8oFc",
  projectId: "popzin"
};

/* Servidor de pagamentos (Cloudflare Worker). Endereço do worker, ex.: https://popzin-api.seunome.workers.dev
   Em branco = o checkout com Pix fica escondido e a loja segue só com o pedido pelo WhatsApp. */
window.POPZIN_CHECKOUT = {
  api: "https://popzin-api.discipulos-pagamento.workers.dev",
  /* Public Key do Mercado Pago (pública, pode ficar aqui). Em branco = sem a opção de cartão. */
  mpPublicKey: "APP_USR-e11c9034-bd65-49f4-811f-f209f7ddf424",
  /* Site Key do Cloudflare Turnstile ("não sou robô"). Em branco = desligado. */
  turnstileSiteKey: "0x4AAAAAAGBeODXtX2zfrX7Z"
};
