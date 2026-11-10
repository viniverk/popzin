# PopZin — catálogo + painel do lojista

Site estático para o GitHub Pages. O painel (`admin.html`) salva produtos, artes e configurações direto no repositório.

## Arquivos
| Arquivo | O que é |
|---|---|
| `index.html` | A loja/catálogo |
| `admin.html` | Painel com login (link "Área do lojista" no rodapé) |
| `produtos.json` | Lista de produtos (o painel edita) |
| `loja.json` | WhatsApp, fretes, Pix, links (o painel edita) |
| `img/` | Artes enviadas pelo painel |
| `admin-config.json` | Criado na 1ª configuração — token criptografado |

## Instalação (uma vez)
1. **Crie o repositório** no GitHub (ex.: `popzin`), público.
2. **Suba todos os arquivos** desta pasta (Add file → Upload files).
3. **Ative o Pages:** Settings → Pages → *Deploy from a branch* → `main` / `(root)` → Save.
   O site fica em `https://viniverk.github.io/popzin/`.
4. **Crie um token:** https://github.com/settings/personal-access-tokens/new
   - *Repository access:* **Only select repositories** → `popzin`
   - *Permissions → Contents:* **Read and write**
   - Escolha uma validade (ex.: 1 ano) e copie o token (`github_pat_...`).
5. **Abra** `https://viniverk.github.io/popzin/admin.html`, preencha usuário do GitHub, repositório, token, e **crie seu usuário e senha do painel**.

Pronto: dali em diante é só entrar com usuário e senha.

## Como funciona a segurança
- O token é salvo no repositório **criptografado** (AES-256-GCM, chave derivada do seu usuário + senha com PBKDF2, 310 mil iterações). Sem a senha, o arquivo não serve para nada.
- Use uma **senha forte** (frase longa) — como o arquivo é público, a força da senha é o que protege.
- O token só tem acesso a este repositório.
- **Esqueceu a senha ou o token venceu?** Apague `admin-config.json` no GitHub, gere outro token e refaça o passo 5.

## Observações
- Depois de salvar no painel, o site leva ~1 minuto para atualizar (tempo do GitHub Pages).
- As imagens são redimensionadas para no máximo 1000px e convertidas para WebP antes do envio.
- Domínio próprio (ex.: loja.cliente3d.com.br): Settings → Pages → Custom domain.

## Banco de dados (Firebase) — atualização instantânea
Com o Firebase configurado, produtos e configurações ficam no Firestore: salvou no painel, já aparece no site.
As fotos são por link (ex.: suba no imgur.com e cole o endereço da imagem).
1. Crie o projeto em console.firebase.google.com (plano gratuito Spark, sem cartão).
2. Firestore Database → criar (southamerica-east1, modo produção).
3. Authentication → E-mail/senha → ativar → Usuários → Adicionar usuário (login do painel).
4. Firestore → Regras → cole `firestore.rules`, troque o e-mail → Publicar.
5. Preencha `config.js` com `apiKey` e `projectId` (Configurações do projeto → Seus apps → Web).
6. Entre no painel com e-mail e senha e clique em **Importar agora** (traz os produtos atuais).

Sem `config.js` preenchido, o site e o painel continuam usando `produtos.json`/`loja.json` do GitHub.
