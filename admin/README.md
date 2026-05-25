# PegaFrete Admin Portal

Painel Administrativo Externo para gerenciamento do ecossistema PegaFrete Logística.

## O que é

Site administrativo desacoplado que se comunica com o Firebase do app principal via APIs REST seguras. Permite gerenciar usuários, fretes, documentos, notificações e logs de auditoria.

## Pré-requisitos

- **Node.js 18+**
- **Firebase Service Account** do projeto `pegafrete-logistica`

## Instalação

```bash
cd admin
cp .env.example .env   # Edite com suas credenciais
npm install
```

## Como obter a Service Account

1. Acesse o [Firebase Console](https://console.firebase.google.com)
2. Selecione o projeto **pegafrete-logistica**
3. Vá em **Configurações do Projeto** → **Contas de Serviço**
4. Clique em **Gerar nova chave privada**
5. Salve o arquivo `.json` e coloque o caminho na variável `FIREBASE_SERVICE_ACCOUNT_JSON` do `.env`

## Como criar o primeiro Admin

1. Cadastre-se normalmente no app PegaFrete
2. Copie seu **UID** no Firebase Console → Authentication
3. Inicie o servidor admin (`npm run dev`)
4. Acesse a aba **"Configurar Admin"** no dashboard, ou envie um POST:

```bash
curl -X POST http://localhost:5000/api/admin/setup-claims \
  -H "Content-Type: application/json" \
  -d '{"uid":"SEU_UID_AQUI","secret":"SUA_CHAVE_DO_ENV"}'
```

5. Faça logout e login novamente para ativar os privilégios

## Rodar localmente

```bash
npm run dev    # Com auto-reload (--watch)
npm start      # Modo produção
```

Acesse: http://localhost:5000

## Deploy na Vercel

1. Crie um novo projeto na Vercel apontando para o diretório `admin/`
2. Configure as variáveis de ambiente no painel da Vercel:
   - `PORT` → `5000`
   - `ADMIN_SETUP_SECRET` → sua chave secreta
   - `FIREBASE_SERVICE_ACCOUNT_JSON` → conteúdo JSON da service account
3. Deploy automático via push no GitHub

## Referência de API

| Método | Rota | Auth | Descrição |
|--------|------|------|-----------|
| POST | `/api/admin/setup-claims` | Secret | Promove UID a admin |
| GET | `/api/admin/stats` | JWT Admin | Métricas operacionais |
| GET | `/api/admin/users` | JWT Admin | Lista usuários (filtro: ?role=) |
| GET | `/api/admin/users/:uid` | JWT Admin | Detalhes de um usuário |
| PUT | `/api/admin/users/:uid` | JWT Admin | Edita dados de usuário |
| GET | `/api/admin/freights` | JWT Admin | Lista fretes |
| PUT | `/api/admin/freights/:id` | JWT Admin | Atualiza status de frete |
| GET | `/api/admin/documents/pending` | JWT Admin | Docs pendentes de verificação |
| POST | `/api/admin/documents/verify` | JWT Admin | Aprova/rejeita documento |
| POST | `/api/admin/notifications/send` | JWT Admin | Envia notificação |
| GET | `/api/admin/logs` | JWT Admin | Logs de segurança (últimos 100) |

## Segurança

1. **JWT + Custom Claims**: Frontend obtém ID Token do Firebase Auth → Backend verifica assinatura e exige `admin: true`
2. **Helmet**: Headers seguros (CSP, HSTS, X-Frame-Options)
3. **CORS**: Whitelist de origens autorizadas
4. **Rate Limiting**: 100 req / 15 min por IP
5. **Firestore Rules**: Regras server-side reforçam `isAdmin()` em operações sensíveis
6. **Sanitização**: Toda renderização client-side passa por sanitização anti-XSS
