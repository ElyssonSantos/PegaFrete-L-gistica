# 🛡️ PegaFrete - Documentação de Segurança e Hardening

Este documento detalha a arquitetura de segurança, fluxo de autenticação e boas práticas implementadas no projeto PegaFrete para garantir um padrão **Zero Trust (Confiança Zero)**.

## 1. Arquitetura de Segurança (Zero Trust)

A segurança do PegaFrete foi refatorada para não depender exclusivamente de proteções no Frontend (cliente). Todas as validações e permissões de acesso são aplicadas no lado do servidor via **Firestore Security Rules** e **Firebase Storage Rules**.

- **Acesso Negado por Padrão**: Todas as coleções e buckets que não possuem uma regra explícita de `allow` estão inacessíveis.
- **Proteção contra IDOR**: Usuários só podem acessar, criar ou alterar dados em que o campo `uid`, `userId` ou `shipperUid` corresponda exatamente ao `request.auth.uid`.
- **Validação de Payload**: Limites estritos de tamanho, formato e campos permitidos impedem injeções de dados e garantem que o banco não seja poluído com lixo ou metadados de sistema.

## 2. Fluxo de Autenticação

Utilizamos o Firebase Authentication de forma segura e mitigada contra ataques comuns:

1. **Anti-Enumeração de Email**: O uso do método `fetchSignInMethodsForEmail` foi desencorajado. Se um usuário não for encontrado no login, o sistema sugere que ele crie a conta, não distinguindo erros genéricos e impedindo varreduras.
2. **Session Timeout (Frontend)**: O aplicativo conta com um auto-logout após 1 hora (60 minutos) de inatividade, limpando o token da sessão localmente.
3. **Bloqueio de Contas Órfãs**: Antigas implementações que deletavam contas "órfãs" pelo lado do cliente (grave falha de segurança) foram totalmente removidas.

## 3. Gerenciamento de Segredos

O aplicativo utiliza um `.gitignore` rigoroso para que segredos e variáveis sensíveis não cheguem ao repositório público. As variáveis públicas do Firebase são definidas via `.env`.

### Como configurar `.env`

1. Existe um arquivo na raiz do projeto chamado `.env.example`.
2. Renomeie (ou crie uma cópia) para `.env`.
3. Preencha com as suas chaves reais do projeto acessando o Firebase Console (Configurações do Projeto > Geral).

```env
FIREBASE_API_KEY=sua_chave_real
FIREBASE_AUTH_DOMAIN=seu_projeto.firebaseapp.com
...
```

*Nota: As chaves web do Firebase (API_KEY) são públicas por design. O que protege seus dados não é esconder a chave, são as **Security Rules**.*

## 4. Como executar Cloud Functions e Cloud Backend

No momento, o aplicativo está **otimizado para rodar de forma serverless no plano Spark (Gratuito) do Firebase**, com as Security Rules atuando como "backend".

*Se no futuro o projeto for migrado para o plano **Blaze (Pay-as-you-go)** para uso de Cloud Functions (node.js):*

1. Abra o `index.html` e altere a constante `USE_CLOUD_FUNCTIONS = true` (atualmente inativa).
2. Entre na pasta `functions`, rode `npm install` e `npm run build`.
3. Use o comando de deploy via Firebase CLI.

## 5. Checklist de Segurança

Antes de qualquer deploy crítico, garanta que os seguintes pontos foram validados:

- [x] **IDOR totalmente mitigado** (Validações estritas de `request.auth.uid`).
- [x] **Limites de input aplicados** (Tamanho máximo, campos permitidos, XSS protection).
- [x] **Uploads protegidos** (Limites de MIME Type via Magic Bytes, extensões e tamanhos configurados via rules e JS).
- [x] **URLs e Payloads externos bloqueados** (Bloqueio de path traversal `../` e arquivos maliciosos).
- [x] **Logs de segurança implementados** (Gravados na coleção `security_logs` com timestamp e UID).
- [x] **Regras do Firestore implantadas** (Firebase deploy `firestore:rules`).

## 6. Boas Práticas para Futuras Implementações

1. **Nunca valide regras críticas apenas no Frontend**: O JS local sempre pode ser contornado. Se precisar de uma nova feature, crie a regra de permissão (allow) correspondente no `firestore.rules`.
2. **Mantenha os limites estritos (Defense in Depth)**: O Frontend ajuda a evitar que payloads quebrem (`sanitizeInput`), mas é o backend (Regras ou Cloud Function) quem recusa.
3. **App Check**: Assim que publicar na Vercel/Produção, ative o Firebase App Check (reCAPTCHA v3) no Firebase Console.
4. **Campos Imutáveis**: Se você adicionar cargos novos de `role`, certifique-se de que a regra `allow update` não permite que o usuário troque sua própria "role" livremente.
