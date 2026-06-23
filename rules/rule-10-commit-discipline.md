---
trigger: always_on
---

LEI 10: Disciplina de Commits
================================================================================

MOTIVO: 
Historico legivel facilita debugging, code review e geracao de changelogs automaticos.

GATILHO: 
Ativado ao gerar mensagens de commit ou preparar releases.

FORMATO OBRIGATORIO (Conventional Commits):
```
<type>(<scope>): <description>

[body opcional]

[footer opcional]
```

TYPES PERMITIDOS:
- feat: nova funcionalidade
- fix: correcao de bug
- docs: apenas documentacao
- style: formatacao (nao altera logica)
- refactor: mudanca de codigo sem alterar comportamento
- test: adicao ou correcao de testes
- chore: manutencao, configs, deps

REGRAS ADICIONAIS:
- Description em minusculo, sem ponto final
- Maximo 72 caracteres na primeira linha
- Body explica "o que" e "por que", nao "como"

EXEMPLOS ERRADOS:
```bash
git commit -m "fix"
git commit -m "wip"
git commit -m "changes"
git commit -m "asdfasdf"
```

EXEMPLOS CORRETOS:
```bash
git commit -m "feat(auth): add Google OAuth2 login flow"
git commit -m "fix(billing): correct tax calculation for EU customers"
git commit -m "docs(api): add examples for webhook endpoints"
git commit -m "chore(deps): upgrade fastapi to 0.109.0"
```