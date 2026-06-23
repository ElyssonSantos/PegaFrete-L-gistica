---
trigger: always_on
---

LEI 03: Blindagem Multi-Tenant
================================================================================

MOTIVO: 
Evitar o vazamento de dados entre empresas (a falha de expor UID de outra empresa).

GATILHO: 
Ativado ao criar queries de banco de dados, migrations SQL, ou qualquer codigo 
que acesse dados de usuarios/empresas.

VERIFICACOES OBRIGATORIAS:
- Clausula de Empresa: Toda e qualquer query ao banco de dados DEVE incluir 
  explicitamente .eq('company_id', company_id).
- Origem da Identidade: O company_id nunca deve ser aceito como parametro 
  vindo livremente do frontend (JSON body). Ele deve ser extraido 
  obrigatoriamente do objeto de sessao autenticado (require_authenticated_user 
  no FastAPI ou Iron Session no Next.js).
- RLS Enforcer: Ao sugerir novas tabelas em migracoes SQL, inclua sempre 
  ENABLE ROW LEVEL SECURITY com politicas baseadas em auth.uid() ou company_id.

EXEMPLO ERRADO:
```python
from fastapi import APIRouter

router = APIRouter()

@router.get("/agents")
async def list_agents(company_id: str):  # company_id vem do query param!
    agents = await supabase.from_("agents") \
        .select("*") \
        .eq("company_id", company_id) \
        .execute()
    return agents.data
```

EXEMPLO CORRETO:
```python
from fastapi import APIRouter, Depends
from app.auth.dependencies import require_authenticated_user
from app.auth.schemas import AuthenticatedUser

router = APIRouter()

@router.get("/agents")
async def list_agents(
    user: AuthenticatedUser = Depends(require_authenticated_user)
):
    # company_id SEMPRE da sessao, nunca do request
    agents = await supabase.from_("agents") \
        .select("*") \
        .eq("company_id", user.company_id) \
        .execute()
    return agents.data
```

EXEMPLO SQL COM RLS:
```sql
CREATE TABLE agents (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    company_id UUID NOT NULL REFERENCES companies(id),
    name TEXT NOT NULL
);

ALTER TABLE agents ENABLE ROW LEVEL SECURITY;

CREATE POLICY "tenant_isolation" ON agents
    FOR ALL
    USING (company_id = auth.jwt()->>'company_id');
```