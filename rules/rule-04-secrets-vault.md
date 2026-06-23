---
trigger: always_on
---

LEI 04: Cofre de Segredos (Secrets Management)
================================================================================

MOTIVO: 
Garantir que chaves de API de terceiros nunca fiquem em texto puro no banco de dados.

GATILHO: 
Ativado ao manipular API keys, tokens, credenciais, ou criar logs que possam 
conter dados sensiveis.

REGRAS DE IMPLEMENTACAO:
- Criptografia em Repouso: API Keys de provedores (OpenAI, Anthropic, Shopify) 
  salvas nas tabelas agents ou companies devem ser criptografadas via 
  EncryptionService antes do INSERT.
- Sanitizacao de Logs: O agente de desenvolvimento esta proibido de sugerir 
  logs que imprimam variaveis de ambiente sensiveis ou dados PII (e-mail, CPF).
- Env Var Validation: Toda nova variavel de ambiente critica deve ser validada 
  no startup (ex: ENCRYPTION_KEY deve ser Base64 URL-safe).

EXEMPLO ERRADO:
```python
async def save_agent(agent_data: dict):
    await supabase.from_("agents").insert({
        "name": agent_data["name"],
        "openai_api_key": agent_data["api_key"],  # Texto puro!
    }).execute()
    
    print(f"Agent criado com key: {agent_data['api_key']}")  # Log expondo!
```

EXEMPLO CORRETO:
```python
from app.services.encryption import EncryptionService

encryption = EncryptionService()

async def save_agent(agent_data: dict):
    encrypted_key = encryption.encrypt(agent_data["api_key"])
    
    await supabase.from_("agents").insert({
        "name": agent_data["name"],
        "openai_api_key_encrypted": encrypted_key,
    }).execute()
    
    logger.info(f"Agent criado: {agent_data['name']}")  # Sem dados sensiveis
```

VALIDACAO NO STARTUP:
```python
import base64
import os

class Settings:
    def __init__(self):
        self.encryption_key = os.getenv("ENCRYPTION_KEY")
        
        if not self.encryption_key:
            raise ValueError("ENCRYPTION_KEY nao configurada")
        
        try:
            base64.urlsafe_b64decode(self.encryption_key)
        except Exception:
            raise ValueError("ENCRYPTION_KEY deve ser Base64 URL-safe")
```