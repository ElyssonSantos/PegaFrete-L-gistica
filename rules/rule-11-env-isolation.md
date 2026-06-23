---
trigger: always_on
---

LEI 11: Isolamento de Ambientes
================================================================================

MOTIVO: 
Prevenir vazamento de dados de producao para dev e execucao acidental de 
codigo destrutivo no ambiente errado.

GATILHO: 
Ativado ao configurar variaveis de ambiente, connection strings ou deploy configs.

SEGREGACAO OBRIGATORIA:
- Bancos Separados: Cada ambiente (dev, staging, prod) DEVE ter seu proprio 
  banco de dados. Nunca compartilhe.
- Prefixos de Variaveis: Use prefixos claros: DEV_, STAGING_, PROD_ para 
  diferenciar configs.
- Feature Flags: Codigo nao finalizado deve estar atras de feature flags, 
  nunca commitado diretamente em main/master.

PROIBICOES:
- Hardcode de URLs de producao em codigo fonte
- Uso de dados reais de clientes em ambiente de desenvolvimento
- Conexao de ambiente local com banco de producao

ARQUIVOS DE ENV SEPARADOS:
```bash
# .env.development
DEV_DATABASE_URL=postgresql://localhost/myapp_dev
DEV_STRIPE_KEY=sk_test_xxxxx

# .env.production (NUNCA commitado)
PROD_DATABASE_URL=postgresql://prod-db.internal/myapp
PROD_STRIPE_KEY=sk_live_xxxxx
```

VALIDACAO NO CODIGO:
```python
class Settings:
    def __init__(self):
        self.env = Environment(os.getenv("APP_ENV", "development"))
        self.prefix = self.env.name + "_"
        
        self.database_url = os.getenv(f"{self.prefix}DATABASE_URL")
        self.stripe_key = os.getenv(f"{self.prefix}STRIPE_KEY")
        
        # Validacao: nao permitir key de prod em dev
        if self.env == Environment.DEV and "live" in self.stripe_key:
            raise ValueError("Chave de producao detectada em ambiente dev!")
```

PROTECAO EM SCRIPTS:
```python
async def seed_test_data():
    settings = Settings()
    
    if settings.env == Environment.PROD:
        raise RuntimeError("SEED BLOQUEADO EM PRODUCAO!")
    
    await db.execute("DELETE FROM users")
```