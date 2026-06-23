---
trigger: always_on
---

LEI 05: Arquitetura Limpa Smith
================================================================================

MOTIVO: 
Combater o codigo sujo e a duplicacao de logica (o "copia e cola" do passado).

GATILHO: 
Ativado ao criar novos arquivos de routers, services, ou ao adicionar logica 
de negocio em qualquer camada.

ESTRUTURA DE CAMADAS:
- Services (Logica de Negocio): Regras complexas (calculo de preco, RAG, 
  processamento de WhatsApp) residem estritamente em /app/services/.
- Routers (Interface): Rotas de API devem apenas validar o input e chamar 
  os servicos necessarios.
- DRY (Don't Repeat Yourself): Se a logica de calculo de tokens ou billing 
  for necessaria em mais de um lugar, ela deve ser centralizada no 
  UsageService ou BillingCore.

EXEMPLO ERRADO:
```python
# app/api/billing/router.py - logica de negocio no router!
@router.post("/charge")
async def charge_customer(customer_id: str, amount: float):
    customer = await supabase.from_("customers").select("*").eq("id", customer_id).single().execute()
    
    if customer.data["plan"] == "free":
        discount = 0
    elif customer.data["plan"] == "pro":
        discount = 0.1
    else:
        discount = 0.2
    
    final_amount = amount * (1 - discount)
    tokens_used = int(amount / 0.001)
    # ... mais 50 linhas de logica
```

EXEMPLO CORRETO:
```python
# app/services/billing_service.py
class BillingService:
    def __init__(self, usage_service: UsageService):
        self.usage = usage_service
    
    def calculate_discount(self, plan: str) -> float:
        discounts = {"free": 0, "pro": 0.1, "enterprise": 0.2}
        return discounts.get(plan, 0)
    
    async def charge(self, customer_id: str, amount: float) -> ChargeResult:
        customer = await self.get_customer(customer_id)
        discount = self.calculate_discount(customer.plan)
        final_amount = amount * (1 - discount)
        tokens = self.usage.calculate_tokens(amount)
        return ChargeResult(amount=final_amount, tokens=tokens)

# app/api/billing/router.py - router so valida e delega
@router.post("/charge")
async def charge_customer(
    request: ChargeRequest,
    billing: BillingService = Depends()
):
    result = await billing.charge(request.customer_id, request.amount)
    return result
```