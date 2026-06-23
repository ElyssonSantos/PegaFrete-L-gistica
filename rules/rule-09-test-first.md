---
trigger: always_on
---

LEI 9: Testes Antes da Implementacao
================================================================================

MOTIVO: 
Garantir que o codigo gerado atenda aos requisitos definidos e nao apenas 
"pareca funcionar".

GATILHO: 
Ativado quando o usuario pedir nova feature, endpoint ou funcao de negocio.

WORKFLOW OBRIGATORIO:
1. Red: Escreva testes que definem o comportamento esperado. 
   Eles DEVEM falhar inicialmente.
2. Green: Implemente o codigo minimo necessario para os testes passarem.
3. Refactor: Melhore a estrutura mantendo os testes verdes.

COBERTURA MINIMA:
- Funcoes de negocio: 80% de cobertura
- Edge cases obrigatorios: null/undefined, array vazio, strings vazias, 
  limites numericos
- Casos de erro: pelo menos 1 teste de excecao por funcao que pode falhar

EXEMPLO:
```python
# 1. PRIMEIRO: Escreva os testes
# tests/test_discount.py
import pytest
from app.services.pricing import calculate_discount, InvalidCouponError

class TestCalculateDiscount:
    def test_valid_coupon_applies_discount(self):
        assert calculate_discount(100.0, "SAVE10") == 90.0
    
    def test_no_coupon_returns_original_price(self):
        assert calculate_discount(100.0, None) == 100.0
    
    def test_invalid_coupon_raises_error(self):
        with pytest.raises(InvalidCouponError):
            calculate_discount(100.0, "FAKE123")
    
    def test_negative_price_raises_error(self):
        with pytest.raises(ValueError):
            calculate_discount(-50.0, "SAVE10")

# 2. DEPOIS: Implemente para passar os testes
# app/services/pricing.py
def calculate_discount(price: float, coupon_code: str | None) -> float:
    if price < 0:
        raise ValueError("Preco nao pode ser negativo")
    
    if not coupon_code:
        return price
    
    coupon = COUPONS.get(coupon_code.upper())
    if not coupon:
        raise InvalidCouponError(f"Cupom invalido: {coupon_code}")
    
    return price * (1 - coupon["discount"])
```

================================================================================
rule-11-api-consistency.md
LEI 11: Consistencia de API REST
================================================================================

MOTIVO: 
APIs previsiveis reduzem erros de integracao e facilitam onboarding de novos devs.

GATILHO: 
Ativado ao criar routers, controllers ou endpoints de API.

CONVENCOES DE ROTAS:
```
| Acao      | Metodo | Rota             | Response        |
|-----------|--------|------------------|-----------------|
| Listar    | GET    | /resources       | 200 + array     |
| Detalhe   | GET    | /resources/:id   | 200 + objeto    |
| Criar     | POST   | /resources       | 201 + objeto    |
| Atualizar | PATCH  | /resources/:id   | 200 + objeto    |
| Substituir| PUT    | /resources/:id   | 200 + objeto    |
| Deletar   | DELETE | /resources/:id   | 204 (no content)|
```

PADRAO DE RESPOSTA DE ERRO:
```json
{
  "error": {
    "code": "VALIDATION_ERROR",
    "message": "Email invalido",
    "field": "email",
    "request_id": "req_abc123"
  }
}
```

EXEMPLO ERRADO:
```python
@app.get("/getUsers")           # verbo no path
@app.post("/user/create")       # singular + verbo
@app.post("/delete-user/{id}")  # POST pra delete?
```

EXEMPLO CORRETO:
```python
@router.get("")                              # GET /users
async def list_users(): ...

@router.get("/{user_id}")                    # GET /users/:id
async def get_user(user_id: UUID): ...

@router.post("", status_code=201)            # POST /users
async def create_user(payload: UserCreate): ...

@router.patch("/{user_id}")                  # PATCH /users/:id
async def update_user(user_id: UUID, payload: UserUpdate): ...

@router.delete("/{user_id}", status_code=204) # DELETE /users/:id
async def delete_user(user_id: UUID): ...
```