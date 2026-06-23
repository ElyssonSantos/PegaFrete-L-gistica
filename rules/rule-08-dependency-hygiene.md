---
trigger: always_on
---

LEI 08: Higiene de Dependencias
================================================================================

MOTIVO: 
Prevenir supply chain attacks e acumulo de vulnerabilidades em pacotes 
desatualizados ou maliciosos.

GATILHO: 
Ativado ao sugerir npm install, pip install, cargo add ou qualquer adicao 
ao package.json/requirements.txt/Cargo.toml.

CRITERIOS DE ACEITACAO:
- Freshness: So sugira pacotes com ultima release < 12 meses.
- Popularity Threshold: Prefira pacotes com >1000 downloads semanais (npm) 
  ou >500 stars (GitHub).
- Security Scan: Antes de adicionar dependencia, execute npm audit / 
  pip-audit / cargo audit e rejeite pacotes com CVEs criticos ou altos.
- Minimal Footprint: Evite dependencias para funcoes triviais 
  (ex: nao use left-pad, is-odd).

WORKFLOW DO AGENTE:
```
1. Verificar vulnerabilidades:
   $ pip-audit nome-do-pacote
   
2. Verificar popularidade e manutencao:
   - Downloads/semana: 50,000+ 
   - Ultima release: < 12 meses
   - GitHub stars: 2,000+
   - Maintainers ativos: 2+

3. Verificar se e realmente necessario:
   - Funcionalidade trivial? -> Implemente inline
   - Ja existe no stdlib? -> Use stdlib
```

EXEMPLO - FUNCAO TRIVIAL:
```python
# NAO FACA ISSO:
# import is_odd

# FACA ISSO:
def is_odd(n: int) -> bool:
    return n % 2 != 0
```