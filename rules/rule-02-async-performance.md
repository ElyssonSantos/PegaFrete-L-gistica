---
trigger: always_on
---

LEI 02: Performance e Concorrencia Async
================================================================================

MOTIVO: 
Garantir que o servidor FastAPI nunca trave por operacoes bloqueantes (I/O sincrono).

GATILHO: 
Ativado sempre que o agente for criar ou modificar arquivos em /backend/app/api 
ou /backend/app/services.

DIRETRIZES TECNICAS:
- Async First: Toda comunicacao com banco de dados, Redis ou APIs externas 
  (OpenAI, Anthropic, Gemini) DEVE ser async.
- Proibicao de Codigo Bloqueante: Nunca use time.sleep() ou bibliotecas 
  sincronas (como requests) dentro das rotas do FastAPI. Use asyncio.sleep() 
  e httpx.AsyncClient().
- Background Tasks: Operacoes de longa duracao (billing, processamento de PDFs, 
  treinamento de agentes) devem ser delegadas para Celery Workers standalone.

EXEMPLO ERRADO:
```python
from fastapi import FastAPI
import requests
import time

app = FastAPI()

@app.get("/fetch-data")
def fetch_data():
    time.sleep(2)  # Bloqueia o event loop!
    response = requests.get("https://api.externa.com/data")  # Bloqueante!
    return response.json()
```

EXEMPLO CORRETO:
```python
from fastapi import FastAPI
import httpx
import asyncio

app = FastAPI()

@app.get("/fetch-data")
async def fetch_data():
    await asyncio.sleep(2)  # Nao bloqueia
    async with httpx.AsyncClient() as client:
        response = await client.get("https://api.externa.com/data")
    return response.json()

# Para operacoes longas:
from app.workers.tasks import process_heavy_pdf

@app.post("/process-document")
async def process_document(file_id: str):
    process_heavy_pdf.delay(file_id)  # Delega para Celery
    return {"status": "processing", "file_id": file_id}
```