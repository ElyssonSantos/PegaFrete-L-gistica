---
trigger: always_on
---

LEI 01: Isolamento de Seguranca Smith
================================================================================

MOTIVO: 
Impedir o erro historico de expor chaves sensiveis ou permitir que o frontend 
ignore a camada de logica do backend.

GATILHO: 
Ativado ao criar ou modificar arquivos em /app, /components, ou qualquer 
codigo client-side que interaja com Supabase ou banco de dados.

RESTRICOES INEGOCIAVEIS:
- Proibicao de Service Role no Front: Nunca, sob qualquer pretexto, utilize a 
  SUPABASE_SERVICE_ROLE_KEY em arquivos dentro de /app ou /components.
- Zero Supabase Direct Writing: O frontend nao deve realizar operacoes de 
  escrita (insert, update, delete) diretamente via cliente Supabase do lado 
  do cliente. Toda alteracao de estado deve passar por uma rota de API (/api/*) 
  que valide a sessao.
- Headers de Seguranca: Toda nova rota ou middleware deve manter os headers 
  de CSP e Anti-Clickjacking (frame-ancestors 'none' para admin, '*' apenas 
  para /embed).

PADRAO DE AUTENTICACAO:
- Use sempre getIronSession com AES-256-GCM para verificar a identidade do 
  usuario no Next.js.

EXEMPLO ERRADO:
```typescript
// app/components/AdminPanel.tsx
import { createClient } from '@supabase/supabase-js'

const supabase = createClient(
  process.env.NEXT_PUBLIC_SUPABASE_URL!,
  process.env.SUPABASE_SERVICE_ROLE_KEY! // VAZAMENTO DE PRIVILEGIO!
)

export function AdminPanel() {
  const deleteUser = async (id: string) => {
    await supabase.from('users').delete().eq('id', id) // Escrita direta!
  }
}
```

EXEMPLO CORRETO:
```typescript
// app/components/AdminPanel.tsx
export function AdminPanel() {
  const deleteUser = async (id: string) => {
    await fetch('/api/admin/users', {
      method: 'DELETE',
      body: JSON.stringify({ userId: id }),
      credentials: 'include'
    })
  }
}

// app/api/admin/users/route.ts
import { getIronSession } from 'iron-session'

export async function DELETE(req: Request) {
  const session = await getIronSession(cookies(), sessionOptions)
  
  if (!session.user?.isAdmin) {
    return Response.json({ error: 'Forbidden' }, { status: 403 })
  }
  
  const supabase = createClient(url, process.env.SUPABASE_SERVICE_ROLE_KEY!)
  // ... delete logic seguro no servidor
}
```