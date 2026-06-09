# Casos de Teste — Autenticação

## Objetivo
Validar controles de autenticação em aplicações web, com foco em prevenção de acesso não autorizado, enumeração de usuários e abuso de credenciais.

---

## TC-AUTH-001 — Login com credenciais válidas

| Campo | Detalhe |
|---------|---------|
| ID | TC-AUTH-001 |
| Categoria | Authentication |
| Severidade esperada | Alta |

**Resultado esperado:** usuário autenticado com sucesso e sessão criada.

---

## TC-AUTH-002 — Login com senha incorreta

**Resultado esperado:** acesso negado sem revelar se o usuário existe.

---

## TC-AUTH-003 — Enumeração de usuários

**Objetivo:** verificar diferenças entre respostas para usuário inexistente e senha incorreta.

**Resultado esperado:** mensagens genéricas e indistinguíveis.

---

## TC-AUTH-004 — Proteção contra brute force

**Passos:**
1. Executar múltiplas tentativas consecutivas.
2. Observar bloqueio, atraso ou rate limiting.

**Resultado esperado:** mecanismo de mitigação ativo.

---

## TC-AUTH-005 — Logout

**Resultado esperado:** sessão invalidada e reutilização do token impossível.

---

## TC-AUTH-006 — Política de senha

**Resultado esperado:** requisitos mínimos de complexidade aplicados.
