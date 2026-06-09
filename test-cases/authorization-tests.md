# Casos de Teste — Autorização

## Objetivo
Validar controles de autorização e segregação de privilégios.

---

## TC-AUTHZ-001 — Acesso horizontal

**Objetivo:** verificar acesso a recursos de outro usuário.

**Resultado esperado:** acesso negado.

---

## TC-AUTHZ-002 — Escalação vertical

**Objetivo:** usuário comum tentando acessar funções administrativas.

**Resultado esperado:** HTTP 403 ou redirecionamento apropriado.

---

## TC-AUTHZ-003 — Manipulação de parâmetros

**Passos:**
1. Alterar IDs em URLs ou APIs.
2. Tentar acessar registros de terceiros.

**Resultado esperado:** validação de autorização no backend.

---

## TC-AUTHZ-004 — Acesso após logout

**Resultado esperado:** recursos protegidos não acessíveis.

---

## TC-AUTHZ-005 — Controle por função (RBAC)

**Resultado esperado:** permissões compatíveis com o perfil atribuído.
