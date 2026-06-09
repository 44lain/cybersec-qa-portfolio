# Casos de Teste — API Security

## Objetivo
Validar controles de segurança em APIs REST.

---

## TC-API-001 — Autenticação obrigatória

**Resultado esperado:** endpoints protegidos retornam 401 quando não autenticados.

---

## TC-API-002 — Autorização por recurso

**Resultado esperado:** usuário não acessa objetos de terceiros.

---

## TC-API-003 — Enumeração de usuários

**Referência:** alinhado ao achado positivo identificado durante a avaliação WordPress.

**Resultado esperado:** API não expõe usuários ou informações sensíveis.

---

## TC-API-004 — Rate Limiting

**Passos:**
1. Enviar múltiplas requisições em curto intervalo.

**Resultado esperado:** limitação de taxa aplicada.

---

## TC-API-005 — Validação de entrada

**Resultado esperado:** entradas inválidas rejeitadas sem erro interno.

---

## TC-API-006 — Exposição de informações

**Resultado esperado:** respostas não revelam stack traces, versões ou segredos.

---

## TC-API-007 — Headers de segurança

**Resultado esperado:** presença de HSTS, CSP, Referrer-Policy e X-Content-Type-Options quando aplicável.
