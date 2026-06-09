# Modelo de Rastreabilidade para Achados

## SEC-001 — Exposição de Artefato Git

### Status
Confirmado

### Reproduzível
Sim

### Impacto de Negócio
Médio

### Evidência Objetiva
Requisição para /.git/HEAD retornando HTTP 403.

### Caso de Teste Relacionado
TC-GIT-001

### Critérios de Validação da Correção

- /.git/HEAD deve retornar 404
- Nenhum objeto Git acessível externamente
- Scan de validação executado após correção
- Evidências registradas em reteste

### Status de Correção

| Data | Responsável | Resultado |
|--------|-------------|------------|
| Pendente | N/A | Aberto |
