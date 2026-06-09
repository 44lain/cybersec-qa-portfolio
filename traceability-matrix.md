# Matriz de Rastreabilidade

| Achado | Descrição | Caso de Teste | Critério de Validação |
|---------|------------|----------------|----------------------|
| SEC-001 | Exposição de artefato Git | TC-GIT-001 | /.git/HEAD retorna 404 |
| SEC-002 | Exposição de artefato SVN | TC-SVN-001 | /.svn retorna 404 |
| SEC-003 | Headers ausentes | TC-HDR-001 | Headers presentes |
| SEC-004 | WordPress identificado | TC-WP-001 | Hardening validado |
| SEC-005 | Enumeração de usuários | TC-API-003 | Enumeração bloqueada |

## Fluxo de QA

Achado → Correção → Caso de Teste → Reteste → Evidência → Encerramento
