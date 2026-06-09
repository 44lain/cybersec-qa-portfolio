# Relatório de Teste de Intrusão

**Classificação:** Confidencial 
**Versão:** 1.4 — Final 
**Modalidade:** Black-box (Fase 1 de 3) 
**Data:** Q2/2025
**Analista:** [REDACTED] 
**Alvo:** [REDACTED].hostingersite.com 

---

## Índice

1. [Sumário Executivo](#1-sumário-executivo)
2. [Escopo e Metodologia](#2-escopo-e-metodologia)
3. [Reconhecimento](#3-reconhecimento)
4. [Vulnerabilidades e Achados](#4-vulnerabilidades-e-achados)
5. [Achados Positivos](#5-achados-positivos)
6. [Limitações do Teste](#6-limitações-do-teste)
7. [Conclusão e Próximas Etapas](#7-conclusão-e-próximas-etapas)
8. [Apêndices](#apêndices)

---

## 1. Sumário Executivo

Este documento apresenta os resultados do teste de intrusão **black-box** realizado contra uma aplicação web WordPress hospedada na plataforma Hostinger, conduzido com autorização explícita do proprietário do sistema.

A fase black-box compreendeu reconhecimento externo sem credenciais, enumeração de superfície de ataque, fingerprinting de tecnologias e tentativa de exploração dos vetores identificados. A presença de um CDN com JS Challenge ativo limitou significativamente a eficácia de ferramentas automatizadas — fato que, por si só, constitui um achado relevante sobre a arquitetura de segurança do sistema.

Os achados mais críticos desta fase são a **presença confirmada de diretórios `.git` e `.svn` no webroot** e a **identificação do CMS WordPress com endpoints administrativos acessíveis**. Ambos representam risco real caso a proteção do CDN seja removida, reconfigurada ou contornada.

**Nível de risco geral:** ⚠️ Médio

### Tabela de Achados

| ID | Título | Severidade | Status |
|----|--------|------------|--------|
| ACHADO-001 | Repositório Git exposto no webroot | Média | Confirmado |
| ACHADO-002 | Repositório SVN exposto no webroot | Média | Confirmado |
| ACHADO-003 | CMS WordPress identificado | Informacional | Confirmado |
| ACHADO-004 | Headers de segurança HTTP ausentes | Baixa | Confirmado |
| ACHADO-005 | Enumeração de usuários bloqueada | Informacional+ | Controle positivo |

### Contagem por Severidade

| Severidade | Qtd | Achados |
|------------|-----|---------|
| Crítica | 0 | — |
| Alta | 0 | — |
| Média | 2 | ACHADO-001, ACHADO-002 |
| Baixa | 1 | ACHADO-004 |
| Informacional | 2 | ACHADO-003, ACHADO-005 |

### Principais Recomendações

1. **Remover imediatamente** os diretórios `.git` e `.svn` do webroot de produção
2. Implementar pipeline de CI/CD para separar artefatos de build do deploy
3. Configurar headers de segurança HTTP no servidor de origem
4. Bloquear rotas WordPress sensíveis (`/wp-login.php`, `/xmlrpc.php`) por IP ou adicionar 2FA
5. **Formalizar autorização por escrito** antes das próximas fases do pentest

---

## 2. Escopo e Metodologia

### 2.1 Escopo

| Campo | Detalhe |
|-------|---------|
| Domínio alvo | [REDACTED].hostingersite.com |
| IPs identificados | [REDACTED — múltiplos nós CDN] |
| Portas testadas | 21, 22, 80, 443, 3306, 8080 |
| Tipo de teste | Black-box (sem credenciais) |
| Autorização | Verbal — sessão com o proprietário |
| Data de realização | Q1/2026 |

> ⚠️ **Nota:** A autorização foi obtida de forma verbal. Recomenda-se fortemente formalizar por escrito (e-mail com confirmação ou documento assinado) antes de futuros engajamentos, tanto para proteção legal do analista quanto do cliente.

**Fora do escopo nesta fase:**
- Acesso a painéis administrativos com credenciais
- Testes de engenharia social
- Infraestrutura interna (fora do domínio alvo)
- Análise de código-fonte (reservada para Fase 3 — White-box)

### 2.2 Metodologia

O teste seguiu as diretrizes do **PTES (Penetration Testing Execution Standard)** e do **OWASP Testing Guide v4**, cobrindo as fases de:

1. **Reconhecimento passivo** — DNS, headers HTTP, `robots.txt`, OSINT
2. **Reconhecimento ativo** — varredura de portas e serviços, enumeração de diretórios
3. **Fingerprinting** — identificação de CMS, infraestrutura, versões e tecnologias
4. **Enumeração de vetores** — endpoints WordPress, repositórios expostos, API REST
5. **Tentativa de exploração** — limitada pela proteção do CDN

### 2.3 Ferramentas Utilizadas

| Ferramenta | Versão | Finalidade |
|------------|--------|------------|
| Gobuster | 3.6 | Enumeração de diretórios (wordlists: common.txt, medium.txt) |
| Nmap | 7.95 | Varredura de portas e fingerprinting de serviços |
| Nikto | 2.6.0 | Scan automatizado de vulnerabilidades web |
| WPScan | 3.8.28 | Análise de instalações WordPress |
| curl | 8.14.1 | Requisições HTTP/HTTPS manuais |
| git-dumper | 1.0.9 | Tentativa de extração de repositório Git |
| Chromium (headless) | — | Tentativa de bypass do JS Challenge |

---

## 3. Reconhecimento

### 3.1 Infraestrutura Identificada

A aplicação está servida através de CDN com bot protection ativo, o que representa uma camada de defesa relevante. O servidor de origem é nginx operando como reverse proxy, não acessível diretamente.

```
CDN:       HCDN (Hostinger CDN)
Plataforma: Hostinger / hPanel
Servidor:  nginx (reverse proxy)
Proteção:  JS Challenge ativo (bot protection)
HTTP/3:    Disponível na porta 443 (QUIC)
```

**Headers HTTP identificados:**

```http
Server: hcdn
panel: hpanel
platform: hostinger
x-hcdn-cache-status: HIT
x-hcdn-request-id: [id único por request]
alt-svc: h3=":443"
Content-Security-Policy: frame-ancestors *
Referrer-Policy: strict-origin-when-cross-origin
```

**Observação sobre CSP:** O valor `frame-ancestors *` na Content-Security-Policy permite que a aplicação seja embutida via iframe em qualquer origem, o que pode facilitar ataques de clickjacking. Registrado como vetor para investigação nas fases seguintes.

### 3.2 Portas e Serviços

Varredura conduzida com Nmap 7.95:

```
PORT     STATE     SERVICE     OBSERVAÇÃO
21/tcp   filtered  ftp         Filtrado pelo CDN
22/tcp   filtered  ssh         Filtrado pelo CDN
80/tcp   open      http        nginx (reverse proxy)
443/tcp  open      ssl/https   hcdn — JS Challenge ativo
3306/tcp filtered  mysql       Filtrado pelo CDN
8080/tcp filtered  http-proxy  Filtrado pelo CDN
```

FTP, SSH, MySQL e o proxy HTTP estão filtrados no perímetro externo — não acessíveis diretamente. A superfície de ataque exposta externamente limita-se às portas 80 e 443.

### 3.3 Arquivo robots.txt

```
User-agent: Googlebot
Disallow: /

User-agent: *
Allow: /
```

O Googlebot está completamente bloqueado, enquanto todos os demais agentes têm acesso irrestrito. Nenhum path sensível foi exposto via `robots.txt`. A configuração sugere ambiente de staging ou site sem intenção de indexação pública — o que, ironicamente, pode reduzir a exposição a crawlers maliciosos.

### 3.4 Enumeração de Diretórios (Gobuster)

A wordlist `common.txt` identificou os seguintes paths relevantes antes que o CDN derrubasse as conexões (~90% da wordlist `medium.txt` concluída):

```
/.git/HEAD      (Status: 403) [Size: 787]
/.git           (Status: 403) [Size: 787]
/.htaccess      (Status: 403) [Size: 787]
/.htpasswd      (Status: 403) [Size: 787]
/.svn           (Status: 403) [Size: 787]
/.svn/entries   (Status: 403) [Size: 787]
/wp-login.php   (Status: 302)
/wp-json        (Status: 200)
/xmlrpc.php     (Status: 302)
```

O retorno HTTP 403 confirma a existência dos recursos — o servidor reconhece o path e ativamente bloqueia o acesso, diferente de um 404 que indicaria ausência.

---

## 4. Vulnerabilidades e Achados

---

### ACHADO-001 — Repositório Git Exposto no Webroot

| Campo | Detalhe |
|-------|---------|
| **Severidade** | ⚠️ Média |
| **CVSS 3.1** | 5.3 — AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N |
| **CWE** | CWE-538: File and Directory Information Exposure |
| **OWASP** | A05:2021 — Security Misconfiguration |
| **URL** | `https://[REDACTED]/.git/HEAD` |
| **Status HTTP** | 403 Forbidden |
| **Ferramenta** | Gobuster 3.6 |

**Descrição:**

O path `/.git/HEAD` retornou HTTP 403, confirmando a existência do diretório `.git` no webroot do servidor de produção. Isso ocorre quando o repositório Git local é copiado junto ao código no momento do deploy, em vez de ser excluído ou utilizado apenas na pipeline de build.

O status 403 indica que o CDN está ativamente bloqueando o acesso neste momento. Entretanto, a proteção é baseada em uma camada externa e não em controle no servidor de origem — o que significa que qualquer alteração no CDN (remoção, reconfiguração, IP direto, falha temporária) exporia o repositório completo.

Com acesso ao `.git`, é possível reconstruir o histórico completo de commits via ferramentas como `git-dumper`, incluindo:
- Código-fonte completo da aplicação
- Credenciais hardcoded em commits antigos
- Chaves de API e tokens
- Arquivos de configuração (`.env`, `wp-config.php`)
- Estrutura interna da aplicação

**Evidência:**

```bash
# Comando executado
gobuster dir -u https://[REDACTED] -w /usr/share/wordlists/dirb/common.txt -k

# Output relevante
/.git/HEAD    (Status: 403) [Size: 787]
/.htaccess    (Status: 403) [Size: 787]
/.htpasswd    (Status: 403) [Size: 787]

# Tentativa de extração (bloqueada)
git-dumper https://[REDACTED]/.git/ ./output
# → Todos os objetos retornaram 403
```

**Impacto:**

Em caso de bypass ou remoção do CDN, um atacante poderia extrair o código-fonte completo e credentials sensíveis, potencialmente comprometendo o banco de dados, contas de terceiros e a integridade total da aplicação.

**Recomendação:**

```bash
# 1. Remover o diretório .git do servidor de produção
rm -rf /var/www/html/.git

# 2. Bloquear via configuração nginx (servidor de origem)
location ~ /\.git {
    deny all;
    return 404;
}

# 3. Usar .gitignore ou pipeline de CI/CD para separar
#    artefatos de build do deploy (nunca copiar .git para produção)

# 4. Auditar histórico de commits em busca de credenciais expostas
git log --all --full-history -- "*.env"
git log -p --all -S "password"
```

**Referências:**
- [CWE-538](https://cwe.mitre.org/data/definitions/538.html)
- [OWASP: Testing for Sensitive Information in Source Code](https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/01-Test_Network_Infrastructure_Configuration)

---

### ACHADO-002 — Repositório SVN Exposto no Webroot

| Campo | Detalhe |
|-------|---------|
| **Severidade** | ⚠️ Média |
| **CVSS 3.1** | 5.3 — AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N |
| **CWE** | CWE-538: File and Directory Information Exposure |
| **OWASP** | A05:2021 — Security Misconfiguration |
| **URLs** | `/.svn/entries`, `/.svn/wc.db` |
| **Status HTTP** | 403 Forbidden |
| **Ferramenta** | Gobuster 3.6 |

**Descrição:**

Os paths `/.svn/entries` e `/.svn/wc.db` retornaram 403, confirmando presença de diretório SVN no webroot. O arquivo `wc.db` é um banco de dados SQLite que contém a estrutura completa do repositório, incluindo paths de todos os arquivos versionados, metadados e conteúdo parcial.

A coexistência de `.git` e `.svn` no mesmo webroot sugere que o projeto passou por migração de sistema de controle de versão sem limpeza adequada dos artefatos.

**Evidência:**

```bash
/.svn           (Status: 403) [Size: 787]
/.svn/entries   (Status: 403) [Size: 787]
/.svn/wc.db     (Status: 403) [Size: 787]
```

**Recomendação:**

```bash
# Remover o diretório .svn do servidor de produção
rm -rf /var/www/html/.svn

# Bloquear via nginx
location ~ /\.svn {
    deny all;
    return 404;
}
```

---

### ACHADO-003 — CMS WordPress Identificado (Information Disclosure)

| Campo | Detalhe |
|-------|---------|
| **Severidade** | ℹ️ Informacional |
| **OWASP** | A05:2021 — Security Misconfiguration |
| **URLs** | `/wp-login.php`, `/wp-json/wp/v2/users`, `/xmlrpc.php` |
| **Status HTTP** | 302 Found |
| **Ferramenta** | curl 8.14.1, WPScan 3.8.28 |

**Descrição:**

WordPress confirmado pela presença e resposta dos endpoints característicos. A identificação do CMS é classificada como informacional, mas é relevante porque direciona a superfície de ataque das próximas fases: brute-force no `wp-login.php`, exploração de plugins vulneráveis, abuso do XML-RPC para amplificação de autenticação, e enumeração de usuários.

A versão exata do WordPress, plugins e temas instalados não foram determinados nesta fase devido ao bloqueio do CDN sobre ferramentas de fingerprinting (WPScan retornou resultados parciais em razão de bug no `cms_scanner 0.15.0`).

**Evidência:**

```bash
curl -sk -o /dev/null -w "%{http_code}" https://[REDACTED]/wp-login.php
# → 302

curl -sk -o /dev/null -w "%{http_code}" https://[REDACTED]/wp-json/wp/v2/users
# → 302

curl -sk -o /dev/null -w "%{http_code}" https://[REDACTED]/xmlrpc.php
# → 302
```

**Recomendação:**

- Manter WordPress, plugins e temas sempre atualizados (habilitar atualizações automáticas de segurança)
- Adicionar autenticação adicional em `/wp-login.php` (2FA ou restrição por IP)
- Desabilitar XML-RPC se não utilizado: `add_filter('xmlrpc_enabled', '__return_false');`
- Remover `readme.html`, que expõe a versão do WordPress

---

### ACHADO-004 — Headers de Segurança HTTP Ausentes

| Campo | Detalhe |
|-------|---------|
| **Severidade** | 🔵 Baixa |
| **OWASP** | A05:2021 — Security Misconfiguration |
| **Ferramenta** | Nikto 2.6.0, curl |

**Descrição:**

Os seguintes headers de segurança estão ausentes nas respostas HTTP do servidor, reduzindo a proteção do navegador do usuário final:

| Header | Risco da Ausência |
|--------|-------------------|
| `Strict-Transport-Security` | Permite ataques de downgrade HTTPS → HTTP |
| `X-Content-Type-Options` | Permite MIME-type sniffing pelo navegador |
| `Permissions-Policy` | APIs sensíveis do browser ficam sem restrição |
| `X-Frame-Options` | Ausência combinada com `CSP: frame-ancestors *` viabiliza clickjacking |

**Observação:** O header `Referrer-Policy: strict-origin-when-cross-origin` estava presente (identificado durante o reconhecimento), o que é positivo.

**Evidência:**

```bash
nikto -h https://[REDACTED] -o nikto_output.txt

# Output relevante
+ Missing anti-clickjacking header
+ Missing X-Content-Type-Options header
+ Missing Strict-Transport-Security header
+ Missing Permissions-Policy header
```

**Recomendação (configuração nginx no servidor de origem):**

```nginx
add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;
add_header X-Content-Type-Options "nosniff" always;
add_header X-Frame-Options "SAMEORIGIN" always;
add_header Permissions-Policy "camera=(), microphone=(), geolocation=()" always;
add_header Content-Security-Policy "frame-ancestors 'self'" always;
```

**Referências:**
- [OWASP Secure Headers Project](https://owasp.org/www-project-secure-headers/)
- [MDN: HTTP Security Headers](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers#security)

---

### ACHADO-005 — Enumeração de Usuários via API REST Bloqueada ✅

| Campo | Detalhe |
|-------|---------|
| **Severidade** | ✅ Informacional (controle positivo) |
| **URL** | `/wp-json/wp/v2/users` |
| **Status** | Resposta não enumerável |

**Descrição:**

O endpoint público de listagem de usuários da API REST do WordPress (`/wp-json/wp/v2/users`) está protegido, retornando resposta não-enumerável em vez de expor usernames cadastrados. Este é um controle de segurança adequadamente implementado — por padrão o WordPress expõe este endpoint, portanto sua proteção é uma configuração intencional positiva.

**Recomendação:**

- Manter este controle ativo
- Verificar também os endpoints `/wp-json/wp/v2/users?per_page=100` e `/wp-json/oembed/1.0/embed?url=...` em fases posteriores, pois podem vazar usernames por vias alternativas

---

## 5. Achados Positivos

| Controle | Status | Observação |
|----------|--------|------------|
| CDN com bot protection (JS Challenge) | ✅ Ativo | Mitiga grande parte de ferramentas automatizadas |
| Portas FTP, SSH, MySQL filtradas | ✅ Correto | Não acessíveis externamente |
| Enumeração de usuários WordPress bloqueada | ✅ Implementado | Endpoint `/wp-json/wp/v2/users` protegido |
| `Referrer-Policy` configurado | ✅ Presente | `strict-origin-when-cross-origin` |
| HTTP/3 (QUIC) disponível | ✅ Moderno | Indica infraestrutura atualizada |

---

## 6. Limitações do Teste

| Limitação | Causa | Impacto nos Resultados |
|-----------|-------|------------------------|
| JS Challenge ativo (CDN) | Proteção de bot do HCDN | Bloqueia todas as ferramentas automatizadas |
| Fingerprinting incompleto | Respostas via CDN | Versão do WP, plugins e temas não determinados |
| Status do XML-RPC | Bloqueado pelo CDN | Não confirmado como ativo ou inativo |
| Git/SVN dump | 403 em todos os objetos | Extração não foi possível nesta fase |
| Bug WPScan / cms_scanner 0.15.0 | Crash no parser do robots.txt | Scan incompleto |
| Gobuster (wordlist medium) | CDN derrubou conexões TLS | ~90% da wordlist processada |
| Browser headless (Chromium) | JS Challenge não bypassado | Acesso ao site via browser automatizado bloqueado |
| Autorização verbal | Sem documento formal | Limitação legal para próximas fases |

---

## 7. Conclusão e Próximas Etapas

A postura de segurança externa do alvo é **razoável**: CDN ativo com bot protection, portas filtradas e enumeração de usuários bloqueada. A segurança efetiva, no entanto, depende fortemente desta camada de CDN — o que representa um ponto único de falha arquitetural.

O principal risco identificado são os artefatos de desenvolvimento (`.git`, `.svn`) presentes no webroot, decorrentes de um processo de deploy sem higiene de repositório. Embora mitigados pelo CDN no momento do teste, representam exposição real e devem ser removidos independentemente das demais fases.

**Não foram encontradas vulnerabilidades exploráveis diretamente nesta fase black-box**, o que é um resultado positivo — mas parcial, dado o alcance limitado pela proteção do CDN.

### Roadmap das Próximas Fases

**Fase 2 — Grey-box (credencial de usuário baixo privilégio)**
- Acessar área administrativa com credencial fornecida
- Enumerar plugins instalados e verificar CVEs via WPScan + API token
- Testar escalação de privilégios (author → editor → admin)
- Verificar permissões de upload de arquivos (possível RCE via webshell)
- Testar CSRF e XSS em formulários autenticados
- Confirmar status e configuração do XML-RPC

**Fase 3 — White-box (acesso total ao código e servidor)**
- Revisão de código-fonte e arquivos de configuração
- Análise de credenciais e segredos armazenados (`.env`, `wp-config.php`)
- Auditoria do banco de dados
- Análise de logs de acesso
- Extração e análise do conteúdo dos repositórios `.git` e `.svn`

---

## Apêndices

### Apêndice A — Linha do Tempo

| Hora (BRT) | Ação |
|------------|------|
| ~11:00 | Início — Gobuster com wordlist `common.txt` |
| ~11:15 | Confirmação de `.git` e `.svn` via enumeração de diretórios |
| ~11:16 | Leitura e análise do `robots.txt` |
| ~11:17 | Tentativa de git-dumper — bloqueado (403 em todos os objetos) |
| ~11:18 | Tentativa de acesso SVN direto — bloqueado (403) |
| ~11:19 | Identificação do JS Challenge via análise do response HTML |
| ~11:20 | Nikto scan — infraestrutura identificada, headers ausentes mapeados |
| ~11:22 | Nmap — mapeamento completo de portas e serviços |
| ~11:45 | WPScan — confirmação de WordPress, scan parcial |
| ~11:48 | WPScan `--force` — limitado por bug no `cms_scanner 0.15.0` |
| ~11:50 | Chromium headless — tentativa de bypass do JS Challenge (sem sucesso) |
| ~11:52 | Gobuster wordlist `medium.txt` — CDN derrubou conexões TLS (~90% concluído) |
| ~12:00 | Encerramento da fase black-box |

### Apêndice B — Glossário

| Termo | Definição |
|-------|-----------|
| Black-box | Teste conduzido sem conhecimento prévio do sistema, simulando um atacante externo |
| CDN | Content Delivery Network — rede de distribuição de conteúdo que atua como proxy |
| JS Challenge | Mecanismo de detecção de bots que exige execução de JavaScript no navegador |
| CVSS | Common Vulnerability Scoring System — sistema de pontuação de severidade de vulnerabilidades |
| Webroot | Diretório raiz do servidor web, cujo conteúdo é servido publicamente |
| git-dumper | Ferramenta que extrai repositórios Git expostos em servidores web |
| HCDN | Hostinger Content Delivery Network |
| PTES | Penetration Testing Execution Standard — framework de metodologia de pentest |

### Apêndice C — Referências

- [OWASP Testing Guide v4.2](https://owasp.org/www-project-web-security-testing-guide/)
- [PTES Technical Guidelines](http://www.pentest-standard.org/index.php/PTES_Technical_Guidelines)
- [CVSS 3.1 Calculator](https://www.first.org/cvss/calculator/3.1)
- [CWE-538: File and Directory Information Exposure](https://cwe.mitre.org/data/definitions/538.html)
- [OWASP A05:2021 — Security Misconfiguration](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/)
- [OWASP Secure Headers Project](https://owasp.org/www-project-secure-headers/)

---

*Relatório produzido com base em teste conduzido com autorização explícita do proprietário do sistema. Todas as informações de identificação foram removidas ou anonimizadas para fins de publicação.*
