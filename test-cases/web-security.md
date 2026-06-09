# Casos de Teste — Segurança Web
## Baseado em Avaliação Black-box: WordPress em CDN

**Versão:** 1.4 
**Framework:** OWASP Testing Guide v4.2 
**Ambiente de referência:** WordPress hospedado em CDN com bot protection 
**Analista:** [REDACTED] 

---

## Índice

- [TC-RECON — Reconhecimento e Footprint](#tc-recon--reconhecimento-e-footprint)
- [TC-REPO — Exposição de Repositórios VCS](#tc-repo--exposição-de-repositórios-vcs)
- [TC-WP — WordPress Security](#tc-wp--wordpress-security)
- [TC-HDR — Headers de Segurança HTTP](#tc-hdr--headers-de-segurança-http)
- [TC-NET — Configuração de Rede e Portas](#tc-net--configuração-de-rede-e-portas)
- [TC-CDN — Bypass e Dependência de CDN](#tc-cdn--bypass-e-dependência-de-cdn)
- [TC-API — API REST WordPress](#tc-api--api-rest-wordpress)

---

## Convenções

### Severidade esperada do achado
| Label | Descrição |
|-------|-----------|
| 🔴 Crítica | Exploração trivial com impacto total |
| 🟠 Alta | Exploração viável com impacto significativo |
| 🟡 Média | Exploração moderada ou impacto limitado |
| 🔵 Baixa | Difícil de explorar ou impacto mínimo |
| ⚪ Info | Sem risco direto, relevante para postura geral |

### Resultado do teste
| Label | Descrição |
|-------|-----------|
| ✅ PASS | Controle implementado corretamente |
| ❌ FAIL | Vulnerabilidade confirmada |
| ⚠️ PARTIAL | Controle parcialmente implementado |
| ⏭️ SKIP | Fora de escopo ou bloqueado |

---

## TC-RECON — Reconhecimento e Footprint

### TC-RECON-001 — Enumeração de Tecnologias via Headers HTTP

| Campo | Detalhe |
|-------|---------|
| **ID** | TC-RECON-001 |
| **Categoria** | Information Disclosure |
| **OWASP** | OTG-INFO-002 |
| **Severidade esperada** | ⚪ Info |
| **Pré-condição** | Acesso HTTP/HTTPS ao alvo |

**Objetivo:** Verificar se os headers HTTP expõem informações desnecessárias sobre a infraestrutura (versão de servidor, plataforma, tecnologias).

**Passos:**
```bash
# 1. Capturar todos os headers de resposta
curl -sk -D - https://ALVO/ -o /dev/null

# 2. Verificar especificamente
curl -sk -I https://ALVO/ | grep -iE "server|x-powered-by|platform|panel"

# 3. Verificar header via requisição OPTIONS
curl -sk -X OPTIONS -D - https://ALVO/ -o /dev/null
```

**Critério PASS:** Headers não expõem versões de software ou tecnologias internas.  
**Critério FAIL:** `Server: nginx/1.18.0`, `X-Powered-By: PHP/8.1`, ou similares com versão exposta.

---

### TC-RECON-002 — Análise de robots.txt para Paths Sensíveis

| Campo | Detalhe |
|-------|---------|
| **ID** | TC-RECON-002 |
| **Categoria** | Information Disclosure |
| **OWASP** | OTG-INFO-001 |
| **Severidade esperada** | ⚪ Info a 🔵 Baixa |
| **Pré-condição** | Acesso HTTP ao alvo |

**Objetivo:** Verificar se `robots.txt` expõe paths administrativos, de backup ou sensíveis inadvertidamente.

**Passos:**
```bash
# 1. Recuperar robots.txt
curl -sk https://ALVO/robots.txt

# 2. Extrair todos os Disallow e Allow
curl -sk https://ALVO/robots.txt | grep -iE "^(dis)?allow"

# 3. Testar paths listados no robots.txt
# Para cada path identificado, verificar acessibilidade
```

**Critério PASS:** Nenhum path administrativo ou sensível exposto; ou arquivo ausente.  
**Critério FAIL:** Paths como `/admin`, `/backup`, `/config`, `/api` expostos no `Disallow`.

---

### TC-RECON-003 — Enumeração de Diretórios e Arquivos

| Campo | Detalhe |
|-------|---------|
| **ID** | TC-RECON-003 |
| **Categoria** | Information Disclosure / Misconfiguration |
| **OWASP** | OTG-CONFIG-001 |
| **Severidade esperada** | 🟡 Média a 🟠 Alta |
| **Pré-condição** | Acesso HTTP; ferramenta de wordlist disponível |

**Objetivo:** Identificar diretórios e arquivos não linkados publicamente que possam expor funcionalidades administrativas, backups ou artefatos de desenvolvimento.

**Passos:**
```bash
# 1. Enumeração básica
gobuster dir -u https://ALVO -w /usr/share/wordlists/dirb/common.txt -k -o gobuster_common.txt

# 2. Enumeração estendida (mais agressiva — cuidado com rate limiting)
gobuster dir -u https://ALVO -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt \
  -k -t 10 --delay 100ms -o gobuster_medium.txt

# 3. Buscar por extensões sensíveis
gobuster dir -u https://ALVO -w wordlist.txt -x php,bak,log,sql,env,config -k

# 4. Verificar listagem de diretório
curl -sk https://ALVO/uploads/ | grep -i "index of"
```

**Critério PASS:** Apenas paths esperados encontrados; sem diretórios sensíveis acessíveis.  
**Critério FAIL:** `.git/`, `.svn/`, `/backup/`, `/.env`, `/config.php.bak` ou similares retornando 200 ou 403.

---

## TC-REPO — Exposição de Repositórios VCS

### TC-REPO-001 — Verificação de Diretório .git Exposto

| Campo | Detalhe |
|-------|---------|
| **ID** | TC-REPO-001 |
| **Categoria** | Sensitive Data Exposure / Misconfiguration |
| **CWE** | CWE-538 |
| **OWASP** | A05:2021 |
| **Severidade esperada** | 🟡 Média a 🟠 Alta |
| **Pré-condição** | Acesso HTTP ao alvo |

**Objetivo:** Verificar se o diretório `.git` está acessível no webroot, confirmando exposição potencial do código-fonte.

**Passos:**
```bash
# 1. Verificar existência do HEAD (arquivo sempre presente em repos Git)
curl -sk -o /dev/null -w "%{http_code}" https://ALVO/.git/HEAD
# 200 = exposto / 403 = existe mas bloqueado / 404 = não existe

# 2. Tentar ler o HEAD diretamente
curl -sk https://ALVO/.git/HEAD

# 3. Verificar outros arquivos do repositório
curl -sk -o /dev/null -w "%{http_code}" https://ALVO/.git/config
curl -sk -o /dev/null -w "%{http_code}" https://ALVO/.git/COMMIT_EDITMSG

# 4. Se acessível (200), tentar extração completa
git-dumper https://ALVO/.git/ ./git_dump_output
```

**Critério PASS:** `/.git/HEAD` retorna 404 (não existe) ou CDN/servidor retorna 404 negando existência.  
**Critério FAIL (crítico):** `/.git/HEAD` retorna 200 com conteúdo — repositório totalmente acessível.  
**Critério FAIL (médio):** `/.git/HEAD` retorna 403 — repositório existe mas está parcialmente protegido por camada externa.

> ⚠️ **Nota:** 403 confirma a presença do diretório. O controle ideal retorna 404, negando a existência do recurso e dificultando o mapeamento da superfície de ataque.

---

### TC-REPO-002 — Verificação de Diretório .svn Exposto

| Campo | Detalhe |
|-------|---------|
| **ID** | TC-REPO-002 |
| **Categoria** | Sensitive Data Exposure / Misconfiguration |
| **CWE** | CWE-538 |
| **OWASP** | A05:2021 |
| **Severidade esperada** | 🟡 Média |
| **Pré-condição** | Acesso HTTP ao alvo |

**Objetivo:** Verificar se artefatos do SVN estão acessíveis no webroot.

**Passos:**
```bash
# 1. Verificar arquivo entries (SVN < 1.7)
curl -sk -o /dev/null -w "%{http_code}" https://ALVO/.svn/entries

# 2. Verificar wc.db (SVN >= 1.7 — banco SQLite com estrutura completa)
curl -sk -o /dev/null -w "%{http_code}" https://ALVO/.svn/wc.db

# 3. Se acessível, baixar e inspecionar
curl -sk https://ALVO/.svn/wc.db -o wc.db
sqlite3 wc.db "SELECT * FROM NODES LIMIT 20;"
```

**Critério PASS:** Todos os paths retornam 404.  
**Critério FAIL:** Qualquer retorno diferente de 404.

---

### TC-REPO-003 — Verificação de Outros Artefatos de Desenvolvimento

| Campo | Detalhe |
|-------|---------|
| **ID** | TC-REPO-003 |
| **Categoria** | Sensitive Data Exposure |
| **Severidade esperada** | 🟡 Média a 🟠 Alta |
| **Pré-condição** | Acesso HTTP ao alvo |

**Objetivo:** Identificar outros artefatos de desenvolvimento expostos inadvertidamente.

**Passos:**
```bash
# Arquivos de configuração e ambiente
curl -sk -o /dev/null -w "%-30s %s\n" https://ALVO/.env "%{http_code}"
curl -sk -o /dev/null -w "%-30s %s\n" https://ALVO/.env.local "%{http_code}"
curl -sk -o /dev/null -w "%-30s %s\n" https://ALVO/.env.production "%{http_code}"
curl -sk -o /dev/null -w "%-30s %s\n" https://ALVO/wp-config.php.bak "%{http_code}"
curl -sk -o /dev/null -w "%-30s %s\n" https://ALVO/wp-config-sample.php "%{http_code}"

# Arquivos de backup
curl -sk -o /dev/null -w "%-30s %s\n" https://ALVO/backup.zip "%{http_code}"
curl -sk -o /dev/null -w "%-30s %s\n" https://ALVO/backup.sql "%{http_code}"
curl -sk -o /dev/null -w "%-30s %s\n" https://ALVO/db.sql "%{http_code}"

# Logs
curl -sk -o /dev/null -w "%-30s %s\n" https://ALVO/error.log "%{http_code}"
curl -sk -o /dev/null -w "%-30s %s\n" https://ALVO/debug.log "%{http_code}"
```

**Critério PASS:** Todos os paths retornam 404.  
**Critério FAIL:** Qualquer arquivo sensível retornando 200.

---

## TC-WP — WordPress Security

### TC-WP-001 — Exposição da Versão do WordPress

| Campo | Detalhe |
|-------|---------|
| **ID** | TC-WP-001 |
| **Categoria** | Information Disclosure |
| **OWASP** | A05:2021 |
| **Severidade esperada** | 🔵 Baixa a ⚪ Info |
| **Pré-condição** | Site WordPress acessível |

**Objetivo:** Verificar se a versão do WordPress está exposta de forma que facilite ataques direcionados.

**Passos:**
```bash
# 1. Verificar readme.html
curl -sk https://ALVO/readme.html | grep -i "version\|wordpress"

# 2. Verificar meta generator no HTML
curl -sk https://ALVO/ | grep -i "generator"

# 3. Verificar via feed RSS
curl -sk https://ALVO/?feed=rss2 | grep -i "generator"

# 4. Verificar via WPScan (se disponível API token)
wpscan --url https://ALVO --api-token SEU_TOKEN --enumerate vp,vt,u
```

**Critério PASS:** Versão não exposta por nenhuma via.  
**Critério FAIL:** Versão identificável via `readme.html`, meta tag, ou feed.

---

### TC-WP-002 — Proteção do wp-login.php

| Campo | Detalhe |
|-------|---------|
| **ID** | TC-WP-002 |
| **Categoria** | Authentication |
| **OWASP** | OTG-AUTHN-003 |
| **Severidade esperada** | 🟡 Média |
| **Pré-condição** | Site WordPress acessível |

**Objetivo:** Verificar se o endpoint de login possui proteções contra brute force e acesso não autorizado.

**Passos:**
```bash
# 1. Verificar acessibilidade do wp-login
curl -sk -o /dev/null -w "%{http_code}" https://ALVO/wp-login.php

# 2. Verificar se há rate limiting (múltiplas tentativas)
for i in {1..5}; do
  curl -sk -o /dev/null -w "%{http_code} " -X POST https://ALVO/wp-login.php \
    -d "log=admin&pwd=wrongpassword&wp-submit=Log+In"
  sleep 0.5
done

# 3. Verificar mensagens de erro (user enumeration via login)
curl -sk -X POST https://ALVO/wp-login.php \
  -d "log=admin&pwd=wrongpassword" | grep -i "error\|invalid"

# 4. Verificar se há CAPTCHA ou 2FA visível no formulário
curl -sk https://ALVO/wp-login.php | grep -iE "captcha|recaptcha|2fa|totp"
```

**Critério PASS:** Login retorna 403 ou 404 para IPs não autorizados; ou rate limiting ativo; ou 2FA implementado.  
**Critério FAIL:** Login acessível sem proteção adicional, sem rate limiting, com mensagens que diferenciam usuário inválido de senha inválida.

---

### TC-WP-003 — Status e Segurança do XML-RPC

| Campo | Detalhe |
|-------|---------|
| **ID** | TC-WP-003 |
| **Categoria** | Attack Surface Reduction |
| **OWASP** | A05:2021 |
| **Severidade esperada** | 🟡 Média |
| **Pré-condição** | Site WordPress acessível |

**Objetivo:** Verificar se o XML-RPC está habilitado e se pode ser abusado para amplificação de autenticação (bruteforce via `system.multicall`).

**Passos:**
```bash
# 1. Verificar se XML-RPC está ativo
curl -sk -o /dev/null -w "%{http_code}" https://ALVO/xmlrpc.php

# 2. Testar chamada de método (se acessível)
curl -sk -X POST https://ALVO/xmlrpc.php \
  -H "Content-Type: text/xml" \
  -d '<?xml version="1.0"?><methodCall><methodName>system.listMethods</methodName></methodCall>'

# 3. Testar multicall (bruteforce amplificado)
curl -sk -X POST https://ALVO/xmlrpc.php \
  -H "Content-Type: text/xml" \
  -d '<?xml version="1.0"?><methodCall><methodName>system.multicall</methodName>
  <params><param><value><array><data>
    <value><struct><member><name>methodName</name>
    <value><string>wp.getUsersBlogs</string></value></member>
    <member><name>params</name><value><array><data>
    <value><array><data>
    <value><string>admin</string></value>
    <value><string>password1</string></value>
    </data></array></value></data></array></value></member></struct></value>
  </data></array></value></param></params></methodCall>'
```

**Critério PASS:** XML-RPC retorna 404 (desabilitado) ou 403 sem conteúdo.  
**Critério FAIL:** XML-RPC retorna 200 com lista de métodos disponíveis; multicall aceito.

---

### TC-WP-004 — Enumeração de Usuários via Author Archive

| Campo | Detalhe |
|-------|---------|
| **ID** | TC-WP-004 |
| **Categoria** | Information Disclosure |
| **OWASP** | OTG-IDENT-004 |
| **Severidade esperada** | 🔵 Baixa a 🟡 Média |
| **Pré-condição** | Site WordPress com posts publicados |

**Objetivo:** Verificar se usernames WordPress podem ser enumerados via rotas de author archive.

**Passos:**
```bash
# 1. Tentar enumerar por ID numérico
for id in 1 2 3 4 5; do
  response=$(curl -sk -o /dev/null -w "%{redirect_url}" https://ALVO/?author=$id)
  echo "Author ID $id → $response"
done

# 2. Verificar se o redirect expõe o username
# Exemplo de FAIL: /?author=1 → /author/admin/

# 3. Verificar via API REST
curl -sk https://ALVO/wp-json/wp/v2/users | python3 -m json.tool 2>/dev/null | grep -i "name\|slug"

# 4. Via oembed
curl -sk "https://ALVO/wp-json/oembed/1.0/embed?url=https://ALVO/" | grep -i "author"
```

**Critério PASS:** Nenhuma das rotas expõe usernames.  
**Critério FAIL:** `/?author=1` redireciona para `/author/admin/`, expondo o username.

---

## TC-HDR — Headers de Segurança HTTP

### TC-HDR-001 — Verificação Completa de Headers de Segurança

| Campo | Detalhe |
|-------|---------|
| **ID** | TC-HDR-001 |
| **Categoria** | Security Misconfiguration |
| **OWASP** | A05:2021 |
| **Referência** | OWASP Secure Headers Project |
| **Severidade esperada** | 🔵 Baixa |
| **Pré-condição** | Acesso HTTP/HTTPS ao alvo |

**Objetivo:** Verificar se os headers de segurança HTTP recomendados estão presentes e corretamente configurados.

**Passos:**
```bash
# 1. Capturar todos os headers
curl -sk -D - https://ALVO/ -o /dev/null > headers.txt

# 2. Verificar cada header crítico
echo "=== Security Headers Check ==="
for header in \
  "Strict-Transport-Security" \
  "X-Content-Type-Options" \
  "X-Frame-Options" \
  "Content-Security-Policy" \
  "Permissions-Policy" \
  "Referrer-Policy" \
  "Cross-Origin-Opener-Policy" \
  "Cross-Origin-Resource-Policy"; do
    result=$(grep -i "$header" headers.txt)
    if [ -z "$result" ]; then
      echo "❌ MISSING: $header"
    else
      echo "✅ PRESENT: $result"
    fi
done
```

**Critério PASS por header:**

| Header | Valor Mínimo Aceitável |
|--------|------------------------|
| `Strict-Transport-Security` | `max-age=31536000` |
| `X-Content-Type-Options` | `nosniff` |
| `X-Frame-Options` | `SAMEORIGIN` ou substituído por CSP `frame-ancestors` |
| `Content-Security-Policy` | Presente com diretivas relevantes (não `frame-ancestors *`) |
| `Permissions-Policy` | Presente |
| `Referrer-Policy` | `strict-origin-when-cross-origin` ou mais restritivo |

**Critério FAIL:** Qualquer header crítico ausente ou com valor inseguro (ex: `Content-Security-Policy: frame-ancestors *`).

---

### TC-HDR-002 — Verificação de HSTS e Preloading

| Campo | Detalhe |
|-------|---------|
| **ID** | TC-HDR-002 |
| **Categoria** | Transport Security |
| **Severidade esperada** | 🔵 Baixa |
| **Pré-condição** | Site HTTPS |

**Passos:**
```bash
# 1. Verificar HSTS
curl -sk -D - https://ALVO/ -o /dev/null | grep -i "strict-transport"

# 2. Verificar redirect HTTP → HTTPS
curl -sk -o /dev/null -w "%{http_code} → %{redirect_url}" http://ALVO/

# 3. Verificar inclusão no preload list
# https://hstspreload.org/?domain=ALVO
```

**Critério PASS:** HSTS presente com `max-age >= 31536000`; HTTP redireciona para HTTPS com 301.  
**Critério FAIL:** HSTS ausente; HTTP acessível sem redirect.

---

## TC-NET — Configuração de Rede e Portas

### TC-NET-001 — Varredura de Portas Expostas

| Campo | Detalhe |
|-------|---------|
| **ID** | TC-NET-001 |
| **Categoria** | Attack Surface Reduction |
| **Severidade esperada** | 🟡 Média a 🟠 Alta |
| **Pré-condição** | Permissão para varredura de rede |

**Objetivo:** Mapear serviços expostos externamente e verificar se portas sensíveis estão filtradas.

**Passos:**
```bash
# 1. Varredura básica de portas comuns
nmap -sV -p 21,22,80,443,3306,5432,6379,8080,8443,9200,27017 ALVO

# 2. Varredura completa (top 1000 portas)
nmap -sV --top-ports 1000 ALVO

# 3. Verificar serviços sensíveis específicos
nmap -sV -p 21 ALVO   # FTP
nmap -sV -p 22 ALVO   # SSH
nmap -sV -p 3306 ALVO # MySQL
nmap -sV -p 6379 ALVO # Redis (frequentemente sem auth)
nmap -sV -p 27017 ALVO # MongoDB (frequentemente sem auth)
```

**Critério PASS:** Apenas portas 80 e 443 acessíveis externamente; demais filtradas.  
**Critério FAIL:** SSH, FTP, MySQL, Redis, MongoDB, ou similares acessíveis externamente sem autenticação.

---

## TC-CDN — Bypass e Dependência de CDN

### TC-CDN-001 — Verificação de IP Direto ao Servidor de Origem

| Campo | Detalhe |
|-------|---------|
| **ID** | TC-CDN-001 |
| **Categoria** | Architecture / Defense in Depth |
| **Severidade esperada** | 🟡 Média a 🟠 Alta |
| **Pré-condição** | Conhecimento do IP de origem (via histórico DNS, certificado TLS, etc.) |

**Objetivo:** Verificar se o servidor de origem aceita conexões diretas, bypassando o CDN e suas proteções.

**Passos:**
```bash
# 1. Descobrir IP de origem via histórico DNS (SecurityTrails, Shodan, etc.)
# 2. Tentar acesso direto ao IP com Host header do domínio
curl -sk -H "Host: DOMINIO" https://IP_ORIGEM/ -o /dev/null -w "%{http_code}"

# 3. Verificar via certificado TLS (CN pode revelar IP real)
echo | openssl s_client -connect ALVO:443 2>/dev/null | openssl x509 -noout -subject

# 4. Verificar registros históricos de DNS
# Consultar: https://securitytrails.com, https://viewdns.info/iphistory/
```

**Critério PASS:** Servidor de origem não responde a conexões diretas (firewall bloqueia tudo exceto CDN).  
**Critério FAIL:** Servidor de origem acessível diretamente, bypassando todas as proteções do CDN.

---

## TC-API — API REST WordPress

### TC-API-001 — Exposição de Endpoints REST Sensíveis

| Campo | Detalhe |
|-------|---------|
| **ID** | TC-API-001 |
| **Categoria** | Information Disclosure / Authentication |
| **OWASP** | API Security Top 10 — API1, API3 |
| **Severidade esperada** | ⚪ Info a 🟡 Média |
| **Pré-condição** | WordPress acessível |

**Objetivo:** Mapear e testar endpoints da API REST WordPress por exposição de dados não autorizados.

**Passos:**
```bash
# 1. Verificar namespace disponíveis
curl -sk https://ALVO/wp-json/ | python3 -m json.tool | grep "namespace"

# 2. Testar endpoints públicos críticos
curl -sk https://ALVO/wp-json/wp/v2/users
curl -sk https://ALVO/wp-json/wp/v2/users?per_page=100
curl -sk https://ALVO/wp-json/wp/v2/posts
curl -sk https://ALVO/wp-json/wp/v2/pages
curl -sk https://ALVO/wp-json/wp/v2/media
curl -sk https://ALVO/wp-json/wp/v2/settings  # Requer autenticação

# 3. Verificar oembed (pode vazar usernames)
curl -sk "https://ALVO/wp-json/oembed/1.0/embed?url=https://ALVO/"

# 4. Verificar se a API pode ser desabilitada completamente
curl -sk https://ALVO/wp-json/ | head -c 100
```

**Critério PASS:** Endpoint `/users` não retorna dados; outros endpoints sem dados sensíveis não autenticados.  
**Critério FAIL:** Usernames, emails, ou metadados sensíveis acessíveis sem autenticação.

---

### TC-API-002 — Verificação de Rate Limiting na API

| Campo | Detalhe |
|-------|---------|
| **ID** | TC-API-002 |
| **Categoria** | API Security |
| **OWASP** | API Security Top 10 — API4 (Lack of Rate Limiting) |
| **Severidade esperada** | 🟡 Média |
| **Pré-condição** | API REST acessível |

**Objetivo:** Verificar se a API REST possui rate limiting para prevenir abuso.

**Passos:**
```bash
# 1. Enviar múltiplas requisições em sequência rápida
for i in {1..20}; do
  code=$(curl -sk -o /dev/null -w "%{http_code}" https://ALVO/wp-json/wp/v2/posts)
  echo "Request $i: HTTP $code"
done

# 2. Verificar headers de rate limiting na resposta
curl -sk -D - https://ALVO/wp-json/wp/v2/posts -o /dev/null | \
  grep -iE "x-ratelimit|retry-after|x-rate"
```

**Critério PASS:** Após N requisições, retorna 429 com `Retry-After` header.  
**Critério FAIL:** Nenhum rate limiting; 200 em todas as requisições independente do volume.

---

## Matriz de Cobertura

| ID | Título | Severidade | OWASP | Status |
|----|--------|------------|-------|--------|
| TC-RECON-001 | Enumeração via Headers HTTP | ⚪ Info | INFO-002 | — |
| TC-RECON-002 | Análise de robots.txt | ⚪ Info | INFO-001 | — |
| TC-RECON-003 | Enumeração de Diretórios | 🟡 Média | CONFIG-001 | — |
| TC-REPO-001 | Diretório .git Exposto | 🟡 Média | A05 | — |
| TC-REPO-002 | Diretório .svn Exposto | 🟡 Média | A05 | — |
| TC-REPO-003 | Outros Artefatos de Dev | 🟡 Média | A05 | — |
| TC-WP-001 | Versão WordPress Exposta | 🔵 Baixa | A05 | — |
| TC-WP-002 | Proteção do wp-login | 🟡 Média | AUTHN-003 | — |
| TC-WP-003 | XML-RPC Status | 🟡 Média | A05 | — |
| TC-WP-004 | Enumeração de Usuários | 🔵 Baixa | IDENT-004 | — |
| TC-HDR-001 | Headers de Segurança | 🔵 Baixa | A05 | — |
| TC-HDR-002 | HSTS e Preloading | 🔵 Baixa | A02 | — |
| TC-NET-001 | Portas Expostas | 🟡 Média | A05 | — |
| TC-CDN-001 | Bypass de CDN | 🟡 Média | A05 | — |
| TC-API-001 | Endpoints REST Sensíveis | 🟡 Média | API1/API3 | — |
| TC-API-002 | Rate Limiting API | 🟡 Média | API4 | — |

---

