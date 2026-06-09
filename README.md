# Cybersecurity QA Portfolio

> Portfólio de Quality Assurance em Segurança — testes, relatórios e automação aplicados a cenários reais.

---

## Sobre

Sou formado em Análise e Desenvolvimento de Sistemas pela UNIP, com 7 anos de experiência em Linux e background em desenvolvimento Full-Stack (React Native, Next.js, Node.js). Migrei minha atuação para segurança ofensiva e QA de segurança, combinando a mentalidade de qualidade de software com práticas de pentest.

Este repositório documenta trabalhos práticos: testes de intrusão realizados, casos de teste estruturados e estudos de segurança aplicados.

---

## Estrutura

```
cybersec-qa-portfolio/
├── README.md
├── reports/
│   ├── blackbox-assessment-redacted.md   ← Relatório real anonimizado (black-box)
│   └── report-qa-template-addendum.md    ← Template estruturado de vulnerabilidade
│
├── test-cases/
│   ├── authentication-tests.md           ← Casos de teste: autenticação
│   ├── authorization-tests.md            ← Casos de teste: autorização e controle de acesso
│   ├── api-security-tests.md             ← Casos de teste: segurança de APIs REST
│   └── web-security.md                   ← Casos de teste: baseado em avaliação black-box real
│
└── certifications/
    └── solyd-introducao-pentest.pdf      ← Certificado Introdução a Pentest — Solyd (2019)
```

---

## Trabalhos em Destaque

### Black-box Assessment — Hostinger WordPress Site
Pentest black-box conduzido contra aplicação web hospedada em CDN com bot protection ativo. Identificados repositórios `.git` e `.svn` expostos no webroot, CMS WordPress confirmado e ausência de headers de segurança. Relatório completo (anonimizado) em [`reports/blackbox-assessment-redacted.md`](reports/blackbox-assessment-redacted.md).

**Ferramentas utilizadas:** Gobuster 3.6, Nmap 7.95, Nikto 2.6.0, WPScan 3.8.28, curl, git-dumper

---

### Casos de Teste de Segurança
Suíte de casos de teste cobrindo:
- **Autenticação** — brute force, lockout, MFA bypass, credential stuffing
- **Autorização** — IDOR, privilege escalation, BOLA/BFLA
- **API REST** — OWASP API Top 10, rate limiting, mass assignment

Formato estruturado com severidade, pré-condições, passos e critério de aprovação/reprovação.

---

## Stack & Conhecimentos

| Área | Detalhes |
|------|----------|
| SO | Linux (uso exclusivo — 7 anos, 3 máquinas) |
| Dev | React Native, Next.js, JavaScript/TypeScript, Python |
| Reconhecimento | Nmap, Gobuster, Nikto, WPScan, curl |
| Exploração | Burp Suite, git-dumper, sqlmap |
| Automação | Python, Bash |
| Frameworks | OWASP Testing Guide v4, PTES |
| Certificações | Introdução a Pentest — Solyd (2019) |

---

## Metodologia

Os testes documentados aqui seguem o **OWASP Testing Guide v4** e o **PTES (Penetration Testing Execution Standard)**, cobrindo as fases de:

1. Reconhecimento passivo
2. Reconhecimento ativo e enumeração
3. Fingerprinting de tecnologias
4. Identificação e validação de vetores
5. Documentação e recomendações

---

## Contato

- GitHub: [@44lain](https://github.com/44lain)
- LinkedIn: [linkedin.com/in/luciano-rodrigues](https://www.linkedin.com/in/luciano-rodrigues-38b644407)
- Email: [lain.fork@gmail.com](mailto:lain.fork@gmail.com)

---

- Portfolio: [Porfolio (Em Desenvolvimento)](https://44lain.vercel.app)

---

> **Aviso Legal:** Todos os testes documentados neste repositório foram realizados com autorização explícita dos proprietários dos sistemas. Nenhuma técnica deve ser aplicada sem permissão formal. O conteúdo é de caráter educacional e profissional.
