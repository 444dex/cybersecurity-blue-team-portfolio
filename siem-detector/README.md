# SIEM Detector - Sistema de Detecção de Intrusão

Sistema inteligente de análise de logs e detecção de ameaças em tempo real, simulando funcionalidades de um SIEM (Security Information and Event Management).

## Sobre o Projeto

Este projeto implementa um detector de intrusão que analisa logs de sistemas e aplicações, identificando padrões suspeitos e gerando alertas de segurança. É uma ferramenta essencial para operações de Blue Team.

## Funcionalidades

- **Detecção de Força Bruta SSH**: Identifica múltiplas tentativas de login falhas
- **SQL Injection**: Detecta padrões de ataques de injeção SQL
- **Port Scanning**: Identifica varreduras de portas
- **Directory Traversal**: Detecta tentativas de acesso a diretórios não autorizados
- **Escalação de Privilégios**: Monitora comandos suspeitos de sudo/su
- **Acesso Não Autorizado**: Rastreia múltiplas tentativas de acesso negado
- **Banco de Dados SQLite**: Armazena todos os alertas para análise posterior
- **Relatórios Automatizados**: Gera relatórios de segurança com estatísticas

## Como Usar

### Instalação

```bash
git clone https://github.com/444dex/cybersecurity-blue-team-portfolio.git
cd siem-detector
chmod +x siem_detector.py
```

### Uso Básico

```bash
# Analisar um arquivo de log
python3 siem_detector.py -f /var/log/auth.log

# Criar logs de exemplo e analisar
python3 siem_detector.py -s

# Ver ajuda
python3 siem_detector.py -h
```

## Exemplos de Saída

```
[ALERTA HIGH]
Regra: brute_force_ssh
IP Origem: 192.168.1.100
Descrição: Tentativa de força bruta SSH detectada
Ocorrências: 6
Timestamp: 2025-01-30T10:15:28
```

## Regras de Detecção

| Regra | Severidade | Threshold | Descrição |
|-------|-----------|-----------|-----------|
| Brute Force SSH | HIGH | 5 tentativas | Múltiplas falhas de autenticação SSH |
| SQL Injection | CRITICAL | 1 tentativa | Padrões de injeção SQL |
| Port Scan | MEDIUM | 10 portas | Varredura de múltiplas portas |
| Directory Traversal | HIGH | 1 tentativa | Acesso a diretórios não autorizados |
| Privilege Escalation | HIGH | 1 tentativa | Uso suspeito de sudo/su |

## Banco de Dados

O sistema armazena todos os alertas em um banco SQLite (`siem_alerts.db`) com o seguinte schema:

- timestamp
- severity
- rule_name
- source_ip
- description
- log_entry

## Melhorias Futuras

- [ ] Interface web para visualização de alertas
- [ ] Integração com APIs de Threat Intelligence
- [ ] Machine Learning para detecção de anomalias
- [ ] Notificações via email/Slack
- [ ] Dashboard em tempo real
- [ ] Exportação de relatórios em PDF

## Conceitos Aplicados

- Análise de logs e SIEM
- Detecção de padrões com regex
- Threat hunting
- Incident response
- Blue Team operations
- Security monitoring

## Contribuindo

Contribuições são bem-vindas! Sinta-se à vontade para abrir issues ou pull requests.

## Licença

MIT License

## Autor

Desenvolvido para demonstração de habilidades em Blue Team e Cibersegurança.
