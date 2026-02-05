# File Integrity Monitor (FIM) - Monitor de Integridade de Arquivos

## Descrição
Sistema de monitoramento de integridade de arquivos que detecta modificações não autorizadas em arquivos críticos do sistema. Calcula hashes, monitora mudanças e gera alertas em tempo real.

## Objetivos de Aprendizado
- Monitoramento de integridade de arquivos
- Detecção de modificações não autorizadas
- Hashing criptográfico (MD5, SHA-256)
- Alertas e resposta a incidentes

## Tecnologias
- Python 3.8+
- Watchdog (monitoramento de filesystem)
- SQLite (baseline de hashes)
- Hashlib (cálculo de hashes)

## Funcionalidades
- Monitoramento em tempo real de diretórios
- Baseline de integridade (SHA-256)
- Detecção de arquivos criados/modificados/deletados
- Whitelist de arquivos permitidos
- Alertas por email/webhook
- Logs detalhados de mudanças
- Verificação de integridade agendada
- Restauração de arquivos comprometidos

## Instalação

```bash
git clone https://github.com/444dex/cybersecurity-blue-team-portfolio.git
cd file-integrity-monitor

python -m venv venv
source venv/bin/activate

pip install -r requirements.txt
```

## Uso

```bash
# Criar baseline inicial
python fim.py --init --path /etc

# Monitorar diretório em tempo real
python fim.py --monitor --path /var/www/html

# Verificar integridade
python fim.py --check --path /etc

# Múltiplos diretórios
python fim.py --monitor --path /etc --path /var/www --path /home

# Com alertas por email
python fim.py --monitor --path /etc --email admin@example.com

# Modo daemon
python fim.py --daemon --path /etc
```

## Estrutura do Projeto
```
file-integrity-monitor/
├── fim.py               # Programa principal
├── baseline.db          # Banco de dados de hashes
├── config.yml           # Configuração
├── alerts/
│   ├── email_alert.py
│   └── webhook_alert.py
├── logs/
│   └── fim.log
└── requirements.txt
```

## Tipos de Eventos Detectados

### Modificações de Arquivo
- Conteúdo alterado (hash diferente)
- Permissões modificadas
- Proprietário/grupo alterado
- Timestamps modificados

### Criação de Arquivos
- Novos arquivos em diretórios monitorados
- Arquivos suspeitos (.sh, .exe, .dll)

### Deleção de Arquivos
- Arquivos críticos removidos
- Tentativa de ocultar rastros

## Exemplo de Output

```bash
$ python fim.py --monitor --path /etc

[*] File Integrity Monitor v1.0
[*] Iniciando monitoramento de /etc
[*] Baseline carregado: 1,247 arquivos

[2025-01-30 14:23:45]   ALERTA: Arquivo modificado
  Arquivo: /etc/passwd
  Tipo: MODIFICADO
  Hash Anterior: a1b2c3d4e5f6...
  Hash Atual: f6e5d4c3b2a1...
  Timestamp: 2025-01-30 14:23:45
  Severidade: CRITICAL

[2025-01-30 14:25:12]   ALERTA: Novo arquivo detectado
  Arquivo: /etc/cron.d/backdoor
  Tipo: CRIADO
  Hash: 9f8e7d6c5b4a...
  Timestamp: 2025-01-30 14:25:12
  Severidade: HIGH

[2025-01-30 14:27:30]  Alerta enviado para: admin@example.com
```

##  Relatório de Integridade

```
╔═══════════════════════════════════════════════╗
║   RELATÓRIO DE INTEGRIDADE DE ARQUIVOS        ║
╠═══════════════════════════════════════════════╣
║ Período: 2025-01-30 00:00 - 23:59            ║
║ Diretórios monitorados: 3                     ║
║ Arquivos no baseline: 1,247                   ║
╠═══════════════════════════════════════════════╣
║ EVENTOS DETECTADOS                            ║
╠═══════════════════════════════════════════════╣
║ Arquivos modificados: 5                       ║
║ Arquivos criados: 2                           ║
║ Arquivos deletados: 0                         ║
╠═══════════════════════════════════════════════╣
║ ALERTAS POR SEVERIDADE                        ║
╠═══════════════════════════════════════════════╣
║ CRITICAL: 2                                   ║
║ HIGH: 3                                       ║
║ MEDIUM: 2                                     ║
╠═══════════════════════════════════════════════╣
║ ARQUIVOS CRÍTICOS MODIFICADOS                 ║
╠═══════════════════════════════════════════════╣
║ • /etc/passwd                                 ║
║ • /etc/shadow                                 ║
╚═══════════════════════════════════════════════╝
```

## Configuração (config.yml)

```yaml
monitoring:
  paths:
    - /etc
    - /var/www/html
    - /home
  
  excluded_patterns:
    - "*.log"
    - "*.tmp"
    - "*.swp"

critical_files:
  - /etc/passwd
  - /etc/shadow
  - /etc/sudoers
  - /etc/ssh/sshd_config

alerts:
  email:
    enabled: true
    smtp_server: smtp.gmail.com
    smtp_port: 587
    from: fim@example.com
    to: admin@example.com
  
  webhook:
    enabled: false
    url: https://hooks.slack.com/services/YOUR/WEBHOOK/URL

scan_interval: 3600  # 1 hora
```


## Use Cases
- Monitorar arquivos de configuração do sistema
- Detectar backdoors e malware
- Compliance (PCI-DSS, HIPAA)
- Detecção de ransomware
- Auditoria de mudanças

## Integrações Possíveis
- SIEM (Splunk, ELK Stack)
- Ticketing systems (Jira, ServiceNow)
- Slack/Teams notifications
- SOAR platforms

## Licença
MIT License
