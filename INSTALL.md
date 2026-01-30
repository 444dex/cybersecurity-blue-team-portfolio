# Guia de Instalação Rápida

## Pré-requisitos

- Python 3.8 ou superior
- pip (gerenciador de pacotes Python)
- Git
- Permissões de root/sudo (para alguns projetos)

## Instalação

### 1. Clone o Repositório

```bash
git clone https://github.com/444dex/cybersecurity-blue-team-portfolio.git
cd cybersecurity-blue-team-portfolio
```

### 2. Escolha um Projeto

Cada projeto está em seu próprio diretório:

```bash
# Exemplo: IDS com Machine Learning
cd ml-network-ids
```

### 3. Crie Ambiente Virtual

```bash
# Criar ambiente virtual
python3 -m venv venv

# Ativar ambiente virtual
# No Linux/Mac:
source venv/bin/activate

# No Windows:
venv\Scripts\activate
```

### 4. Instale Dependências

```bash
pip install -r requirements.txt
```

### 5. Execute o Projeto

Cada projeto tem instruções específicas no seu README. Exemplo:

```bash
# IDS - Treinar modelo
python train_model.py

# IDS - Monitorar rede
sudo python ids_monitor.py --interface eth0

# SIEM - Analisar logs
python siem_analyzer.py --file /var/log/auth.log --type auth

# Web Scanner - Scanear site
python web_scanner.py --url http://testphp.vulnweb.com

# Honeypot SSH - Iniciar
python ssh_honeypot.py --port 2222

# FIM - Criar baseline
python fim.py --init --path /etc
```

## Instalação de Todos os Projetos

Se você quiser instalar as dependências de todos os projetos de uma vez:

```bash
# Script de instalação completa
for dir in ml-network-ids siem-log-analyzer web-vulnerability-scanner ssh-honeypot file-integrity-monitor; do
    echo "Instalando dependências de $dir..."
    cd $dir
    python3 -m venv venv
    source venv/bin/activate
    pip install -r requirements.txt
    deactivate
    cd ..
done
```

## Projetos que Requerem Permissões Especiais

### IDS (ml-network-ids)
- **Requer:** Permissões root para captura de pacotes
- **Comando:** `sudo python ids_monitor.py`

### SSH Honeypot (ssh-honeypot)
- **Requer:** Permissões root se usar porta < 1024
- **Comando:** `sudo python ssh_honeypot.py --port 22`
- **Nota:** Gerar chave SSH: `ssh-keygen -t rsa -f honeypot_key -N ""`

### FIM (file-integrity-monitor)
- **Requer:** Permissões de leitura nos diretórios monitorados
- **Comando:** `python fim.py --init --path /etc`

## Verificação da Instalação

Após instalar, você pode verificar se tudo está funcionando:

```bash
# Verificar versão do Python
python3 --version

# Verificar se os módulos foram instalados
cd ml-network-ids
source venv/bin/activate
python -c "import scapy, sklearn, pandas; print('OK')"
```

## Troubleshooting

### Erro: "scapy requires root privileges"
**Solução:** Execute com sudo: `sudo python ids_monitor.py`

### Erro: "ModuleNotFoundError"
**Solução:** Certifique-se de ativar o ambiente virtual:
```bash
source venv/bin/activate
pip install -r requirements.txt
```

### Erro ao instalar scapy no Windows
**Solução:** Instale WinPcap ou Npcap primeiro:
- Download: https://npcap.com/#download

### Erro: "Permission denied" ao criar baseline do FIM
**Solução:** Execute com permissões adequadas:
```bash
sudo python fim.py --init --path /etc
```

## Ambientes de Teste Recomendados

Para testar os projetos com segurança:

1. **Máquinas Virtuais:**
   - VirtualBox
   - VMware
   - QEMU/KVM

2. **Ambientes Lab:**
   - [TryHackMe](https://tryhackme.com/)
   - [HackTheBox](https://www.hackthebox.com/)
   - [DVWA](http://www.dvwa.co.uk/) (para web scanner)
   - [Metasploitable](https://sourceforge.net/projects/metasploitable/)

3. **Containers Docker:**
   - Isole os projetos em containers
   - Use docker-compose para ambientes completos

## Próximos Passos

Depois de instalar os projetos:

1. Leia o README.md de cada projeto
2. Execute os exemplos fornecidos
3. Personalize os projetos para seu caso de uso
4. Contribua com melhorias (pull requests são bem-vindos!)

## Suporte

Se encontrar problemas:
- Abra uma issue no GitHub
- Consulte a documentação de cada projeto
- Entre em contato: miguelerick.a.k@gmail.com
