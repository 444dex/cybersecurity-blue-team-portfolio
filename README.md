# Portfólio de Projetos de Cibersegurança - Blue Team

Coleção de projetos práticos de cibersegurança focados em **Blue Team** para demonstrar habilidades em detecção, monitoramento, análise e resposta a incidentes.

## Sobre

Portfólio desenvolvido para demonstrar competências técnicas em cibersegurança defensiva, com foco em:
- Detecção de ameaças e intrusões
- Análise de logs e eventos de segurança
- Monitoramento de infraestrutura
- Resposta a incidentes
- Automação de tarefas de segurança

## Projetos

### 1 - Sistema de Detecção de Intrusão com Machine Learning
**Tecnologias:** Python, Scikit-learn, Scapy, Pandas

Sistema IDS baseado em ML que detecta tráfego malicioso em tempo real, incluindo port scanning, DDoS e brute force.

**Destaques:**
- Detecção de anomalias com Random Forest
- Captura e análise de pacotes de rede
- Acurácia de ~95%
- Dashboard de alertas em tempo real

[Ver projeto](./ml-network-ids/)

---

### 2 - Analisador de Logs SIEM
**Tecnologias:** Python, Regex, Pandas, SQLite

Sistema SIEM para análise e correlação de logs de segurança com implementação de regras SIGMA.

**Destaques:**
- Parser para múltiplos formatos (Apache, SSH, Windows)
- Detecção de brute force, SQL injection, privilege escalation
- Correlação de eventos
- Geração de relatórios

[Ver projeto](./siem-log-analyzer/)

---

### 3 - Scanner de Vulnerabilidades Web
**Tecnologias:** Python, Requests, BeautifulSoup4

Scanner automatizado para identificar vulnerabilidades OWASP Top 10 em aplicações web.

**Destaques:**
- Testa SQL Injection, XSS, CSRF
- Verifica security headers
- Análise de configurações SSL/TLS
- Relatórios detalhados em HTML

[Ver projeto](./web-vulnerability-scanner/)

---

### 4 - SSH Honeypot (Em desenvolvimento)
**Tecnologias:** Python, Paramiko, SQLite, GeoIP

Honeypot SSH que registra tentativas de ataque e comportamento de atacantes.

**Destaques:**
- Shell emulado realista
- Coleta de credenciais e comandos
- Geolocalização de atacantes
- Dashboard de threat intelligence

[Ver projeto](./ssh-honeypot/)

---

### 5 - Monitor de Integridade de Arquivos (FIM) (Em desenvolvimento)
**Tecnologias:** Python, Watchdog, Hashlib, SQLite

Sistema de monitoramento de integridade que detecta modificações não autorizadas em arquivos críticos.

**Destaques:**
- Monitoramento em tempo real
- Baseline de integridade com SHA-256
- Alertas para arquivos críticos do sistema
- Logs detalhados de eventos

[Ver projeto](./file-integrity-monitor/)

---

## Habilidades Demonstradas

### Técnicas
- Detecção e resposta a intrusões (IDS/IPS)
- Análise de logs e correlação de eventos (SIEM)
- Testes de penetração (vulnerability assessment)
- Threat Intelligence e honeypots
- File Integrity Monitoring
- Machine Learning aplicado à segurança

### Ferramentas e Tecnologias
- **Linguagens:** Python
- **Frameworks:** Scikit-learn, Pandas, NumPy
- **Redes:** Scapy, Paramiko, Requests
- **Databases:** SQLite
- **Segurança:** Hashlib, SSL/TLS, Cryptography

### Conceitos de Segurança
- OWASP Top 10
- MITRE ATT&CK Framework
- Regras SIGMA
- IOCs (Indicators of Compromise)
- Network Traffic Analysis
- Log Analysis
- Incident Response



### Instalação

```bash
# Clone o repositório
git clone https://github.com/444dex/cybersecurity-blue-team-portfolio.git
cd cybersecurity-blue-team-portfolio

# Escolha um projeto
cd ml-network-ids

# Instale dependências
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# Execute o projeto
python ids_monitor.py --help
```

## Próximos Projetos

Projetos futuros planejados:
- [ ] Sistema de Detecção de Malware com YARA Rules
- [ ] Analisador de Tráfego de Rede (Packet Analyzer)
- [ ] Sistema de Correlação de Eventos (SOAR básico)
- [ ] Dashboard SOC com Elasticsearch + Kibana
- [ ] Automated Incident Response Playbooks

## Recursos de Aprendizado

- [OWASP](https://owasp.org/)
- [MITRE ATT&CK](https://attack.mitre.org/)
- [SANS Reading Room](https://www.sans.org/reading-room/)
- [CyberDefenders](https://cyberdefenders.org/)
- [Blue Team Labs Online](https://blueteamlabs.online/)

## Licença

MIT License - Projetos desenvolvidos para fins educacionais

## Contato

- **LinkedIn:** https://www.linkedin.com/in/miguel-erick-assun%C3%A7%C3%A3o-kuipers-9665382b4/
- **GitHub:** https://github.com/444dex
- **Email:** miguelerick.a.k@gmail.com

---

 **Nota:** Todos os projetos devem ser usados apenas em ambientes autorizados e para fins educacionais. O uso indevido dessas ferramentas pode ser ilegal.
