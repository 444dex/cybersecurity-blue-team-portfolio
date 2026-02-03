# Sistema de Detecção de Intrusão com Machine Learning

## Descrição
Sistema IDS baseado em machine learning para detectar tráfego de rede anômalo e possíveis ataques (DDoS, port scanning, brute force). Utiliza Random Forest para classificação de tráfego normal vs malicioso.

## Objetivos de Aprendizado
- Análise de tráfego de rede
- Machine Learning aplicado à cibersegurança
- Detecção de anomalias
- Visualização de ameaças

## Tecnologias
- Python 3.8+
- Scikit-learn
- Pandas, NumPy
- Scapy (análise de pacotes)
- Matplotlib/Seaborn

## Funcionalidades
- Captura e análise de pacotes de rede
- Detecção de port scanning
- Identificação de ataques DDoS
- Detecção de brute force
- Dashboard de alertas em tempo real
- Logs de incidentes

## Instalação

```bash
# Clone o repositório
git clone https://github.com/seu-usuario/ml-network-ids.git
cd ml-network-ids

# Crie ambiente virtual
python -m venv venv
source venv/bin/activate  # Linux/Mac
# ou
venv\Scripts\activate  # Windows

# Instale dependências
pip install -r requirements.txt
```

## Uso

```bash
# Treinar o modelo
python train_model.py

# Executar IDS com interface auto-detectada (Windows e Linux)
python ids_monitor.py

# Listar interfaces de rede disponíveis no sistema
python ids_monitor.py --list-interfaces

# Especificar interface manualmente
python ids_monitor.py --interface eth0          # Linux
python ids_monitor.py --interface "Wi-Fi"       # Windows
python ids_monitor.py --interface wlan0         # Linux (Wi-Fi)

# Analisar arquivo PCAP
python analyze_pcap.py --file capture.pcap
```

> **Nota (Linux):** a captura de pacotes requer privilégios root. Execute com `sudo python ids_monitor.py`.  
> **Nota (Windows):** instale o [Npcap](https://npcap.com/#download) antes de executar. Não é necessário `sudo`.

## Métricas de Desempenho
- Acurácia: ~95%
- Precisão: ~93%
- Recall: ~94%
- F1-Score: ~93.5%

## Estrutura do Projeto
```
ml-network-ids/
├── data/
│   ├── train/          # Dados de treinamento
│   └── test/           # Dados de teste
├── models/
│   └── ids_model.pkl   # Modelo treinado
├── src/
│   ├── capture.py      # Captura de pacotes
│   ├── feature_extraction.py
│   ├── detection.py    # Lógica de detecção
│   └── alerts.py       # Sistema de alertas
├── train_model.py
├── ids_monitor.py
├── analyze_pcap.py
└── requirements.txt
```

## Compatibilidade

| Sistema | Interface padrão | Privilegio necessário | Requisito extra |
|---|---|---|---|
| Linux | `eth0`, `wlan0`, `enp0s3`… | `sudo` | — |
| macOS | `en0`, `en1`… | `sudo` | — |
| Windows | `Wi-Fi`, `Ethernet`… | não | [Npcap](https://npcap.com/#download) instalado |

Se você não passar `--interface`, o programa detecta automaticamente qual interface está ativa. Use `--list-interfaces` para ver todas as opções do seu sistema.

## Tipos de Ataques Detectados
1. **Port Scanning** - Detecção de varredura de portas
2. **DDoS** - Ataques de negação de serviço distribuído
3. **Brute Force** - Tentativas de autenticação forçada
4. **Anomalias de Tráfego** - Padrões incomuns de rede

## Exemplo de Saída
```
[2026-01-30 14:23:45] ALERT: Port Scan detectado
  - Origem: 192.168.1.105
  - Destino: 192.168.1.1
  - Portas: 80, 443, 22, 3306, 8080
  - Confiança: 97%
```

## Aprendizados
Este projeto demonstra:
- Captura e análise de tráfego de rede
- Feature engineering para dados de rede
- Implementação de modelos de ML para segurança
- Detecção de ameaças em tempo real

## Licença
MIT License

## Autor
Miguel "444dex" Kuipers - [LinkedIn](https://www.linkedin.com/in/miguel-erick-assun%C3%A7%C3%A3o-kuipers-9665382b4/) - [GitHub](https://github.com/444dex/)
