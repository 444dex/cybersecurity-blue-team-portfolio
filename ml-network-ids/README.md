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
git clone https://github.com/444dex/cybersecurity-blue-team-portfolio.git
cd ml-network-ids

# Crie ambiente virtual
python -m venv venv
source venv/bin/activate  # Linux/Mac
# ou
venv\Scripts\activate  # Windows

# Instale dependências
pip install -r requirements.txt
```

## 💻 Uso

```bash
# Treinar o modelo
python train_model.py

# Executar IDS em tempo real
sudo python ids_monitor.py --interface eth0

# Analisar arquivo PCAP
python analyze_pcap.py --file capture.pcap
```

## 📈 Métricas de Desempenho
- Acurácia: ~95%
- Precisão: ~93%
- Recall: ~94%
- F1-Score: ~93.5%

## 📂 Estrutura do Projeto
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

## 🔍 Tipos de Ataques Detectados
1. **Port Scanning** - Detecção de varredura de portas
2. **DDoS** - Ataques de negação de serviço distribuído
3. **Brute Force** - Tentativas de autenticação forçada
4. **Anomalias de Tráfego** - Padrões incomuns de rede

## 📝 Exemplo de Saída
```
[2025-01-30 14:23:45] ALERT: Port Scan detectado
  - Origem: 192.168.1.105
  - Destino: 192.168.1.1
  - Portas: 80, 443, 22, 3306, 8080
  - Confiança: 97%
```

## 🎓 Aprendizados
Este projeto demonstra:
- Captura e análise de tráfego de rede
- Feature engineering para dados de rede
- Implementação de modelos de ML para segurança
- Detecção de ameaças em tempo real

## 📄 Licença
MIT License

## 👤 Autor
Seu Nome - [LinkedIn](seu-linkedin) - [GitHub](seu-github)
