#!/usr/bin/env python3
"""
Script para treinar modelo de Machine Learning para detecção de intrusão
Utiliza dataset simulado para demonstração
"""

import os
import pickle
import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, confusion_matrix
import matplotlib.pyplot as plt
import seaborn as sns


def generate_synthetic_data(n_samples=10000):
    """
    Gera dados sintéticos para treinamento
    Em produção, use datasets reais como KDD Cup 99, NSL-KDD ou CICIDS2017
    
    Args:
        n_samples: Número de amostras a gerar
        
    Returns:
        DataFrame: Dados sintéticos
    """
    np.random.seed(42)
    
    data = []
    
    # Tráfego normal (70%)
    n_normal = int(n_samples * 0.7)
    for _ in range(n_normal):
        data.append({
            'packet_length': np.random.randint(64, 1500),
            'protocol': np.random.choice([6, 17]),  # TCP ou UDP
            'src_port': np.random.randint(1024, 65535),
            'dst_port': np.random.choice([80, 443, 22, 21, 25]),
            'flags': np.random.randint(0, 32),
            'window_size': np.random.randint(1000, 65535),
            'ttl': np.random.randint(64, 128),
            'label': 0  # Normal
        })
    
    # Port Scan (10%)
    n_portscan = int(n_samples * 0.1)
    for _ in range(n_portscan):
        data.append({
            'packet_length': np.random.randint(40, 100),
            'protocol': 6,  # TCP
            'src_port': np.random.randint(1024, 65535),
            'dst_port': np.random.randint(1, 65535),
            'flags': 2,  # SYN flag
            'window_size': np.random.randint(1000, 8192),
            'ttl': np.random.randint(32, 64),
            'label': 1  # Malicioso
        })
    
    # DDoS (10%)
    n_ddos = int(n_samples * 0.1)
    for _ in range(n_ddos):
        data.append({
            'packet_length': np.random.randint(20, 200),
            'protocol': np.random.choice([1, 6, 17]),
            'src_port': np.random.randint(1024, 65535),
            'dst_port': np.random.choice([80, 443]),
            'flags': np.random.randint(0, 32),
            'window_size': np.random.randint(100, 1000),
            'ttl': np.random.randint(32, 64),
            'label': 1  # Malicioso
        })
    
    # Brute Force (10%)
    n_bruteforce = int(n_samples * 0.1)
    for _ in range(n_bruteforce):
        data.append({
            'packet_length': np.random.randint(100, 500),
            'protocol': 6,
            'src_port': np.random.randint(1024, 65535),
            'dst_port': 22,  # SSH
            'flags': 24,  # ACK + PSH
            'window_size': np.random.randint(1000, 65535),
            'ttl': np.random.randint(64, 128),
            'label': 1  # Malicioso
        })
    
    return pd.DataFrame(data)


def train_model(data):
    """
    Treina modelo Random Forest
    
    Args:
        data: DataFrame com dados de treinamento
        
    Returns:
        tuple: (modelo treinado, métricas)
    """
    # Separa features e labels
    X = data.drop('label', axis=1)
    y = data['label']
    
    # Split treino/teste
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )
    
    print(f"Dados de treino: {len(X_train)}")
    print(f"Dados de teste: {len(X_test)}")
    print(f"Distribuição de classes:")
    print(y_train.value_counts(normalize=True))
    
    # Treina Random Forest
    print("\nTreinando Random Forest Classifier...")
    model = RandomForestClassifier(
        n_estimators=100,
        max_depth=10,
        random_state=42,
        n_jobs=-1
    )
    model.fit(X_train, y_train)
    
    # Avalia modelo
    print("\nAvaliando modelo...")
    y_pred = model.predict(X_test)
    
    # Relatório de classificação
    print("\nRelatório de Classificação:")
    print(classification_report(y_test, y_pred, 
                                target_names=['Normal', 'Malicioso']))
    
    # Matriz de confusão
    cm = confusion_matrix(y_test, y_pred)
    
    # Feature importance
    feature_importance = pd.DataFrame({
        'feature': X.columns,
        'importance': model.feature_importances_
    }).sort_values('importance', ascending=False)
    
    print("\nImportância das Features:")
    print(feature_importance)
    
    return model, {
        'confusion_matrix': cm,
        'feature_importance': feature_importance,
        'X_test': X_test,
        'y_test': y_test,
        'y_pred': y_pred
    }


def plot_results(metrics):
    """
    Plota resultados do treinamento
    
    Args:
        metrics: Dicionário com métricas
    """
    fig, axes = plt.subplots(1, 2, figsize=(14, 5))
    
    # Matriz de confusão
    sns.heatmap(metrics['confusion_matrix'], annot=True, fmt='d', 
                cmap='Blues', ax=axes[0])
    axes[0].set_title('Matriz de Confusão')
    axes[0].set_xlabel('Predito')
    axes[0].set_ylabel('Real')
    axes[0].set_xticklabels(['Normal', 'Malicioso'])
    axes[0].set_yticklabels(['Normal', 'Malicioso'])
    
    # Importância das features
    metrics['feature_importance'].plot(
        kind='barh', 
        x='feature', 
        y='importance',
        ax=axes[1],
        legend=False
    )
    axes[1].set_title('Importância das Features')
    axes[1].set_xlabel('Importância')
    
    plt.tight_layout()
    plt.savefig('models/training_results.png', dpi=300, bbox_inches='tight')
    print("\nGráficos salvos em models/training_results.png")


def main():
    # Cria diretório para modelos
    os.makedirs('models', exist_ok=True)
    
    # Gera dados sintéticos
    print("Gerando dados sintéticos de treinamento...")
    print("NOTA: Em produção, use datasets reais como CICIDS2017 ou NSL-KDD")
    data = generate_synthetic_data(n_samples=10000)
    
    # Treina modelo
    model, metrics = train_model(data)
    
    # Salva modelo
    model_path = 'models/ids_model.pkl'
    with open(model_path, 'wb') as f:
        pickle.dump(model, f)
    print(f"\nModelo salvo em {model_path}")
    
    # Plota resultados
    plot_results(metrics)
    
    print("\n✅ Treinamento concluído com sucesso!")
    print(f"Use o modelo com: python ids_monitor.py --model {model_path}")


if __name__ == '__main__':
    main()
