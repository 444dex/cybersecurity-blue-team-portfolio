#!/usr/bin/env python3
"""
Sistema de Detecção de Intrusão com Machine Learning
Monitora tráfego de rede e detecta atividades suspeitas
"""

import argparse
import pickle
import logging
from datetime import datetime
from collections import defaultdict
import scapy.all as scapy
import numpy as np
import pandas as pd

# Configuração de logging
logging.basicConfig(
    level=logging.INFO,
    format='[%(asctime)s] %(levelname)s: %(message)s',
    handlers=[
        logging.FileHandler('ids_alerts.log'),
        logging.StreamHandler()
    ]
)

class NetworkIDS:
    def __init__(self, model_path='models/ids_model.pkl', threshold=0.8):
        """
        Inicializa o IDS
        
        Args:
            model_path: Caminho para o modelo treinado
            threshold: Threshold de confiança para alertas
        """
        self.threshold = threshold
        self.packet_buffer = []
        self.connection_tracker = defaultdict(list)
        
        # Carrega modelo treinado
        try:
            with open(model_path, 'rb') as f:
                self.model = pickle.load(f)
            logging.info(f"Modelo carregado de {model_path}")
        except FileNotFoundError:
            logging.warning("Modelo não encontrado. Execute train_model.py primeiro")
            self.model = None
    
    def extract_features(self, packet):
        """
        Extrai features de um pacote para classificação
        
        Args:
            packet: Pacote scapy
            
        Returns:
            dict: Features extraídas
        """
        features = {
            'packet_length': len(packet),
            'protocol': 0,
            'src_port': 0,
            'dst_port': 0,
            'flags': 0,
            'window_size': 0,
            'ttl': 0
        }
        
        # Protocolo
        if packet.haslayer(scapy.TCP):
            features['protocol'] = 6
            features['src_port'] = packet[scapy.TCP].sport
            features['dst_port'] = packet[scapy.TCP].dport
            features['flags'] = int(packet[scapy.TCP].flags)
            features['window_size'] = packet[scapy.TCP].window
        elif packet.haslayer(scapy.UDP):
            features['protocol'] = 17
            features['src_port'] = packet[scapy.UDP].sport
            features['dst_port'] = packet[scapy.UDP].dport
        elif packet.haslayer(scapy.ICMP):
            features['protocol'] = 1
        
        # TTL
        if packet.haslayer(scapy.IP):
            features['ttl'] = packet[scapy.IP].ttl
        
        return features
    
    def detect_port_scan(self, src_ip, dst_ip, dst_port):
        """
        Detecta tentativas de port scanning
        
        Args:
            src_ip: IP de origem
            dst_ip: IP de destino
            dst_port: Porta de destino
            
        Returns:
            bool: True se port scan detectado
        """
        key = f"{src_ip}->{dst_ip}"
        self.connection_tracker[key].append({
            'port': dst_port,
            'timestamp': datetime.now()
        })
        
        # Limpa conexões antigas (>60 segundos)
        self.connection_tracker[key] = [
            conn for conn in self.connection_tracker[key]
            if (datetime.now() - conn['timestamp']).seconds < 60
        ]
        
        # Detecta se muitas portas diferentes foram tentadas
        unique_ports = len(set(conn['port'] for conn in self.connection_tracker[key]))
        
        if unique_ports > 10:  # Threshold de portas
            return True
        
        return False
    
    def detect_ddos(self, src_ip, dst_ip):
        """
        Detecta possíveis ataques DDoS
        
        Args:
            src_ip: IP de origem
            dst_ip: IP de destino
            
        Returns:
            bool: True se DDoS detectado
        """
        key = f"ddos->{dst_ip}"
        self.connection_tracker[key].append({
            'src': src_ip,
            'timestamp': datetime.now()
        })
        
        # Limpa conexões antigas
        self.connection_tracker[key] = [
            conn for conn in self.connection_tracker[key]
            if (datetime.now() - conn['timestamp']).seconds < 10
        ]
        
        # Detecta volume alto de conexões em curto período
        if len(self.connection_tracker[key]) > 100:
            return True
        
        return False
    
    def process_packet(self, packet):
        """
        Processa um pacote capturado
        
        Args:
            packet: Pacote scapy
        """
        if not packet.haslayer(scapy.IP):
            return
        
        src_ip = packet[scapy.IP].src
        dst_ip = packet[scapy.IP].dst
        
        # Extrai features
        features = self.extract_features(packet)
        
        # Detecção baseada em regras
        alerts = []
        
        # Port Scan
        if packet.haslayer(scapy.TCP):
            dst_port = packet[scapy.TCP].dport
            if self.detect_port_scan(src_ip, dst_ip, dst_port):
                alerts.append({
                    'type': 'PORT_SCAN',
                    'src': src_ip,
                    'dst': dst_ip,
                    'severity': 'HIGH',
                    'details': 'Múltiplas portas sendo scaneadas'
                })
        
        # DDoS
        if self.detect_ddos(src_ip, dst_ip):
            alerts.append({
                'type': 'DDOS',
                'src': src_ip,
                'dst': dst_ip,
                'severity': 'CRITICAL',
                'details': 'Volume anormal de tráfego detectado'
            })
        
        # Detecção por ML (se modelo disponível)
        if self.model:
            features_array = np.array([list(features.values())])
            prediction = self.model.predict_proba(features_array)[0]
            
            if prediction[1] > self.threshold:  # Classe maliciosa
                alerts.append({
                    'type': 'ANOMALY',
                    'src': src_ip,
                    'dst': dst_ip,
                    'severity': 'MEDIUM',
                    'details': f'Padrão anômalo detectado (confiança: {prediction[1]:.2%})',
                    'confidence': prediction[1]
                })
        
        # Registra alertas
        for alert in alerts:
            self.log_alert(alert)
    
    def log_alert(self, alert):
        """
        Registra um alerta de segurança
        
        Args:
            alert: Dicionário com informações do alerta
        """
        message = (
            f"ALERT [{alert['severity']}]: {alert['type']}\n"
            f"  Origem: {alert['src']}\n"
            f"  Destino: {alert['dst']}\n"
            f"  Detalhes: {alert['details']}"
        )
        
        if alert['severity'] == 'CRITICAL':
            logging.critical(message)
        elif alert['severity'] == 'HIGH':
            logging.error(message)
        else:
            logging.warning(message)
    
    def start_monitoring(self, interface='eth0', packet_count=0):
        """
        Inicia monitoramento de rede
        
        Args:
            interface: Interface de rede a monitorar
            packet_count: Número de pacotes (0 = infinito)
        """
        logging.info(f"Iniciando monitoramento na interface {interface}")
        logging.info("Pressione Ctrl+C para parar")
        
        try:
            scapy.sniff(
                iface=interface,
                prn=self.process_packet,
                count=packet_count,
                store=False
            )
        except KeyboardInterrupt:
            logging.info("\nMonitoramento interrompido pelo usuário")
        except Exception as e:
            logging.error(f"Erro durante monitoramento: {e}")


def main():
    parser = argparse.ArgumentParser(
        description='Sistema de Detecção de Intrusão com ML'
    )
    parser.add_argument(
        '--interface',
        default='eth0',
        help='Interface de rede a monitorar'
    )
    parser.add_argument(
        '--model',
        default='models/ids_model.pkl',
        help='Caminho para o modelo treinado'
    )
    parser.add_argument(
        '--threshold',
        type=float,
        default=0.8,
        help='Threshold de confiança para alertas (0-1)'
    )
    parser.add_argument(
        '--count',
        type=int,
        default=0,
        help='Número de pacotes a capturar (0 = infinito)'
    )
    
    args = parser.parse_args()
    
    # Inicializa IDS
    ids = NetworkIDS(model_path=args.model, threshold=args.threshold)
    
    # Inicia monitoramento
    ids.start_monitoring(interface=args.interface, packet_count=args.count)


if __name__ == '__main__':
    main()
