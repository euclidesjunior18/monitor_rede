# Monitor de Rede & Dispositivos

Aplicativo desenvolvido em Python com interface gráfica GTK 3 moderna para monitoramento de rede local e tráfego de dados no Linux.

## Funcionalidades

1. **Aba "Dispositivos Conectados"**:
   - Varredura assíncrona multithread de todos os hosts da sub-rede local.
   - Detecção do **Endereço IP**, **Nome do Dispositivo (Hostname)**, **Endereço MAC**, **Fabricante da Placa de Rede (OUI)** e **Latência (Ping ms)**.
   - Reconhecimento automático do computador local e identificação de fornecedores com base no banco de dados IEEE OUI.
   - Suporte a seleção de interface de rede (Wi-Fi, Ethernet, etc.) e cancelamento de varredura.

2. **Aba "Informações Locais & Tráfego"**:
   - Medição e exibição em tempo real (1 segundo) da **Taxa de Upload (Up)** e **Taxa de Download (Down)** em B/s, KB/s ou MB/s.
   - Contadores acumulados de **Bytes Recebidos** e **Bytes Enviados**.
   - Tabela detalhada por interface de rede com IPs, MACs, taxas atuais, totais transferidos e contagem de pacotes.

## Requisitos

- Python 3
- PyGObject / GTK 3 (`python3-gi`)
- psutil
- netifaces

Em sistemas baseados em Debian/Ubuntu/Mint:
```bash
sudo apt install python3-gi python3-gi-cairo gir1.2-gtk-3.0 ieee-data
pip install psutil netifaces
```

## Como Executar

Execute diretamente via terminal:

```bash
python3 monitor_rede.py
```
