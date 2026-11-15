#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Monitor de Rede & Dispositivos
Funcionalidades:
- Varredura de dispositivos conectados na rede local (IP, MAC, Fabricante/OUI, Nome do Host, Latência, Status).
- Aba de Informações Locais com tráfego em tempo real (Upload / Download, Taxa KB/s, Total de Bytes, Pacotes, Erros, IPs e Interfaces).
- Interface moderna em GTK 3.
"""

import sys
import os
import time
import socket
import threading
import subprocess
import ipaddress
from concurrent.futures import ThreadPoolExecutor

import psutil
import netifaces
import gi

gi.require_version('Gtk', '3.0')
gi.require_version('GLib', '2.0')
from gi.repository import Gtk, GLib, Gdk, Pango

# -------------------------------------------------------------
# Utilitários de Formatação e Fabricantes (OUI)
# -------------------------------------------------------------
def format_bytes(bytes_num):
    """Formata bytes para exibição legível (KB, MB, GB)."""
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if bytes_num < 1024.0:
            return f"{bytes_num:.2f} {unit}"
        bytes_num /= 1024.0
    return f"{bytes_num:.2f} PB"


class OUILookup:
    """Carrega o banco de dados de fabricantes de placas de rede (OUI)."""
    def __init__(self):
        self.vendors = {}
        self._load_oui()

    def _load_oui(self):
        paths = [
            "/usr/share/ieee-data/oui.txt",
            "/var/lib/ieee-data/oui.txt",
            "/usr/share/misc/oui.txt"
        ]
        for path in paths:
            if os.path.exists(path):
                try:
                    with open(path, "r", encoding="utf-8", errors="ignore") as f:
                        for line in f:
                            if "(hex)" in line:
                                parts = line.split("(hex)")
                                prefix = parts[0].strip().replace("-", ":").upper()
                                vendor = parts[1].strip()
                                self.vendors[prefix] = vendor
                    break
                except Exception as e:
                    print(f"Erro ao ler {path}: {e}")

    def lookup(self, mac):
        if not mac or mac == "Desconhecido":
            return "Desconhecido"
        norm_mac = mac.upper().replace("-", ":")
        parts = norm_mac.split(":")
        if len(parts) >= 3:
            prefix = ":".join(parts[:3])
            return self.vendors.get(prefix, "Fabricante Desconhecido")
        return "Desconhecido"


# -------------------------------------------------------------
# Mecanismo de Descoberta de Rede (Scanner)
# -------------------------------------------------------------
class NetworkScanner:
    def __init__(self, oui_lookup):
        self.oui_lookup = oui_lookup
        self.is_scanning = False
        self._cancel_scan = False

    def get_local_interfaces(self):
        """Retorna lista de interfaces de rede ativas com IPv4."""
        active_ifaces = []
        for iface in netifaces.interfaces():
            if iface == 'lo':
                continue
            addrs = netifaces.ifaddresses(iface)
            if netifaces.AF_INET in addrs:
                for entry in addrs[netifaces.AF_INET]:
                    ip = entry.get('addr')
                    netmask = entry.get('netmask')
                    if ip and netmask and not ip.startswith('127.'):
                        active_ifaces.append({
                            'interface': iface,
                            'ip': ip,
                            'netmask': netmask,
                            'mac': self._get_mac_for_iface(iface)
                        })
        return active_ifaces

    def _get_mac_for_iface(self, iface):
        addrs = netifaces.ifaddresses(iface)
        if netifaces.AF_LINK in addrs:
            for entry in addrs[netifaces.AF_LINK]:
                mac = entry.get('addr')
                if mac:
                    return mac.upper()
        return "Desconhecido"

    def read_arp_table(self):
        """Lê a tabela ARP do kernel Linux (/proc/net/arp)."""
        arp_entries = {}
        try:
            with open("/proc/net/arp", "r") as f:
                lines = f.readlines()[1:]
                for line in lines:
                    parts = line.split()
                    if len(parts) >= 6:
                        ip = parts[0]
                        hw_addr = parts[3].upper()
                        flags = parts[2]
                        if hw_addr != "00:00:00:00:00:00" and flags != "0x0":
                            arp_entries[ip] = hw_addr
        except Exception as e:
            print(f"Erro ao ler /proc/net/arp: {e}")
        return arp_entries

    def scan_network(self, iface_info, progress_cb, device_found_cb, done_cb):
        """Executa varredura com threads na sub-rede."""
        self.is_scanning = True
        self._cancel_scan = False

        def worker():
            try:
                ip_net = ipaddress.IPv4Network(f"{iface_info['ip']}/{iface_info['netmask']}", strict=False)
                hosts = list(ip_net.hosts())
                total = len(hosts)

                # Inclui de imediato o computador local
                my_ip = iface_info['ip']
                my_mac = iface_info['mac']
                my_host = socket.gethostname()
                my_vendor = self.oui_lookup.lookup(my_mac)
                GLib.idle_add(device_found_cb, {
                    'ip': my_ip,
                    'hostname': f"{my_host} (Este Computador)",
                    'mac': my_mac,
                    'vendor': my_vendor,
                    'latency': "0.0 ms",
                    'status': "Ativo"
                })

                completed = 0

                def ping_host(target_ip_str):
                    if self._cancel_scan:
                        return None
                    # Ping rápido (1 envio, timeout de 1s)
                    t0 = time.time()
                    res = subprocess.run(
                        ['ping', '-c', '1', '-W', '1', target_ip_str],
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE
                    )
                    elapsed = (time.time() - t0) * 1000
                    if res.returncode == 0:
                        return (target_ip_str, f"{elapsed:.1f} ms")
                    return None

                # Dispara pings concorrentes para alimentar a tabela ARP
                with ThreadPoolExecutor(max_workers=64) as executor:
                    futures = {executor.submit(ping_host, str(h)): str(h) for h in hosts if str(h) != my_ip}
                    for f in futures:
                        if self._cancel_scan:
                            break
                        f.result()
                        completed += 1
                        if progress_cb and completed % 5 == 0:
                            perc = completed / total
                            GLib.idle_add(progress_cb, perc, completed, total)

                # Coleta entradas da tabela ARP
                arp_table = self.read_arp_table()

                def resolve_info(target_ip, mac_addr):
                    hostname = "Desconhecido"
                    try:
                        name_info = socket.gethostbyaddr(target_ip)
                        hostname = name_info[0]
                    except Exception:
                        pass
                    
                    # Medição de latência final
                    latency = "N/A"
                    res = subprocess.run(['ping', '-c', '1', '-W', '1', target_ip], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                    if res.returncode == 0:
                        for line in res.stdout.decode('utf-8', errors='ignore').splitlines():
                            if 'time=' in line:
                                try:
                                    latency = line.split('time=')[1].split()[0] + " ms"
                                except Exception:
                                    pass

                    vendor = self.oui_lookup.lookup(mac_addr)
                    return {
                        'ip': target_ip,
                        'hostname': hostname,
                        'mac': mac_addr,
                        'vendor': vendor,
                        'latency': latency,
                        'status': "Ativo"
                    }

                # Resolve nomes e detalha os dispositivos encontrados
                with ThreadPoolExecutor(max_workers=20) as executor:
                    res_futures = []
                    for ip_found, mac_found in arp_table.items():
                        # Certifica que pertence à sub-rede escaneada
                        try:
                            if ipaddress.IPv4Address(ip_found) in ip_net and ip_found != my_ip:
                                res_futures.append(executor.submit(resolve_info, ip_found, mac_found))
                        except Exception:
                            continue

                    for rf in res_futures:
                        dev = rf.result()
                        if dev:
                            GLib.idle_add(device_found_cb, dev)

            except Exception as e:
                print(f"Erro na varredura: {e}")
            finally:
                self.is_scanning = False
                GLib.idle_add(done_cb)

        t = threading.Thread(target=worker, daemon=True)
        t.start()

    def cancel(self):
        self._cancel_scan = True


# -------------------------------------------------------------
# Interface Gráfica GTK
# -------------------------------------------------------------
class NetworkMonitorWindow(Gtk.Window):
    def __init__(self):
        super().__init__(title="Monitor de Rede & Dispositivos")
        self.set_default_size(960, 640)
        self.set_position(Gtk.WindowPosition.CENTER)

        # OUI e Scanner
        self.oui = OUILookup()
        self.scanner = NetworkScanner(self.oui)
        self.found_devices = {}  # ip -> dict

        # Monitor de tráfego
        self.last_io_time = time.time()
        self.last_io_counters = psutil.net_io_counters(pernic=True)

        self._build_ui()
        self._start_traffic_timer()

    def _build_ui(self):
        # HeaderBar moderna
        header = Gtk.HeaderBar()
        header.set_show_close_button(True)
        header.props.title = "Monitor de Rede"
        header.props.subtitle = "Descoberta de dispositivos & Tráfego de dados"
        self.set_titlebar(header)

        # Botão Atualizar / Escanear na HeaderBar
        self.btn_scan = Gtk.Button(label="  Escanear Rede")
        scan_icon = Gtk.Image.new_from_icon_name("view-refresh-symbolic", Gtk.IconSize.BUTTON)
        self.btn_scan.set_image(scan_icon)
        self.btn_scan.set_always_show_image(True)
        self.btn_scan.connect("clicked", self.on_scan_clicked)
        header.pack_start(self.btn_scan)

        # Seletor de Interface na HeaderBar
        self.combo_iface = Gtk.ComboBoxText()
        self._populate_interfaces()
        header.pack_start(self.combo_iface)

        # Notebook com Abas
        notebook = Gtk.Notebook()
        self.add(notebook)

        # Aba 1: Dispositivos da Rede
        devices_box = self._create_devices_tab()
        notebook.append_page(devices_box, Gtk.Label(label=" Dispositivos Conectados "))

        # Aba 2: Informações Locais & Tráfego (Upload / Download)
        traffic_box = self._create_local_info_tab()
        notebook.append_page(traffic_box, Gtk.Label(label=" Informações Locais & Tráfego "))

    def _populate_interfaces(self):
        self.interfaces = self.scanner.get_local_interfaces()
        self.combo_iface.remove_all()
        for idx, iface in enumerate(self.interfaces):
            self.combo_iface.append_text(f"{iface['interface']} ({iface['ip']})")
        if self.interfaces:
            self.combo_iface.set_active(0)

    # -------------------------------------------------------------
    # Construção da Aba de Dispositivos
    # -------------------------------------------------------------
    def _create_devices_tab(self):
        vbox = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8)
        vbox.set_border_width(12)

        # Barra de Progresso
        self.progress_bar = Gtk.ProgressBar()
        self.progress_bar.set_show_text(True)
        self.progress_bar.set_text("Pronto para escanear.")
        vbox.pack_start(self.progress_bar, False, False, 0)

        # Tabela (TreeView) de dispositivos
        # Colunas: IP, Nome do Dispositivo, Endereço MAC, Fabricante/OUI, Latência, Status
        self.device_store = Gtk.ListStore(str, str, str, str, str, str)
        self.tree_view = Gtk.TreeView(model=self.device_store)
        self.tree_view.set_rules_hint(True)

        cols = [
            ("Endereço IP", 0, 140),
            ("Nome do Host", 1, 180),
            ("Endereço MAC", 2, 160),
            ("Fabricante da Placa", 3, 240),
            ("Latência", 4, 90),
            ("Status", 5, 80)
        ]

        for title, col_idx, min_width in cols:
            renderer = Gtk.CellRendererText()
            column = Gtk.TreeViewColumn(title, renderer, text=col_idx)
            column.set_resizable(True)
            column.set_sort_column_id(col_idx)
            column.set_min_width(min_width)
            self.tree_view.append_column(column)

        scroll = Gtk.ScrolledWindow()
        scroll.set_policy(Gtk.PolicyType.AUTOMATIC, Gtk.PolicyType.AUTOMATIC)
        scroll.add(self.tree_view)
        vbox.pack_start(scroll, True, True, 0)

        # Barra inferior de estatísticas
        self.lbl_devices_status = Gtk.Label(label="0 dispositivos encontrados.")
        self.lbl_devices_status.set_xalign(0)
        vbox.pack_start(self.lbl_devices_status, False, False, 4)

        return vbox

    # -------------------------------------------------------------
    # Construção da Aba de Informações Locais & Tráfego
    # -------------------------------------------------------------
    def _create_local_info_tab(self):
        vbox = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=14)
        vbox.set_border_width(16)

        # Painel Superior: Cartões de Taxa Up/Down em tempo real
        cards_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=16)
        cards_box.set_homogeneous(True)

        # Cartão Download
        card_down = Gtk.Frame(label=" Taxa de Download (Entrada) ")
        box_down = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=6)
        box_down.set_border_width(14)
        self.lbl_rate_down = Gtk.Label()
        self.lbl_rate_down.set_markup("<span size='xx-large' weight='bold' foreground='#2e7d32'>0.00 KB/s</span>")
        self.lbl_total_down = Gtk.Label(label="Total recebido: 0 B")
        box_down.pack_start(self.lbl_rate_down, True, True, 0)
        box_down.pack_start(self.lbl_total_down, True, True, 0)
        card_down.add(box_down)
        cards_box.pack_start(card_down, True, True, 0)

        # Cartão Upload
        card_up = Gtk.Frame(label=" Taxa de Upload (Saída) ")
        box_up = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=6)
        box_up.set_border_width(14)
        self.lbl_rate_up = Gtk.Label()
        self.lbl_rate_up.set_markup("<span size='xx-large' weight='bold' foreground='#1565c0'>0.00 KB/s</span>")
        self.lbl_total_up = Gtk.Label(label="Total enviado: 0 B")
        box_up.pack_start(self.lbl_rate_up, True, True, 0)
        box_up.pack_start(self.lbl_total_up, True, True, 0)
        card_up.add(box_up)
        cards_box.pack_start(card_up, True, True, 0)

        vbox.pack_start(cards_box, False, False, 0)

        # Detalhes das Interfaces Locais (Tabela de Interfaces e Tráfego)
        frame_details = Gtk.Frame(label=" Estatísticas por Interface de Rede ")
        box_details = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8)
        box_details.set_border_width(10)

        # Store: Interface, IP, MAC, Download Rate, Upload Rate, Total Baixado, Total Enviado, Pacotes
        self.iface_store = Gtk.ListStore(str, str, str, str, str, str, str, str)
        self.iface_tree = Gtk.TreeView(model=self.iface_store)
        self.iface_tree.set_rules_hint(True)

        iface_cols = [
            ("Interface", 0, 100),
            ("IP Local", 1, 130),
            ("MAC", 2, 140),
            ("Down (Taxa)", 3, 100),
            ("Up (Taxa)", 4, 100),
            ("Total Down", 5, 110),
            ("Total Up", 6, 110),
            ("Pacotes (E/S)", 7, 130)
        ]

        for title, col_idx, min_width in iface_cols:
            renderer = Gtk.CellRendererText()
            column = Gtk.TreeViewColumn(title, renderer, text=col_idx)
            column.set_resizable(True)
            column.set_min_width(min_width)
            self.iface_tree.append_column(column)

        scroll_iface = Gtk.ScrolledWindow()
        scroll_iface.set_policy(Gtk.PolicyType.AUTOMATIC, Gtk.PolicyType.AUTOMATIC)
        scroll_iface.add(self.iface_tree)
        box_details.pack_start(scroll_iface, True, True, 0)
        frame_details.add(box_details)

        vbox.pack_start(frame_details, True, True, 0)

        # Caixa com dados do sistema
        self.lbl_sys_info = Gtk.Label()
        self.lbl_sys_info.set_xalign(0)
        self._update_system_info_label()
        vbox.pack_start(self.lbl_sys_info, False, False, 0)

        return vbox

    def _update_system_info_label(self):
        hostname = socket.gethostname()
        try:
            fqdn = socket.getfqdn()
        except Exception:
            fqdn = hostname
        self.lbl_sys_info.set_markup(
            f"<b>Nome da Máquina:</b> {hostname}  |  <b>FQDN:</b> {fqdn}  |  <b>Atualização em tempo real:</b> 1 segundo"
        )

    # -------------------------------------------------------------
    # Temporizador de Tráfego de Rede (1s)
    # -------------------------------------------------------------
    def _start_traffic_timer(self):
        GLib.timeout_add_seconds(1, self._update_traffic_metrics)

    def _update_traffic_metrics(self):
        now = time.time()
        elapsed = now - self.last_io_time
        if elapsed <= 0:
            return True

        current_io = psutil.net_io_counters(pernic=True)
        total_recv_rate = 0.0
        total_sent_rate = 0.0
        total_bytes_recv = 0
        total_bytes_sent = 0

        # Lista atualizada de interfaces
        self.iface_store.clear()

        # Obter mapeamento de IPs locais
        iface_ips = {}
        iface_macs = {}
        for iface in netifaces.interfaces():
            addrs = netifaces.ifaddresses(iface)
            ip_val = "N/A"
            if netifaces.AF_INET in addrs:
                ip_val = addrs[netifaces.AF_INET][0].get('addr', 'N/A')
            mac_val = "N/A"
            if netifaces.AF_LINK in addrs:
                mac_val = addrs[netifaces.AF_LINK][0].get('addr', 'N/A')
            iface_ips[iface] = ip_val
            iface_macs[iface] = mac_val.upper()

        for iface_name, cur_stats in current_io.items():
            prev_stats = self.last_io_counters.get(iface_name)
            if prev_stats:
                recv_diff = cur_stats.bytes_recv - prev_stats.bytes_recv
                sent_diff = cur_stats.bytes_sent - prev_stats.bytes_sent
                rate_recv = recv_diff / elapsed
                rate_sent = sent_diff / elapsed
            else:
                rate_recv = 0.0
                rate_sent = 0.0

            if iface_name != 'lo':
                total_recv_rate += rate_recv
                total_sent_rate += rate_sent
                total_bytes_recv += cur_stats.bytes_recv
                total_bytes_sent += cur_stats.bytes_sent

            self.iface_store.append([
                iface_name,
                iface_ips.get(iface_name, "N/A"),
                iface_macs.get(iface_name, "N/A"),
                f"{format_bytes(rate_recv)}/s",
                f"{format_bytes(rate_sent)}/s",
                format_bytes(cur_stats.bytes_recv),
                format_bytes(cur_stats.bytes_sent),
                f"{cur_stats.packets_recv} / {cur_stats.packets_sent}"
            ])

        self.last_io_time = now
        self.last_io_counters = current_io

        # Atualiza labels de taxa
        self.lbl_rate_down.set_markup(
            f"<span size='xx-large' weight='bold' foreground='#2e7d32'>{format_bytes(total_recv_rate)}/s</span>"
        )
        self.lbl_rate_up.set_markup(
            f"<span size='xx-large' weight='bold' foreground='#1565c0'>{format_bytes(total_sent_rate)}/s</span>"
        )
        self.lbl_total_down.set_text(f"Total recebido: {format_bytes(total_bytes_recv)}")
        self.lbl_total_up.set_text(f"Total enviado: {format_bytes(total_bytes_sent)}")

        return True

    # -------------------------------------------------------------
    # Controle da Varredura
    # -------------------------------------------------------------
    def on_scan_clicked(self, widget):
        if self.scanner.is_scanning:
            self.scanner.cancel()
            self.btn_scan.set_label("  Escanear Rede")
            self.progress_bar.set_text("Varredura cancelada.")
            return

        active_idx = self.combo_iface.get_active()
        if active_idx < 0 or active_idx >= len(self.interfaces):
            self.progress_bar.set_text("Nenhuma interface selecionada.")
            return

        selected_iface = self.interfaces[active_idx]
        self.found_devices.clear()
        self.device_store.clear()

        self.btn_scan.set_label("  Parar Varredura")
        self.progress_bar.set_fraction(0.0)
        self.progress_bar.set_text(f"Varrendo rede {selected_iface['ip']}...")

        self.scanner.scan_network(
            selected_iface,
            progress_cb=self.on_scan_progress,
            device_found_cb=self.on_device_found,
            done_cb=self.on_scan_done
        )

    def on_scan_progress(self, fraction, current, total):
        self.progress_bar.set_fraction(fraction)
        self.progress_bar.set_text(f"Varrendo hosts: {current} de {total} ({int(fraction * 100)}%)")

    def on_device_found(self, device):
        ip = device['ip']
        if ip not in self.found_devices:
            self.found_devices[ip] = device
            self.device_store.append([
                device['ip'],
                device['hostname'],
                device['mac'],
                device['vendor'],
                device['latency'],
                device['status']
            ])
            count = len(self.found_devices)
            self.lbl_devices_status.set_text(f"{count} dispositivo(s) encontrado(s) na rede.")

    def on_scan_done(self):
        self.btn_scan.set_label("  Escanear Rede")
        self.progress_bar.set_fraction(1.0)
        count = len(self.found_devices)
        self.progress_bar.set_text(f"Varredura concluída. {count} dispositivo(s) detectado(s).")


def main():
    app = NetworkMonitorWindow()
    app.connect("destroy", Gtk.main_quit)
    app.show_all()
    Gtk.main()


if __name__ == "__main__":
    main()
