
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import time
import threading
import collections
import platform
import os
import sys

try:
    import pywifi
    from pywifi import const
    PYWIFI_AVAILABLE = True
except ImportError:
    PYWIFI_AVAILABLE = False
    print("[AVISO IMPORTANTE] PyWiFi não pôde ser importado. Funcionalidades de scan de redes Wi-Fi estarão desabilitadas.")

try:
    import netifaces
    NETIFACES_AVAILABLE = True
except ImportError:
    NETIFACES_AVAILABLE = False
    print("[AVISO IMPORTANTE] Netifaces não pôde ser importado. Funcionalidades de obtenção de detalhes da interface de rede estarão desabilitadas.")

try:
    import ipaddress 
    IPADDRESS_AVAILABLE = True
except ImportError:
    IPADDRESS_AVAILABLE = False
    print("[AVISO IMPORTANTE] Módulo 'ipaddress' não pôde ser importado.")

try:
    from scapy.all import ARP, Ether, srp, sr1, IP, ICMP
    from scapy.all import conf as scapy_conf
    SCAPY_AVAILABLE = True
    if SCAPY_AVAILABLE:
        scapy_conf.verb = 0 
except ImportError:
    SCAPY_AVAILABLE = False
  


APP_VERSION = "v0.3.2 (Npcap Discussion)"

AKM_TYPES = {}
CIPHER_TYPES = {}
AUTH_TYPES = {}

if PYWIFI_AVAILABLE:
    AKM_TYPES = {
        const.AKM_TYPE_NONE: "Nenhum (Aberta/WEP Estático)",
        const.AKM_TYPE_WPA: "WPA",
        const.AKM_TYPE_WPAPSK: "WPA-PSK",
        const.AKM_TYPE_WPA2: "WPA2",
        const.AKM_TYPE_WPA2PSK: "WPA2-PSK",
    }
    CIPHER_TYPES = {
        const.CIPHER_TYPE_NONE: "Nenhum",
        const.CIPHER_TYPE_WEP: "WEP",
        const.CIPHER_TYPE_TKIP: "TKIP",
        const.CIPHER_TYPE_CCMP: "CCMP (AES)",
    }
    AUTH_TYPES = {
        const.AUTH_ALG_OPEN: "Aberta",
        const.AUTH_ALG_SHARED: "Chave Compartilhada (WEP)",
    }


def freq_to_channel(freq_mhz):
    if not isinstance(freq_mhz, (int, float)) or freq_mhz <= 0: return "N/A"
    try:
        freq = int(freq_mhz)
        if 2412 <= freq <= 2484: return 14 if freq == 2484 else (freq - 2407) // 5
        elif 5170 <= freq <= 5825: return (freq - 5000) // 5
        elif 5925 <= freq <= 7125: return (freq - 5950) // 5 + 1
        else: return f"{freq}MHz"
    except ValueError: return "N/A"

def rssi_to_quality(rssi):
    if not isinstance(rssi, (int, float)): return "N/A"
    try:
        rssi_val = int(rssi)
        if rssi_val >= -50: quality = 100
        elif rssi_val <= -100: quality = 0
        else: quality = 2 * (rssi_val + 100)
        return max(0, min(100, quality))
    except ValueError: return "N/A"


def log_message(results_widget, message):
    if results_widget and results_widget.winfo_exists():
        results_widget.insert(tk.END, message)
        results_widget.see(tk.END)
        results_widget.update_idletasks()


def get_wifi_scan_results(results_widget):
    if not PYWIFI_AVAILABLE:
        log_message(results_widget, "[ERRO] Biblioteca PyWiFi não está disponível. Scan Wi-Fi cancelado.\n")
        return []
        
    log_message(results_widget, "[INFO] Iniciando scan de redes Wi-Fi com pywifi...\n")
    wifi = None; iface = None
    try:
        wifi = pywifi.PyWiFi()
        if not wifi.interfaces():
            log_message(results_widget, "[ERRO] Nenhuma interface Wi-Fi encontrada pelo pywifi.\n")
            return []
        
        iface = wifi.interfaces()[0]
        log_message(results_widget, f"[INFO] Usando interface Wi-Fi: {iface.name()}\n")
        log_message(results_widget, "[INFO] Solicitando scan de redes (pode levar alguns segundos)...\n")
        iface.scan()
        time.sleep(8) 

        scan_results_raw = iface.scan_results()
        if not scan_results_raw:
            log_message(results_widget, "[INFO] Nenhuma rede encontrada ou scan falhou.\n")
            return []

        log_message(results_widget, f"[INFO] Scan concluído. {len(scan_results_raw)} redes encontradas.\n")
        
        parsed_results = []
        for profile in scan_results_raw:
            ssid = profile.ssid if profile.ssid else "SSID Oculto"
            bssid = profile.bssid if profile.bssid else "N/A"
            signal_rssi = profile.signal
            signal_quality_val = rssi_to_quality(signal_rssi)
            signal_quality_str = f"{signal_quality_val}%" if signal_quality_val != "N/A" else "N/A"
            freq_mhz = profile.freq if hasattr(profile, 'freq') else "N/A"
            channel = freq_to_channel(freq_mhz)

          
            akm_values = profile.akm
            if isinstance(akm_values, int): akm_values = [akm_values]
            elif not isinstance(akm_values, (list, tuple)): akm_values = []
            akm_strings = [AKM_TYPES.get(a, f"AKM({a})") for a in akm_values]
            
            auth_values = profile.auth
            if isinstance(auth_values, int): auth_values = [auth_values]
            elif not isinstance(auth_values, (list, tuple)): auth_values = []
         

            cipher_values = profile.cipher
            if isinstance(cipher_values, int): cipher_values = [cipher_values]
            elif not isinstance(cipher_values, (list, tuple)): cipher_values = []
            cipher_strings = [CIPHER_TYPES.get(c, f"Cipher({c})") for c in cipher_values]
            
            simple_security = "Aberta"
            if any(akm_type in akm_values for akm_type in [const.AKM_TYPE_WPAPSK, const.AKM_TYPE_WPA2PSK]):
                if const.AKM_TYPE_WPA2PSK in akm_values and const.CIPHER_TYPE_CCMP in cipher_values:
                    simple_security = "WPA2-PSK (AES/CCMP)"
                elif const.AKM_TYPE_WPAPSK in akm_values and const.CIPHER_TYPE_TKIP in cipher_values:
                    simple_security = "WPA-PSK (TKIP)"
                elif const.AKM_TYPE_WPA2PSK in akm_values:
                    simple_security = f"WPA2-PSK ({', '.join(cipher_strings)})"
                else:
                    simple_security = f"WPA-PSK ({', '.join(cipher_strings)})"
            elif any(akm_type in akm_values for akm_type in [const.AKM_TYPE_WPA, const.AKM_TYPE_WPA2]):
                 simple_security = "WPA/WPA2 Enterprise"
            elif const.CIPHER_TYPE_WEP in cipher_values and (not akm_values or const.AKM_TYPE_NONE in akm_values):
                 simple_security = "WEP"
            elif (not akm_values or const.AKM_TYPE_NONE in akm_values) and \
                 (not cipher_values or const.CIPHER_TYPE_NONE in cipher_values):
                 simple_security = "Aberta"

            parsed_results.append({
                "SSID": ssid, "BSSID": bssid, "Sinal (RSSI)": signal_rssi, 
                "Qualidade": signal_quality_str, "Frequência": f"{freq_mhz} MHz" if isinstance(freq_mhz, (int,float)) else freq_mhz,
                "Canal": channel, "Segurança (Simplificada)": simple_security, "RawProfile": profile
            })
        return parsed_results
    except AttributeError as ae:
        log_message(results_widget, f"[ERRO PYWIFI ATTR] Atributo não encontrado: {ae}. Verifique a versão do pywifi e constantes.\n")
        return []
    except Exception as e:
        log_message(results_widget, f"[ERRO] Ocorreu um erro com pywifi durante o scan: {e}\n")
        import traceback; log_message(results_widget, traceback.format_exc() + "\n")
        return []


def get_active_network_interface_details(results_widget):
  
    if not NETIFACES_AVAILABLE or not IPADDRESS_AVAILABLE:
        log_message(results_widget, "[ERRO] Bibliotecas Netifaces ou IPAddress não disponíveis. Análise da interface cancelada.\n")
        return None
    try:
        gateways = netifaces.gateways()
        if 'default' not in gateways or not gateways['default'] or netifaces.AF_INET not in gateways['default']:
            log_message(results_widget, "[AVISO] Nenhuma gateway IPv4 padrão encontrada.\n")
            return None
        default_gw_info = gateways['default'][netifaces.AF_INET]
        gw_ip, iface_name_from_netifaces = default_gw_info[0], default_gw_info[1]
        
    
        scapy_iface_to_use = iface_name_from_netifaces
        if platform.system() == "Windows" and SCAPY_AVAILABLE:
            try:
               
                from scapy.arch.windows import get_windows_if_list 
                
              
                normalized_netifaces_guid = iface_name_from_netifaces.strip('{}').lower()

                found_match = False
                for if_dict in get_windows_if_list():
                    scapy_guid = if_dict.get('guid', '').strip('{}').lower()
                    if scapy_guid == normalized_netifaces_guid:
                        
                        scapy_iface_to_use = if_dict.get('name', iface_name_from_netifaces)
                        log_message(results_widget, f"[INFO] Interface Netifaces '{iface_name_from_netifaces}' mapeada para Scapy iface '{scapy_iface_to_use}'.\n")
                        found_match = True
                        break
                if not found_match:
                    log_message(results_widget, f"[AVISO] Não foi possível mapear GUID '{iface_name_from_netifaces}' para nome Scapy. Usando '{iface_name_from_netifaces}' (pode falhar com Scapy).\n")
            except Exception as e_map:
                log_message(results_widget, f"[AVISO] Erro ao tentar mapear nome de interface para Scapy: {e_map}. Usando '{iface_name_from_netifaces}'.\n")

        log_message(results_widget, f"[INFO] Gateway Padrão: {gw_ip} via Interface (Netifaces): '{iface_name_from_netifaces}', (Para Scapy): '{scapy_iface_to_use}'\n")

        iface_addrs = netifaces.ifaddresses(iface_name_from_netifaces) # Usar o nome original do netifaces para obter IPs
        if netifaces.AF_INET not in iface_addrs or not iface_addrs[netifaces.AF_INET]:
            log_message(results_widget, f"[AVISO] Interface '{iface_name_from_netifaces}' não possui um endereço IPv4.\n")
            return None
        
        ipv4_info = iface_addrs[netifaces.AF_INET][0]
        ip_addr = ipv4_info['addr']; netmask = ipv4_info['netmask']
        network = ipaddress.ip_network(f"{ip_addr}/{netmask}", strict=False)
        network_cidr = str(network)
        log_message(results_widget, f"[INFO] IP Local: {ip_addr}, Máscara: {netmask}, Rede (CIDR): {network_cidr}\n")
        return {"iface_name": scapy_iface_to_use, "ip_addr": ip_addr, "netmask": netmask, "gateway": gw_ip, "network_cidr": network_cidr, "original_iface_name": iface_name_from_netifaces}
    except Exception as e:
        log_message(results_widget, f"[ERRO] Falha ao obter detalhes da interface de rede: {e}\n")
        return None

def arp_scan_local_network(network_cidr, iface_name_scapy, results_widget):
   
    if not SCAPY_AVAILABLE:
        log_message(results_widget, "[ERRO] Scapy não está disponível. ARP scan cancelado.\n")
        return []
    log_message(results_widget, f"[INFO] Iniciando ARP scan na rede {network_cidr} via interface Scapy '{iface_name_scapy}'...\n")
    log_message(results_widget, "[AVISO] Requer privilégios de admin/root e pode demorar.\n")
    hosts_found = []
    try:
        ans, unans = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=network_cidr), timeout=3, iface=iface_name_scapy, verbose=False)
        if ans:
            log_message(results_widget, f"[INFO] {len(ans)} hosts responderam ao ARP scan:\n")
            for sent, received in ans:
                hosts_found.append({'ip': received.psrc, 'mac': received.hwsrc})
                log_message(results_widget, f"  IP: {received.psrc:<15} MAC: {received.hwsrc}\n")
        else: log_message(results_widget, "[INFO] Nenhum host respondeu ao ARP scan.\n")
    except PermissionError: log_message(results_widget, "[ERRO CRÍTICO] Permissão negada para ARP scan. Execute como admin/root.\n")
    except OSError as e: log_message(results_widget, f"[ERRO CRÍTICO] Erro de SO no ARP scan (interface '{iface_name_scapy}' válida? Npcap/libpcap?): {e}\n")
    except Exception as e: log_message(results_widget, f"[ERRO] Falha no ARP scan: {e}\n"); import traceback; log_message(results_widget, traceback.format_exc() + "\n")
    return hosts_found

def guess_os_by_ttl(target_ip, iface_name_scapy, results_widget):
   
    if not SCAPY_AVAILABLE: return "N/A (Scapy indisponível)"
    log_message(results_widget, f"  [OS-GUESS] Ping em {target_ip} para TTL (Interface Scapy: '{iface_name_scapy}')...\n")
    try:
        ans = sr1(IP(dst=target_ip)/ICMP(), timeout=1, verbose=False, iface=iface_name_scapy)
        if ans and ans.haslayer(IP):
            ttl = ans.getlayer(IP).ttl
            if 1<=ttl<=64: return f"Linux/Unix (TTL:{ttl})"
            elif 65<=ttl<=128: return f"Windows (TTL:{ttl})"
            else: return f"Outro/Desconhecido (TTL:{ttl})"
        else: log_message(results_widget, f"  [OS-GUESS] Sem resposta ICMP de {target_ip}.\n"); return "N/A (Sem Resposta ICMP)"
    except Exception as e: log_message(results_widget, f"  [OS-GUESS] Erro ao pingar {target_ip}: {e}\n"); return "N/A (Erro no Ping)"


def detect_arp_spoofing_signs(gateway_ip, iface_name_scapy, results_widget):
   
    if not SCAPY_AVAILABLE:
        log_message(results_widget, "[MITM-ARP] Scapy indisponível, impossível verificar ARP spoofing.\n")
        return False
    if not gateway_ip or not iface_name_scapy:
        log_message(results_widget, "[MITM-ARP] IP do Gateway ou nome da interface Scapy não fornecido.\n")
        return False
    log_message(results_widget, f"[MITM-ARP] Verificando ARP spoofing para gateway {gateway_ip} na interface Scapy '{iface_name_scapy}'...\n")
    log_message(results_widget, "[AVISO] Requer privilégios de admin/root.\n")
    detected_macs_for_gateway = set()
    possible_spoofing = False
    num_probes = 3; timeout_per_probe = 1
    try:
        for i in range(num_probes):
            log_message(results_widget, f"  [MITM-ARP-DEBUG] Sonda ARP {i+1}/{num_probes} para {gateway_ip}...\n")
            ans = sr1(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=gateway_ip), timeout=timeout_per_probe, iface=iface_name_scapy, verbose=False) 
            if ans and ans.haslayer(ARP) and ans.getlayer(ARP).op == 2:
                sender_mac = ans.getlayer(ARP).hwsrc; sender_ip = ans.getlayer(ARP).psrc
                if sender_ip == gateway_ip:
                    log_message(results_widget, f"    [MITM-ARP-DEBUG] Resposta ARP para {gateway_ip} veio de MAC: {sender_mac}\n")
                    detected_macs_for_gateway.add(sender_mac)
        if len(detected_macs_for_gateway) > 1:
            log_message(results_widget, f"[ALERTA MITM] MÚLTIPLOS MACs ({len(detected_macs_for_gateway)}) responderam para gateway ({gateway_ip}): {', '.join(detected_macs_for_gateway)}\n  FORTE INDICADOR de ARP spoofing!\n")
            possible_spoofing = True
        elif len(detected_macs_for_gateway) == 1:
            log_message(results_widget, f"[MITM-ARP] Apenas um MAC ({list(detected_macs_for_gateway)[0]}) respondeu para o gateway. Parece normal.\n")
        else:
            log_message(results_widget, f"[MITM-ARP] Nenhuma resposta ARP clara do gateway {gateway_ip}.\n")
    except PermissionError: log_message(results_widget, "[ERRO CRÍTICO] Permissão negada para teste de ARP spoofing. Execute como admin/root.\n")
    except OSError as e: log_message(results_widget, f"[ERRO CRÍTICO] Erro de SO no teste de ARP spoofing (interface '{iface_name_scapy}'? Npcap/libpcap?): {e}\n")
    except Exception as e: log_message(results_widget, f"[ERRO] Falha no teste de ARP spoofing: {e}\n"); import traceback; log_message(results_widget, traceback.format_exc() + "\n")
    return possible_spoofing


all_scanned_networks_global = []

def execute_wifi_scan_and_display(results_widget, scan_button):
    global all_scanned_networks_global
    all_scanned_networks_global = []
    try:
        networks = get_wifi_scan_results(results_widget)
        if networks:
            all_scanned_networks_global = networks
            log_message(results_widget, "\n--- Redes Encontradas (PyWiFi) ---\n")
            for net in networks: 
                log_message(results_widget, f"SSID: {net['SSID']}\n  BSSID: {net['BSSID']}\n  Sinal: {net['Sinal (RSSI)']} dBm ({net['Qualidade']})\n  Frequência: {net['Frequência']} (Canal: {net['Canal']})\n  Segurança: {net['Segurança (Simplificada)']}\n{'-'*30}\n")
        else: log_message(results_widget, "[INFO] Nenhuma rede Wi-Fi processada ou scan falhou.\n")
    except Exception as e:
        if results_widget and results_widget.winfo_exists(): log_message(results_widget, f"[ERRO GERAL NO SCAN WIFI] Ocorreu: {e}\n"); import traceback; log_message(results_widget, traceback.format_exc() + "\n")
    finally:
        if scan_button and scan_button.winfo_exists(): scan_button.config(state=tk.NORMAL)

def start_wifi_scan_thread(results_widget, scan_button):

    scan_button.config(state=tk.DISABLED)
    if results_widget and results_widget.winfo_exists():
        results_widget.config(state=tk.NORMAL)
        results_widget.delete('1.0', tk.END) 
        log_message(results_widget, "Iniciando scan de Wi-Fi (Fase 1)...\n")
    threading.Thread(target=execute_wifi_scan_and_display, args=(results_widget, scan_button), daemon=True).start()

def execute_lan_scan_and_display(results_widget, scan_button_lan):
    
    try:
        net_info = get_active_network_interface_details(results_widget)
        if net_info and net_info.get("network_cidr") and net_info.get("iface_name"):
            hosts = arp_scan_local_network(net_info["network_cidr"], net_info["iface_name"], results_widget)
            if hosts:
                log_message(results_widget, "\n--- Tentando identificar SO dos hosts encontrados (TTL) ---\n")
                for host in hosts:
                    os_guess = guess_os_by_ttl(host['ip'], net_info["iface_name"], results_widget)
                    log_message(results_widget, f"  IP: {host['ip']:<15} MAC: {host['mac']:<17}  SO Provável: {os_guess}\n")
            log_message(results_widget, "\n--- Análise da Rede Local Concluída ---\n")
        else:
            log_message(results_widget, "[ERRO] Não foi possível obter informações da rede para iniciar o scan da LAN.\n")
    except Exception as e:
        if results_widget and results_widget.winfo_exists(): log_message(results_widget, f"[ERRO GERAL NO SCAN LAN] Ocorreu: {e}\n"); import traceback; log_message(results_widget, traceback.format_exc() + "\n")
    finally:
        if scan_button_lan and scan_button_lan.winfo_exists(): scan_button_lan.config(state=tk.NORMAL)

def start_lan_scan_thread(results_widget, scan_button_lan):
  
    if not SCAPY_AVAILABLE:
        messagebox.showerror("Scapy Indisponível", "Scapy é necessário para o scan da LAN.")
        return
    scan_button_lan.config(state=tk.DISABLED)
    log_message(results_widget, "\n\n--- Iniciando Análise da Rede Local Conectada (Fase 2) ---\n")
    threading.Thread(target=execute_lan_scan_and_display, args=(results_widget, scan_button_lan), daemon=True).start()

def analyze_mitm_vulnerabilities_for_connected_network(results_widget):
   
    log_message(results_widget, "\n--- Análise de Vulnerabilidades MITM (Rede Conectada) ---\n")
    net_details = get_active_network_interface_details(results_widget)
    if not net_details or not net_details.get("gateway") or not net_details.get("iface_name"):
        log_message(results_widget, "[MITM-ERRO] Não foi possível obter detalhes da rede ativa. Análise MITM cancelada.\n")
        return

    gateway_ip = net_details["gateway"]
    iface_name_scapy = net_details["iface_name"] 
    
    log_message(results_widget, "[MITM-INFO] Avaliação de Segurança da Rede (Geral):\n")
    log_message(results_widget, "  Lembre-se: Redes Abertas ou WEP são ALTAMENTE VULNERÁVEIS a MITM.\n")
    log_message(results_widget, "  Use senhas fortes e WPA2-AES ou WPA3 para maior segurança.\n")
    
    detect_arp_spoofing_signs(gateway_ip, iface_name_scapy, results_widget)
    
    log_message(results_widget, "\n[MITM-INFO] Análise de Evil Twin:\n")
   
    if all_scanned_networks_global:
        log_message(results_widget, "  Lógica de Evil Twin: Compare manualmente o BSSID da sua conexão com a lista de 'Redes Encontradas'.\n"
                                    "  Implementação robusta requer identificação precisa do BSSID da conexão ATIVA.\n")
    else:
        log_message(results_widget, "  Execute o 'Scan de Redes Wi-Fi' primeiro para análise de Evil Twin.\n")
    log_message(results_widget, "\n--- Análise MITM Concluída ---\n")

def execute_mitm_analysis_and_display(results_widget, scan_button_mitm):
   
    try:
        analyze_mitm_vulnerabilities_for_connected_network(results_widget)
    except Exception as e:
        if results_widget and results_widget.winfo_exists(): log_message(results_widget, f"[ERRO GERAL NA ANÁLISE MITM] Ocorreu: {e}\n"); import traceback; log_message(results_widget, traceback.format_exc() + "\n")
    finally:
        if scan_button_mitm and scan_button_mitm.winfo_exists(): scan_button_mitm.config(state=tk.NORMAL)

def start_mitm_analysis_thread(results_widget, scan_button_mitm):
   
    if not SCAPY_AVAILABLE:
        messagebox.showerror("Scapy Indisponível", "Scapy é necessário para a Análise MITM.")
        return
    scan_button_mitm.config(state=tk.DISABLED)
    log_message(results_widget, "\n\n--- Iniciando Análise de Vulnerabilidades MITM (Fase 3) ---\n")
    threading.Thread(target=execute_mitm_analysis_and_display, args=(results_widget, scan_button_mitm), daemon=True).start()


def setup_gui():
    
    window = tk.Tk()
    window.title(f"Analisador Wi-Fi, LAN & MITM {APP_VERSION}")
    window.geometry("900x750")
    style = ttk.Style()
    try:
        if platform.system() == "Windows":
            if 'vista' in style.theme_names(): style.theme_use('vista')
        elif 'clam' in style.theme_names(): style.theme_use('clam')
    except tk.TclError: print("[GUI INFO] Tema ttk preferido não encontrado.")
    control_frame = ttk.Frame(window, padding="10")
    control_frame.pack(fill=tk.X)
    scan_wifi_button = ttk.Button(control_frame, text="1. Procurar Redes Wi-Fi", command=lambda: start_wifi_scan_thread(results_widget, scan_wifi_button))
    scan_wifi_button.pack(side=tk.LEFT, padx=(0, 5), ipady=2)
    if not PYWIFI_AVAILABLE: scan_wifi_button.config(state=tk.DISABLED)
    scan_lan_button = ttk.Button(control_frame, text="2. Analisar Rede Local", command=lambda: start_lan_scan_thread(results_widget, scan_lan_button))
    scan_lan_button.pack(side=tk.LEFT, padx=(0,5), ipady=2)
    if not SCAPY_AVAILABLE or not NETIFACES_AVAILABLE: scan_lan_button.config(state=tk.DISABLED)
    scan_mitm_button = ttk.Button(control_frame, text="3. Análise MITM (Conectado)", command=lambda: start_mitm_analysis_thread(results_widget, scan_mitm_button))
    scan_mitm_button.pack(side=tk.LEFT, ipady=2)
    if not SCAPY_AVAILABLE or not NETIFACES_AVAILABLE: scan_mitm_button.config(state=tk.DISABLED)
    results_widget = scrolledtext.ScrolledText(window, wrap=tk.WORD, font=("Consolas", 9), height=40, state=tk.NORMAL, relief=tk.SOLID, borderwidth=1)
    results_widget.pack(padx=10, pady=(0, 10), expand=True, fill=tk.BOTH)
    log_message(results_widget, f"Bem-vindo ao Analisador de Redes {APP_VERSION}!\n")
    log_message(results_widget, "Fases: 1. Scan Wi-Fi | 2. Scan LAN | 3. Análise MITM\n")
  
    window.mainloop()


if __name__ == "__main__":
    print(f"*****************************************************************")
    print(f"* Analisador Wi-Fi, LAN & MITM (Python) {APP_VERSION}           *")
    print(f"*****************************************************************")
    print(f"* Plataforma: {platform.system()} {platform.release()}         *")
    if 'sys' in globals() and hasattr(sys, 'version_info'): # Check se sys foi importado
        print(f"* Python: {sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}                               *")
    else:
        print("* Python: (sys module não importado para obter versão)        *")
    print(f"*****************************************************************")
    print(f"* AVISO IMPORTANTE DE USO: (Leia com atenção)                   *")
    print(f"* 1. PERMISSÃO É ESSENCIAL: Use APENAS em redes para as quais   *")
    print(f"* tem AUTORIZAÇÃO EXPLÍCITA para analisar/testar.            *")
    print(f"* 2. FINS EDUCATIVOS: Esta ferramenta é para APRENDIZAGEM.      *")
    # ... (Resto dos avisos) ...
    print(f"*****************************************************************\n")
    
    if not PYWIFI_AVAILABLE: print("[AVISO INICIALIZAÇÃO] PyWiFi não carregado.")
    if not NETIFACES_AVAILABLE: print("[AVISO INICIALIZAÇÃO] Netifaces não carregado.")
    if not IPADDRESS_AVAILABLE: print("[AVISO INICIALIZAÇÃO] Módulo 'ipaddress' não carregado.")
    if not SCAPY_AVAILABLE:
        print("[AVISO INICIALIZAÇÃO - SCAPY NÃO ENCONTRADO/IMPORTADO]")
        # ... (Avisos detalhados sobre Scapy) ...
    
    print("Pressione Enter para tentar iniciar a aplicação GUI...")
    input() 

    print("\n[INFO] Tentando iniciar a Interface Gráfica do Utilizador (GUI)...")
    try:
        setup_gui()
    except Exception as e:
        print("\n!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!")
        print("!!! ERRO CRÍTICO AO INICIAR A GUI ou DURANTE A EXECUÇÃO: !!!")
        print(f"Tipo de Erro: {type(e).__name__}, Mensagem: {str(e)}")
        import traceback
        print("\n--- Traceback Completo ---"); traceback.print_exc(); print("--------------------------\n")
        input("\nPressione Enter para fechar esta janela de erro.")
