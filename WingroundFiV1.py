import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import pywifi
from pywifi import const
import time
import threading
import collections

import netifaces
import ipaddress
try:
    from scapy.all import ARP, Ether, srp, sr1, conf as scapy_conf
    SCAPY_AVAILABLE = True
    scapy_conf.verb = 0
except ImportError:
    SCAPY_AVAILABLE = False
  
AKM_TYPES = { const.AKM_TYPE_NONE: "Nenhum (Aberta ou WEP Estático)", const.AKM_TYPE_WPA: "WPA", const.AKM_TYPE_WPAPSK: "WPA-PSK", const.AKM_TYPE_WPA2: "WPA2", const.AKM_TYPE_WPA2PSK: "WPA2-PSK"}
CIPHER_TYPES = {const.CIPHER_TYPE_NONE: "Nenhum", const.CIPHER_TYPE_WEP: "WEP", const.CIPHER_TYPE_TKIP: "TKIP", const.CIPHER_TYPE_CCMP: "CCMP (AES)"}
AUTH_TYPES = {const.AUTH_ALG_OPEN: "Aberta", const.AUTH_ALG_SHARED: "Chave Compartilhada (WEP)"}

def freq_to_channel(freq_mhz):
    if not isinstance(freq_mhz, (int, float)) or freq_mhz <= 0: return "N/A"
    try:
        freq = int(freq_mhz)
        if 2412 <= freq <= 2484: return 14 if freq == 2484 else (freq - 2407) // 5
        elif 5170 <= freq <= 5825: return (freq - 5000) // 5
        elif 5925 <= freq <= 7125: return (freq - 5950) // 5 
        else: return f"{freq}MHz"
    except ValueError: return "N/A"

def rssi_to_quality(rssi):
    if not isinstance(rssi, (int, float)): return "N/A"
    try:
        rssi_val = int(rssi); quality = max(0, min(100, 2 * (rssi_val + 100)))
        return quality
    except ValueError: return "N/A"


def log_message(results_widget, message):
    if results_widget.winfo_exists():
        results_widget.insert(tk.END, message)
        results_widget.see(tk.END)
        results_widget.update_idletasks()

def get_wifi_scan_results(results_widget):

    log_message(results_widget, "[INFO] Iniciando scan de redes Wi-Fi com pywifi...\n")
    wifi = None; iface = None
    try:
        wifi = pywifi.PyWiFi()
        if not wifi.interfaces():
            log_message(results_widget, "[ERRO] Nenhuma interface Wi-Fi encontrada pelo pywifi.\n")
            return []
        iface = wifi.interfaces()[0]
        log_message(results_widget, f"[INFO] Usando interface: {iface.name()}\n")
        log_message(results_widget, "[INFO] Solicitando scan de redes...\n")
        iface.scan()
        log_message(results_widget, "[INFO] Aguardando resultados do scan (8 segundos)...\n")
        time.sleep(8)
        scan_results_raw = iface.scan_results()
        if not scan_results_raw:
            log_message(results_widget, "[INFO] Nenhuma rede encontrada ou scan falhou.\n")
            return []
        log_message(results_widget, f"[INFO] Scan concluído. {len(scan_results_raw)} redes encontradas.\n\n")
        parsed_results = []
        for profile in scan_results_raw:
            ssid = profile.ssid if profile.ssid else "SSID Oculto"; bssid = profile.bssid if profile.bssid else "N/A"
            signal_rssi = profile.signal; signal_quality = f"{rssi_to_quality(signal_rssi)}%"
            freq_mhz = profile.freq if hasattr(profile, 'freq') else "N/A"; channel = freq_to_channel(freq_mhz)
            akm_strings = [AKM_TYPES.get(a, f"AKM_Desconhecido({a})") for a in profile.akm]
            cipher_strings = [CIPHER_TYPES.get(c, f"Cipher_Desconhecido({c})") for c in profile.cipher]
            simple_security = "Aberta" 
       
            if any(akm in profile.akm for akm in [const.AKM_TYPE_WPAPSK, const.AKM_TYPE_WPA2PSK]):
                simple_security = "WPA2-PSK (AES)" if const.AKM_TYPE_WPA2PSK in profile.akm and const.CIPHER_TYPE_CCMP in profile.cipher else "WPA-PSK (TKIP)"
            elif any(akm in profile.akm for akm in [const.AKM_TYPE_WPA, const.AKM_TYPE_WPA2]): simple_security = "WPA/WPA2 Enterprise"
            elif const.CIPHER_TYPE_WEP in profile.cipher : simple_security = "WEP"
            
            parsed_results.append({"SSID": ssid, "BSSID": bssid, "Sinal (RSSI)": signal_rssi, "Qualidade": signal_quality,
                                   "Frequência": f"{freq_mhz} MHz" if isinstance(freq_mhz, (int,float)) else freq_mhz,
                                   "Canal": channel, "Segurança (Simplificada)": simple_security, "RawProfile": profile}) 
        return parsed_results
    except Exception as e:
        log_message(results_widget, f"[ERRO] Ocorreu um erro com pywifi: {e}\n")
        import traceback; log_message(results_widget, traceback.format_exc() + "\n")
        return []

def get_active_network_interface_details(results_widget):
    
    try:
        gateways = netifaces.gateways()
        if 'default' not in gateways or not gateways['default'] or netifaces.AF_INET not in gateways['default']:
            log_message(results_widget, "[AVISO] Nenhuma gateway IPv4 padrão encontrada.\n")
            return None
        default_gw_info = gateways['default'][netifaces.AF_INET]
        gw_ip, iface_name = default_gw_info[0], default_gw_info[1]
        log_message(results_widget, f"[INFO] Gateway padrão: {gw_ip} via interface '{iface_name}'\n")
        iface_addrs = netifaces.ifaddresses(iface_name)
        if netifaces.AF_INET not in iface_addrs or not iface_addrs[netifaces.AF_INET]:
            log_message(results_widget, f"[AVISO] Interface '{iface_name}' não possui IPv4.\n")
            return None
        ipv4_info = iface_addrs[netifaces.AF_INET][0]
        ip_addr = ipv4_info['addr']; netmask = ipv4_info['netmask']
        network = ipaddress.ip_network(f"{ip_addr}/{netmask}", strict=False)
        network_cidr = str(network)
        log_message(results_widget, f"[INFO] IP Local: {ip_addr}, Máscara: {netmask}, Rede: {network_cidr}\n")
        return {"iface_name": iface_name, "ip_addr": ip_addr, "netmask": netmask, "gateway": gw_ip, "network_cidr": network_cidr}
    except Exception as e:
        log_message(results_widget, f"[ERRO] Falha ao obter detalhes da interface de rede: {e}\n")
        return None

def arp_scan_local_network(network_cidr, iface_name, results_widget):

    if not SCAPY_AVAILABLE:
        log_message(results_widget, "[ERRO] Scapy não está disponível. ARP scan cancelado.\n")
        return []
    log_message(results_widget, f"[INFO] Iniciando ARP scan na rede {network_cidr} via interface {iface_name}...\n")
    log_message(results_widget, "[AVISO] Requer privilégios de admin/root e pode demorar.\n")
    hosts_found = []
    try:
        ans, unans = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=network_cidr), timeout=3, iface=iface_name, verbose=False)
        if ans:
            log_message(results_widget, f"[INFO] {len(ans)} hosts responderam ao ARP scan:\n")
            for sent, received in ans:
                hosts_found.append({'ip': received.psrc, 'mac': received.hwsrc})
                log_message(results_widget, f"  IP: {received.psrc:<15} MAC: {received.hwsrc}\n")
        else: log_message(results_widget, "[INFO] Nenhum host respondeu ao ARP scan.\n")
    except PermissionError: log_message(results_widget, "[ERRO CRÍTICO] Permissão negada para ARP scan. Execute como admin/root.\n")
    except OSError as e: log_message(results_widget, f"[ERRO CRÍTICO] Erro de SO no ARP scan (interface '{iface_name}'? Npcap/libpcap?): {e}\n")
    except Exception as e: log_message(results_widget, f"[ERRO] Falha no ARP scan: {e}\n"); import traceback; log_message(results_widget, traceback.format_exc() + "\n")
    return hosts_found

def guess_os_by_ttl(target_ip, iface_name, results_widget):
   
    if not SCAPY_AVAILABLE: return "N/A (Scapy indisponível)"
    log_message(results_widget, f"  [OS-GUESS] Ping em {target_ip} para TTL...\n")
    try:
        ans = sr1(IP(dst=target_ip)/ICMP(), timeout=1, verbose=False, iface=iface_name)
        if ans:
            ttl = ans.ttl
            if 1<=ttl<=64: return f"Linux/Unix (TTL:{ttl})"
            elif 65<=ttl<=128: return f"Windows (TTL:{ttl})"
            else: return f"Outro/Desconhecido (TTL:{ttl})"
        else: log_message(results_widget, f"  [OS-GUESS] Sem resposta ICMP de {target_ip}.\n"); return "N/A (Sem resposta ICMP)"
    except Exception as e: log_message(results_widget, f"  [OS-GUESS] Erro ao pingar {target_ip}: {e}\n"); return "N/A (Erro no Ping)"



def get_current_wifi_connection_details_pywifi(results_widget):
    """Obtém detalhes da conexão Wi-Fi ativa usando PyWiFi."""
    wifi = None
    iface = None
    try:
        wifi = pywifi.PyWiFi()
        if not wifi.interfaces():
            log_message(results_widget, "[MITM-INFO] Nenhuma interface Wi-Fi (pywifi).\n")
            return None
        
        iface = wifi.interfaces()[0] 
        
        if iface.status() == const.IFACE_CONNECTED:
           
            current_bssid = None
          

            profiles = iface.scan_results() 
            status = iface.status()
            
         
            log_message(results_widget, f"[MITM-INFO] Conectado via interface Wi-Fi: {iface.name()}. Detalhes de segurança da rede conectada devem ser verificados.\n")
            
        
            return {"iface_name_wifi": iface.name(), "ssid": "N/A (pywifi não fornece diretamente)", "bssid": "N/A", "security_profile": None}
        else:
            log_message(results_widget, "[MITM-INFO] Interface Wi-Fi não está conectada.\n")
            return None
            
    except Exception as e:
        log_message(results_widget, f"[ERRO] Falha ao obter detalhes da conexão Wi-Fi (pywifi): {e}\n")
        return None


def detect_arp_spoofing_signs(gateway_ip, iface_name, results_widget):
    """Tenta detetar sinais de ARP spoofing para o gateway."""
    if not SCAPY_AVAILABLE:
        log_message(results_widget, "[MITM-ARP] Scapy indisponível, impossível verificar ARP spoofing.\n")
        return False
    if not gateway_ip or not iface_name:
        log_message(results_widget, "[MITM-ARP] IP do Gateway ou nome da interface não fornecido.\n")
        return False

    log_message(results_widget, f"[MITM-ARP] Verificando ARP spoofing para o gateway {gateway_ip} na interface {iface_name}...\n")
    log_message(results_widget, "[AVISO] Requer privilégios de admin/root.\n")
    
    detected_macs_for_gateway = set()
    possible_spoofing = False

    try:
       
        for _ in range(3):
           
            ans = sr1(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=gateway_ip, psrc="0.0.0.0"),
                      timeout=1, iface=iface_name, verbose=False)
            if ans and ARP in ans and ans[ARP].op == 2: 
                sender_mac = ans[ARP].hwsrc
                sender_ip = ans[ARP].psrc
                if sender_ip == gateway_ip:
                    log_message(results_widget, f"  [MITM-ARP-DEBUG] Resposta ARP para {gateway_ip} veio de MAC: {sender_mac}\n")
                    detected_macs_for_gateway.add(sender_mac)
            time.sleep(0.3) 
        if len(detected_macs_for_gateway) > 1:
            log_message(results_widget, f"[ALERTA MITM] MÚLTIPLOS MACs ({len(detected_macs_for_gateway)}) responderam para o IP do gateway ({gateway_ip}): {', '.join(detected_macs_for_gateway)}\n")
            log_message(results_widget, "  Isto é um FORTE INDICADOR de ARP spoofing!\n")
            possible_spoofing = True
        elif len(detected_macs_for_gateway) == 1:
            log_message(results_widget, f"[MITM-ARP] Apenas um MAC ({list(detected_macs_for_gateway)[0]}) respondeu para o gateway. Parece normal.\n")
        else:
            log_message(results_widget, f"[MITM-ARP] Nenhuma resposta ARP clara recebida do gateway {gateway_ip} durante o teste.\n"
                                        "  Verifique a conectividade ou se o gateway bloqueia estes pedidos.\n")
            
    except PermissionError:
         log_message(results_widget, "[ERRO CRÍTICO] Permissão negada para teste de ARP spoofing. Execute como admin/root.\n")
    except OSError as e:
        log_message(results_widget, f"[ERRO CRÍTICO] Erro de SO no teste de ARP spoofing (interface '{iface_name}'? Npcap/libpcap?): {e}\n")
    except Exception as e:
        log_message(results_widget, f"[ERRO] Falha durante o teste de ARP spoofing: {e}\n")
        import traceback
        log_message(results_widget, traceback.format_exc() + "\n")
        
    return possible_spoofing


def analyze_mitm_vulnerabilities_for_connected_network(results_widget):
    """Orquestra a análise de vulnerabilidades MITM para a rede conectada."""
    log_message(results_widget, "\n\n--- Iniciando Análise de Vulnerabilidades MITM (Rede Conectada) ---\n")

   
    net_details = get_active_network_interface_details(results_widget)
    if not net_details or not net_details.get("gateway") or not net_details.get("iface_name"):
        log_message(results_widget, "[MITM-ERRO] Não foi possível obter detalhes da rede ativa. Análise MITM cancelada.\n")
        return

    gateway_ip = net_details["gateway"]
    iface_name = net_details["iface_name"]

  
    log_message(results_widget, "[MITM-INFO] Avaliação de Segurança da Rede (Genérica):\n")
    log_message(results_widget, "  - Redes Abertas (sem senha) ou WEP são ALTAMENTE VULNERÁVEIS a MITM.\n")
    log_message(results_widget, "  - WPA/WPA2/WPA3 com senhas fracas também são um risco.\n")
    log_message(results_widget, "  - Use sempre senhas fortes e WPA2-AES ou WPA3.\n")
   


    detect_arp_spoofing_signs(gateway_ip, iface_name, results_widget)



    log_message(results_widget, "\n--- Análise MITM Concluída ---\n")




all_scanned_networks_global = [] 
def execute_wifi_scan_and_display(results_widget, scan_button):
    global all_scanned_networks_global
    all_scanned_networks_global = []
    try:
        networks = get_wifi_scan_results(results_widget)
        if networks:
            all_scanned_networks_global = networks 
            log_message(results_widget, "\n--- Redes Encontradas ---\n")
            for net in networks:
                log_message(results_widget, f"SSID: {net['SSID']}\n")
                log_message(results_widget, f"  BSSID: {net['BSSID']}\n")
                log_message(results_widget, f"  Sinal: {net['Sinal (RSSI)']} dBm ({net['Qualidade']}%)\n")
                log_message(results_widget, f"  Frequência: {net['Frequência']} (Canal: {net['Canal']})\n")
                log_message(results_widget, f"  Segurança: {net['Segurança (Simplificada)']}\n")
                log_message(results_widget, "-"*30 + "\n")
        else:
            log_message(results_widget, "[INFO] Nenhuma rede Wi-Fi processada ou scan falhou.\n")

    except Exception as e:
        if results_widget.winfo_exists(): log_message(results_widget, f"[ERRO GERAL NO SCAN WIFI] Ocorreu: {e}\n"); import traceback; log_message(results_widget, traceback.format_exc() + "\n")
    finally:
        if scan_button.winfo_exists(): scan_button.config(state=tk.NORMAL)

def start_mitm_analysis_thread(results_widget, scan_button_mitm):
    if not SCAPY_AVAILABLE:
        messagebox.showerror("Scapy Indisponível", "A biblioteca Scapy é necessária para a análise MITM, mas não pôde ser importada.")
        return

    scan_button_mitm.config(state=tk.DISABLED)
    log_message(results_widget, "\n\n--- Iniciando Análise MITM ---\n")

    scan_thread = threading.Thread(
        target=execute_mitm_analysis_and_display,
        args=(results_widget, scan_button_mitm),
        daemon=True
    )
    scan_thread.start()

def execute_mitm_analysis_and_display(results_widget, scan_button_mitm):
    try:
        analyze_mitm_vulnerabilities_for_connected_network(results_widget)
    except Exception as e:
        if results_widget.winfo_exists():
            log_message(results_widget, f"[ERRO GERAL NA ANÁLISE MITM] Ocorreu: {e}\n")
            import traceback
            log_message(results_widget, traceback.format_exc() + "\n")
    finally:
        if scan_button_mitm.winfo_exists():
            scan_button_mitm.config(state=tk.NORMAL)


def setup_gui():
    window = tk.Tk()
    window.title(f"Analisador Wi-Fi & LAN & MITM (v0.3)")
    window.geometry("900x750")

    style = ttk.Style()
    try:
        available_themes = style.theme_names()
        if 'clam' in available_themes: style.theme_use('clam')
        elif 'vista' in available_themes: style.theme_use('vista')
    except tk.TclError: print("Tema ttk preferido não encontrado.")

    control_frame = ttk.Frame(window, padding="10")
    control_frame.pack(fill=tk.X)

    scan_wifi_button = ttk.Button(control_frame, text="1. Procurar Redes Wi-Fi (PyWiFi)",
                             command=lambda: start_wifi_scan_thread(results_widget, scan_wifi_button))
    scan_wifi_button.pack(side=tk.LEFT, padx=(0, 5), ipady=2)

    scan_lan_button = ttk.Button(control_frame, text="2. Analisar Rede Local (Scapy)",
                                 command=lambda: start_lan_scan_thread(results_widget, scan_lan_button))
    scan_lan_button.pack(side=tk.LEFT, padx=(0,5), ipady=2)

  
    scan_mitm_button = ttk.Button(control_frame, text="3. Análise MITM (Rede Conectada)",
                                 command=lambda: start_mitm_analysis_thread(results_widget, scan_mitm_button))
    scan_mitm_button.pack(side=tk.LEFT, ipady=2)


    results_widget = scrolledtext.ScrolledText(window, wrap=tk.WORD, height=40, state=tk.NORMAL, relief=tk.SOLID, borderwidth=1)
    results_widget.pack(padx=10, pady=(0, 10), expand=True, fill=tk.BOTH)

    log_message(results_widget, "Bem-vindo ao Analisador de Redes Wi-Fi, LAN & MITM!\n")
    log_message(results_widget, "Fases: 1. Scan Wi-Fi (PyWiFi) | 2. Scan LAN (Scapy) | 3. Análise MITM (Scapy)\n")
    log_message(results_widget, "Scapy requer admin/root e Npcap (Win) ou libpcap (Linux).\n\n")
   
    if not SCAPY_AVAILABLE:
        log_message(results_widget, "[ALERTA IMPORTANTE] Scapy não está carregado. Funções de Scan da LAN e Análise MITM estão desabilitadas/limitadas.\n\n")

    window.mainloop()

-
if __name__ == "__main__":
   
    print("*****************************************************************")
    print("* Analisador Wi-Fi, LAN & MITM (Python)                         *")
    print("* Fases: Scan Wi-Fi, Scan LAN, Análise MITM                     *")
    print("*****************************************************************")
    print("* AVISO IMPORTANTE DE USO: (Leia com atenção)                   *")
    print("* 1. PERMISSÃO É ESSENCIAL: Use APENAS em redes para as quais   *")
    print("* tem AUTORIZAÇÃO EXPLÍCITA para analisar/testar.            *")
    print("* 2. FINS EDUCATIVOS: Esta ferramenta é para APRENDIZAGEM.      *")
    print("* Não use para atividades maliciosas ou invasivas.           *")
    print("* 3. PRIVILÉGIOS DE ADMIN/ROOT: Muitas funcionalidades (Scapy)  *")
    print("* exigem execução com privilégios elevados.                  *")
    print("* 4. SEM GARANTIAS: O uso é por sua conta e risco.              *")
    print("* *")
    print("* Dependências: pywifi, comtypes (Win), netifaces, scapy        *")
    print("* Scapy requer Npcap (Windows - com modo WinPcap) ou            *")
    print("* libpcap-dev e tcpdump (Linux).                                *")
    print("*****************************************************************\n")
    
    if not SCAPY_AVAILABLE:
        print("\n[AVISO IMPORTANTE DE INICIALIZAÇÃO - SCAPY NÃO ENCONTRADO]")
      
    
    print("Pressione Enter para iniciar a aplicação GUI...")
    input()
    setup_gui()
