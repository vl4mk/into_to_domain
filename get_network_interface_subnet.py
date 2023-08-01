import socket
import ipaddress
import psutil

def get_active_eth_interface():
    try:
        interfaces = psutil.net_if_stats()
        for interface, status in interfaces.items():
            if status.isup and interface != "lo" and not interface.startswith("lo"):
                return interface
    except Exception as e:
        print("Произошла ошибка при получении активного сетевого интерфейса:", str(e))
    return None

print("Active eth adapter: " + get_active_eth_interface())

active_eth = get_active_eth_interface()

# Получение активного сетевого интерфейса из find_eth_adapter
active_eth = get_active_eth_interface()
def get_network_interface_subnet(interface_name):
    interfaces = psutil.net_if_addrs()
    if interface_name in interfaces:
        addresses = interfaces[interface_name]
        for address in addresses:
            if address.family == socket.AF_INET:
                ip_address = address.address
                netmask = address.netmask
                network = ipaddress.IPv4Network(f"{ip_address}/{netmask}", strict=False)
                subnet = f"{network.network_address}/{network.prefixlen}"
                return subnet
    return None

# Получение подсети и маски подсети для интерфейса Ethernet0


subnet = get_network_interface_subnet(active_eth)
if subnet is not None:
    print("Subnet for active eth adapter:", subnet)
else:
    print("Не удалось получить подсеть и маску подсети для сетевого интерфейса")

get_active_eth_interface()