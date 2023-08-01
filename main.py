import acii_picture
import ldap3
import ipaddress
import re
import asyncio
from tqdm import tqdm
import subprocess
import get_network_interface_subnet
from getpass import getpass
from ldap3 import Server, Connection, SUBTREE
from ldap3.core.exceptions import LDAPBindError


# Define global variables
ip_addresses = []
domain_controller_names = []


def connect_to_domain_controller(ip):
    global ip_addresses, domain_controller_names
    try:
        # Создание соединения с сервером LDAP с установленным тайм-аутом в 0.001 секунд
        server = ldap3.Server(str(ip), get_info=ldap3.ALL, connect_timeout=0.002)

        # Анонимное подключение
        conn = ldap3.Connection(server, user=None, password=None, auto_bind=True)

        # Поиск информации о контроллере домена
        conn.search(search_base='', search_scope=ldap3.BASE, search_filter='(objectClass=*)',
                    attributes=['serverName', 'dnsHostName'])

        # Извлечение информации о контроллере домена
        entry = conn.entries[0]
        #server_name = entry['serverName'].value
        dns_host_name = entry['dnsHostName'].value

        # Разрыв соединения
        conn.unbind()

        # Добавление IP-адресов и доменных имен в соответствующие переменные
        ip_addresses.append(str(ip))
        domain_controller_names.append(dns_host_name)

    except ldap3.core.exceptions.LDAPSocketOpenError:
        pass


async def scan_ip(ip, progress_bar):
    loop = asyncio.get_running_loop()
    await loop.run_in_executor(None, connect_to_domain_controller, ip)
    progress_bar.update(1)


async def connect_to_domain_controllers():
    try:
        # Диапазон IP-адресов подсети из get_network_inetface_subnet
        subnet = get_network_interface_subnet.subnet

        # Получение объекта подсети из строки
        subnet_obj = ipaddress.ip_network(subnet)

        # Создание списка задач для асинхронного выполнения
        tasks = []

        # Создание прогресс бара с количеством IP-адресов
        progress_bar = tqdm(total=subnet_obj.num_addresses, desc="Scanning IPs progress")

        # Цикл для создания задач на сканирование каждого IP-адреса
        for ip in subnet_obj.hosts():
            task = asyncio.create_task(scan_ip(ip, progress_bar))
            tasks.append(task)

        # Выполнение задач и ожидание результатов
        await asyncio.gather(*tasks)

        # Завершение прогресс бара
        progress_bar.close()

    except Exception as e:
        print("Произошла ошибка при подключении к контроллерам домена:", e)


# Вызов метода с обработкой исключений
def get_ad_name():
        try:
            asyncio.run(connect_to_domain_controllers())
        except Exception as e:
            print("Error:", e)

#  Start scan for get AD information
get_ad_name()

print("Available IP addresses and domain controller names: ")
for index, (ip_address, dc_name) in enumerate(zip(ip_addresses, domain_controller_names), start=1):
    print(f"{index}. {dc_name}")


if len(ip_addresses) == 1:
    selected_ip = ip_addresses[0]
    selected_ad_name = domain_controller_names[0]
    print("Selected DC:", selected_ip, selected_ad_name)
    match = re.search(r'\.(.+)$', selected_ad_name)
    if match:
        full_name_domain = match.group(1)
        print("Domain name:", full_name_domain)
    else:
        print("Failed to extract the domain name")
    print()
else:
    while True:
        selection = input("Select DC for work: ")

        if selection.isdigit():
            selection = int(selection)
            if 1 <= selection <= len(ip_addresses):
                selected_ip = ip_addresses[selection - 1]
                selected_ad_name = domain_controller_names[selection - 1]
                print("Selected DC:", selected_ip,  selected_ad_name)
                match = re.search(r'\.(.+)$', selected_ad_name)
                if match:
                    full_name_domain = match.group(1)
                    print("Domain name:", full_name_domain)
                else:
                    print("Failed to extract the domain name")
                print()
                break
            else:
                print("Incorrect choice. Please select the correct number from the list")
        else:
            selected_ip = selection
            selected_ad_name = selection
            print("Selected DC:", selection)
            break


def set_dns_servers():
    # Определение активного сетевого адаптера
    adapter_name = get_network_interface_subnet.get_active_eth_interface()
    # Формирование команды netsh для изменения DNS-серверов
    command1 = f"netsh interface ip set dns name=\"{adapter_name}\" static {selected_ip}"
    command2 = f"netsh interface ip add dns name=\"{adapter_name}\" 8.8.8.8 index=2"
    try:
        # Выполнение команд через командную строку
        subprocess.run(command1, shell=True, check=True)
        subprocess.run(command2, shell=True, check=True)
        print("DNS servers changed successfully")
    except subprocess.CalledProcessError as e:
        print("Error when changing DNS servers:", e)


def get_pc_f_domain():
        subdomain, domain = full_name_domain.split(".", 1)

        # Создание объекта Server с указанием адреса и порта LDAP-сервера
        server = Server(selected_ip, port=389, use_ssl=False, get_info='ALL')

        # Максимальное количество попыток ввода имени пользователя и пароля
        max_attempts = 3

        for attempt in range(max_attempts):
            login = input("Input admin username: ")
            admin_username = f"{subdomain}\\{login}"
            admin_password = getpass("Input admin's password: ")

            # Создание объекта Connection и установка соединения с LDAP-сервером2
            try:
                connection = Connection(server, user=admin_username, password=admin_password, auto_bind=True)
                # Проверка успешной аутентификации
                if connection.bind():
                    print("Authentication successful")
                    break
                else:
                    print("Authentication error")
                    if attempt < max_attempts - 1:
                        print("Try again.")
            except LDAPBindError:
                print("Incorrect login or password")
                if attempt < max_attempts - 1:
                    print("Try again.")
        else:
            print("Retries exceeded. Return to main menu.")
            return

        # Запрос списка имен компьютеров в домене
        search_base = f"dc={subdomain},dc={domain}"
        print(search_base)
        search_filter = '(objectClass=computer)'
        connection.search(search_base, search_filter, search_scope=SUBTREE, attributes=['sAMAccountName'])

        # Проверка успешного выполнения запроса
        if connection.result['result'] == 0:
            print("Request completed successfully")
            entries = connection.entries
            for entry in entries:
                computer_name = entry['sAMAccountName'].value

                print(f"{computer_name}")
        else:
            print("Error while executing request")

        # Закрытие соединения
        connection.unbind()


def get_username_f_domain():
    subdomain, domain = full_name_domain.split(".", 1)

    # Создание объекта Server с указанием адреса и порта LDAP-сервера
    server = Server(selected_ip, port=389, use_ssl=False, get_info='ALL')

    # Максимальное количество попыток ввода имени пользователя и пароля
    max_attempts = 3

    for attempt in range(max_attempts):
        login = input("Input admin username: ")
        admin_username = f"{subdomain}\\{login}"
        admin_password = getpass("Input admin's password: ")

        # Создание объекта Connection и установка соединения с LDAP-сервером2
        try:
            connection = Connection(server, user=admin_username, password=admin_password, auto_bind=True)
            # Проверка успешной аутентификации
            if connection.bind():
                print("Authentication successful")
                break
            else:
                print("Authentication error")
                if attempt < max_attempts - 1:
                    print("Try again.")
        except LDAPBindError:
            print("Incorrect login or password")
            if attempt < max_attempts - 1:
                print("Try again.")
    else:
        print("Retries exceeded. Return to main menu.")
        return

    # Запрос списка имен пользователей в домене
    search_base = f"dc={subdomain},dc={domain}"
    search_filter = '(objectCategory=person)'
    connection.search(search_base, search_filter, search_scope=SUBTREE,
                      attributes=['cn', 'userPrincipalName', 'userAccountControl'])

    # Проверка успешного выполнения запроса
    if connection.result['result'] == 0:
        print("Request completed successfully")
        entries = connection.entries
        for entry in entries:
            user_name = entry['cn'].value
            user_logon_name = entry['userPrincipalName'].value
            user_account_control = entry['userAccountControl'].value

            # Проверка состояния аккаунта
            if int(user_account_control) & 2:  # Проверка флага "ACCOUNTDISABLE"
                account_status = "Disable"
            else:
                account_status = "Enable"

            print(f"{user_name} * {user_logon_name} * {account_status}")
    else:
        print("Error while executing request")

    # Закрытие соединения
    connection.unbind()


def add_computer_to_domain():
    subdomain, domain = full_name_domain.split(".", 1)
    # Ввод нового имени компьютера
    new_computer_name = input("Enter a new computer name: ")

    # Проверка логина и пароля до трех попыток
    for _ in range(3):
        username = input("Enter username: ")
        password = getpass("Enter password: ")

        # Формирование команды PowerShell
        powershell_command = f"Add-Computer -DomainName '{subdomain}' -NewName '{new_computer_name}' -Credential (New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList '{username}', (ConvertTo-SecureString -String '{password}' -AsPlainText -Force))"

        try:
            # Выполнение команды PowerShell
            result = subprocess.run(["powershell", "-Command", powershell_command], capture_output=True)
            error = result.stderr.decode().strip()

            if result.returncode == 0:
                print("The computer was successfully added to the domain.", selected_ad_name)
                break
            else:
                print("Error:")
                print(error)  # Выводим только вторую строку с сообщением об ошибке
        except subprocess.CalledProcessError as e:
            print("Error PowerShell:")
            print(e.stderr.decode())
    else:
        print("Превышено количество попыток ввода правильного логина и пароля.")
        return


def remove_computer_from_domain():

    # Проверка логина и пароля до трех попыток
    for _ in range(3):
        username = input("Enter admin's username: ")

        # Формирование команды PowerShell
        powershell_command = f"Remove-Computer -UnjoinDomainCredential '{full_name_domain}\\{username}' -PassThru -Verbose -Force"

        try:
            # Выполнение команды PowerShell
            result = subprocess.run(["powershell", "-Command", powershell_command], capture_output=True)
            #output = result.stdout.decode().strip()
            error = result.stderr.decode().strip()

            if result.returncode == 0:
                print("The computer was successfully removed from the domain.")
                break
            else:
                print("Error when removing computer from domain: ")
                print(error)
        except subprocess.CalledProcessError as e:
            print("Error while executing command PowerShell:")
            print(e.stderr.decode())
    else:
        print("Exceeded the number of attempts to enter the correct login and password.")
        return

def add_gitsteladmin():
    command1 = f"net user gitsteladmin d5568949!"
    try:
        subprocess.run(command1, shell=True, check=True)
        print("Succes")
    except subprocess.CalledProcessError as e:
        print("Error:", e)

def restart_pc():
    command1 = f"shutdown -r -t 0"
    try:
        # Выполнение команд через командную строку
        subprocess.run(command1,  shell=True, check=True)
        print("Succes")
    except subprocess.CalledProcessError as e:
        print("Error:", e)


def greet():
    print("Select function:")
    print("1. Input AD's DNS")
    print("2. Get computers names from AD")
    print("3. Get user's names from AD")
    print("4. Into to the domain")
    print("5. Get out to the domain")
    print("6. Add gisteladmin")
    print("7. Restart PC")
    print("0. Exit program")


# Основной цикл программы
while True:
    greet()  # Вывод приветствия и доступных действий
    choice = input("Please make choice from list: ")

    if choice == "1":
        set_dns_servers()
    elif choice == "2":
        get_pc_f_domain()
    elif choice == "3":
        get_username_f_domain()
    elif choice == "4":
        add_computer_to_domain()
    elif choice == "5":
        remove_computer_from_domain()
    elif choice == "6":
        add_gitsteladmin()
    elif choice == "7":
        restart_pc()
    elif choice == "0":
        print("Program completed")
        break
    else:
        print("Incorrect choice, please make choice from list.")
