
from cx_Freeze import setup, Executable

build_exe_options = {
    "packages": ["getpass", "psutil", "socket", "ipaddress", "find_eth_adapter", "subprocess", "acii_picture", "ldap3", "re", "asyncio", "tqdm", "get_network_interface_subnet", "logging"],

}


setup(
    name="eth_adpt ",
    version="1.0",
    description="Описание вашего приложения",
    executables=[Executable("main.py")]
)