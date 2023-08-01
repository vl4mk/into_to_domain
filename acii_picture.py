import art
import subprocess
import re

ascii_art = art.text2art("GitsTel")
acii_art1 = """
             .,-:;//;:=,
         . :H@@@MM@M#H/.,+%;,
      ,/X+ +M@@M@MM%=,-%HMMM@X/,
     -+@MM; $M@@MH+-,;XMMMM@MMMM@+-
    ;@M@@M- XM@X;. -+XXXXXHHH@M@M#@/.
  ,%MM@@MH ,@%=            .---=-=:=,.
  -@#@@@MX .,              -%HX$$%%%+;
 =-./@M@M$                  .;@MMMM@MM:
 X@/ -$MM/                    .+MM@@@M$
,@M@H: :@:                    . -X#@@@@-
,@@@MMX, .                    /H- ;@M@M=
.H@@@@M@+,                    %MM+..%#$.
 /MMMM@MMH/.                  XM@MH; -;
  /%+%$XHH@$=              , .H@@@@MX,
   .=--------.           -%H.,@@@@@MX,
   .%MM@@@HHHXX$$$%+- .:$MMX -M@@MM%.
     =XMMM@MM@MM#H;,-+HMM@M+ /MMMX=
       =%@M@M#@$-.=$@MM@@@M; %M%=
         ,:+$+-,/H#MMMMMMM@- -,
               =++%%%%+/:-.
"""


def get_info_abaut_pc():
    command1 = f"net user"
    command2 = f"ipconfig"
    try:
        # Выполнение команд через командную строку
        subprocess.run(command1,  shell=True, check=True)
        subprocess.run(command2, shell=True, check=True)
    except subprocess.CalledProcessError as e:
        print("Error:", e)


def is_computer_in_domain():
    powershell_command = "gwmi Win32_ComputerSystem"
    result = subprocess.run(["powershell", "-Command", powershell_command], capture_output=True, text=True)

    output = result.stdout.strip()

    # Поиск строки, начинающейся с "Domain:"
    match = re.search(r"Domain\s+:\s+(\S+)", output)

    if match:
        domain = match.group(1)
        print("Domain:", domain)
    else:
        print("Domain not found in the output.")




print(ascii_art)

get_info_abaut_pc()
is_computer_in_domain()