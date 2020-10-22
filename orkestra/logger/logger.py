from colorama import init, Fore
import datetime

init(autoreset=True)


def time():
    return "[%s][" % datetime.datetime.now().strftime("%d/%m/%Y %H:%M:%S")


def log(msg):
    print(time() + Fore.LIGHTBLACK_EX + "LOG" + Fore.RESET + "] " + msg.capitalize())


def info(msg):
    print(time() + Fore.LIGHTBLUE_EX + "INFO" + Fore.RESET + "] " + msg.capitalize())


def error(msg):
    print(time() + Fore.RED + "ERROR" + Fore.RESET + "] " + msg.capitalize())


def warn(msg):
    print(time() + Fore.YELLOW + "WARNING" + Fore.RESET + "] " + msg.capitalize())


def done(msg):
    print(time() + Fore.GREEN + "SUCCESS" + Fore.RESET + "] " + msg.capitalize())
