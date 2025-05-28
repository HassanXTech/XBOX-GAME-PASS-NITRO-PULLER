import logging
import os
import time
from functools import partial
import datetime
from colorama import Fore, Style, init
import os

class InputFormatter:
    def __init__(self):
        self.prompt_color = "\033[38;5;120m>>\033[0m "

    def format_input(self, prompt):
        return f"{self.prompt_color}{prompt}"

class CustomLogger:
    def __init__(self) -> None:
        init(autoreset=True)
        self.colors = {
            "green": Fore.GREEN,
            "red": Fore.RED,
            "yellow": Fore.YELLOW,
            "blue": Fore.BLUE,
            "magenta": Fore.MAGENTA,
            "cyan": Fore.CYAN,
            "white": Fore.WHITE,
            "black": Fore.BLACK,
            "reset": Style.RESET_ALL,
            "lightblack": Fore.LIGHTBLACK_EX,
            "lightred": Fore.LIGHTRED_EX,
            "lightgreen": Fore.LIGHTGREEN_EX,
            "lightyellow": Fore.LIGHTYELLOW_EX,
            "lightblue": Fore.LIGHTBLUE_EX,
            "lightmagenta": Fore.LIGHTMAGENTA_EX,
            "lightcyan": Fore.LIGHTCYAN_EX,
            "lightwhite": Fore.LIGHTWHITE_EX,
            "darkblue": Fore.BLUE 
        }

    def log(self, level, color, message, obj=""):
        print(f"{self.timestamp()} {color}{level} {self.colors['reset']}│ {self.colors['white']}{message}"
              f" {self.colors['lightgreen']}[{obj}]{self.colors['reset'] if obj else ''}")
        
    def clear(self):
        os.system("cls" if os.name == "nt" else "clear")

    def timestamp(self):
        return f"{self.colors['lightblack']}[{datetime.datetime.now().strftime('%H:%M:%S')}] {self.colors['reset']}"

    def purchased(self, message, obj=""):
        self.log(f"{self.colors['green']}✔ PURCHASED", self.colors['green'], message, obj )

    def promo(self, message, obj=""):
        self.log(f"{self.colors['blue']}✦ PROMO", self.colors['blue'], message, obj)

    def success(self, message, obj=""):
        self.log(f"{self.colors['cyan']}✔ SUCCESS", self.colors['cyan'], message, obj)

    def error(self, message, obj=""):
        self.log(f"{self.colors['red']}✖ ERROR", self.colors['red'], message, obj)

    def info(self, message, obj=""):
        self.log(f"{self.colors['green']}ℹ INFO", self.colors['green'], message, obj)

    def linked(self, message, obj=""):
        self.log(f"{self.colors['lightyellow']}ℹ LINK", self.colors['lightyellow'], message, obj)

    
    def input(self, prompt):
        formatted_prompt = self.input_formatter.format_input(prompt)
        return input(formatted_prompt)

