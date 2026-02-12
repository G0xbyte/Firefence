import logging
import re

from prompt_toolkit import print_formatted_text, HTML
from prompt_toolkit.styles import Style

style = Style.from_dict({
    'bottom-toolbar': '#232627 bg:#FDBC4B',
    'bottom-bar.divider': 'bg:#181818',
    'prompt': '#FDBC4B bold',

    'bold': 'bold',
    'error': '#ff4561',
    'warning': '#ffd438',
    'info': '#52d7ff',
    'ok': '#55ff7f',
})

def log_setup():
    logging.basicConfig(
        filename='fireFence.log',
        format='%(asctime)s - %(levelname)s - %(message)s',
        level=logging.INFO,
        datefmt='%Y-%m-%d %H:%M:%S'
    )

def log(message, log=None):
    print_formatted_text(HTML(message), style=style)
    if log != None:
        clean_text = re.sub(r'<[^>]+>', '', message)
        logging.log(log, clean_text)