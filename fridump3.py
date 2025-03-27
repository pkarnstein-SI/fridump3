import textwrap
import frida
import os
import sys
import frida.core
import dumper
import utils
import argparse
import logging
from rich_argparse import ArgumentDefaultsRichHelpFormatter
from rich.progress import track
from rich.logging import RichHandler
from rich.console import Console
from rich.text import Text
import numpy as np
import matplotlib, re

console = Console()
cmap = matplotlib.colormaps["rainbow_r"]
logo = r"""
  ______    _     _                      __   _____ 
 |  ____|  (_)   | |                    /_ | | ____|
 | |__ _ __ _  __| |_   _ _ __ ___  _ __ | | | |__  
 |  __| '__| |/ _` | | | | '_ ` _ \| '_ \| | |___ \ 
 | |  | |  | | (_| | |_| | | | | | | |_) | |_ ___) |
 |_|  |_|  |_|\__,_|\__,_|_| |_| |_| .__/|_(_)____/ 
                                   | |              
                                   |_|              
        """

length = max([len(a) for a in logo.split("\n")])
# print(length)
gradient = np.linspace(0, 1, length)

newbanner = Text("")
for line in [a for a in logo.split("\n") if a!=""]:
     newline = Text("")
     for (i,chr) in enumerate([a for a in re.split(r"(.)", line) if a!='']):
          colorhex = matplotlib.colors.rgb2hex(cmap(gradient[i])) 
          newline.append(f"{chr}", style=f"{colorhex}")
     newbanner.append(newline)
     newbanner.append(Text("\n"))

console = Console(color_system="truecolor")

# Main Menu
def MENU():
    parser = argparse.ArgumentParser(
        prog='fridump',
        formatter_class=ArgumentDefaultsRichHelpFormatter,
        description=textwrap.dedent(""))

    parser.add_argument('process',
                        help='the process that you will be injecting to')
    parser.add_argument('-o', '--out', type=str, metavar="dir",
                        help='provide full output directory path. (def: \'dump\')')
    parser.add_argument('-U', '--usb', action='store_true',
                        help='device connected over usb')
    parser.add_argument('-v', '--verbose', action='store_true',
                        help='verbose')
    parser.add_argument('-r', '--read-only', action='store_true',
                        help="dump read-only parts of memory. More data, more errors")
    parser.add_argument('-s', '--strings', action='store_true',
                        help='run strings on all dump files. Saved in output dir.')
    parser.add_argument('--max-size', type=int, metavar="bytes",
                        help='maximum size of dump file in bytes (def: 20971520)')
    args = parser.parse_args()
    return args


console.print(newbanner)

arguments = MENU()

# Define Configurations
APP_NAME = arguments.process
DIRECTORY = ""
USB = arguments.usb
DEBUG_LEVEL = logging.INFO
STRINGS = arguments.strings
MAX_SIZE = 20971520
PERMS = 'rw-'

if arguments.read_only:
    PERMS = 'r--'

if arguments.verbose:
    DEBUG_LEVEL = logging.DEBUG
logging.basicConfig(format='%(message)s', level=DEBUG_LEVEL, handlers=[RichHandler(rich_tracebacks=True)])


# Start a new Session
session = None
try:
    if USB:
        session = frida.get_usb_device().attach(APP_NAME)
    else:
        session = frida.attach(APP_NAME)
except Exception as e:
    logging.error("Can't connect to App. Have you connected the device?")
    logging.debug(str(e))
    sys.exit()


# Selecting Output directory
if arguments.out is not None:
    DIRECTORY = arguments.out
    if os.path.isdir(DIRECTORY):
        logging.info("Output directory is set to: " + DIRECTORY)
    else:
        logging.error("The selected output directory does not exist!")
        sys.exit(1)

else:
    logging.info("Current Directory: " + str(os.getcwd()))
    DIRECTORY = os.path.join(os.getcwd(), "dump")
    logging.info("Output directory is set to: " + DIRECTORY)
    if not os.path.exists(DIRECTORY):
        logging.info("Creating directory...")
        os.makedirs(DIRECTORY)

mem_access_viol = "cum"

logging.info("Starting Memory dump...")

script = session.create_script(
    """'use strict';

    rpc.exports = {
      enumerateRanges: function (prot) {
        return Process.enumerateRangesSync(prot);
      },
      readMemory: function (address, size) {
        return Memory.readByteArray(ptr(address), size);
      }
    };

    """)

def on_message(message, data):
    logging.info(message)

script.on('message', on_message)
script.load()

agent = script.exports_sync
ranges = agent.enumerate_ranges(PERMS)

if arguments.max_size is not None:
    MAX_SIZE = arguments.max_size

# i = 0
# l = len(ranges)

# Performing the memory dump

for range in track(ranges, description="[green]"+"Dumping memory...".ljust(32)):
    base = range["base"]
    size = range["size"]

    logging.debug("Base Address: " + str(base))
    logging.debug("")
    logging.debug("Size: " + str(size))


    if size > MAX_SIZE:
        logging.debug("Too big, splitting the dump into chunks")
        mem_access_viol = dumper.splitter(
            agent, base, size, MAX_SIZE, mem_access_viol, DIRECTORY)
        continue
    mem_access_viol = dumper.dump_to_file(
        agent, base, size, mem_access_viol, DIRECTORY)

    
# Run Strings if selected

if STRINGS:
    files = os.listdir(DIRECTORY)
    i = 0
    l = len(files)
    # print("Running strings on all files:")
    for f1 in track(files, description="[green]"+"Running strings on all files...".ljust(32)):
        utils.strings(f1, DIRECTORY)

console.print("[green]:heavy_check_mark: Finished!")