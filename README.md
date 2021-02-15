# Python 3 Bluetooth Analyser

This repository is for my Honours Project at Edinburgh Napier University for Cybersecurity and Forensics.

## Basic Requirements
- Windows 10.
- Python 3 Installed. (https://www.python.org/downloads/)
- Wireshark Installed. (https://www.wireshark.org/download.html)
- TShark Installed. (Installed by default during Wireshark installation)
- Python Modules Installed:
    - PySimpleGUI
    - pyshark
    - plotly
    - networkx
    - numpy
    - pandas

## Live Capture Requirements
- Bluefruit LE Sniffer. (found at https://www.adafruit.com/product/2269)

# Instructions

## Installation
- Download project zip by going to Code > Download ZIP
- Extract the ZIP to a new folder.
- Install Python 3 from https://www.python.org/downloads/, use default configuration.
- Install Wireshark, keep default settings and ensure TShark gets installed.
- Install the modules from the basic requirements list by using the command "pip3 install **module_name**" in either PowerShell or CMD
- Launch the Application by running "py Bluetooth Analyser.py" in PowerShell or CMD from within the "bluetooth_analyser" folder.<br>I recommend you do this by first deselecting any items in the folder, **Shift + Right Clicking** an empty area of the folder and selecting "Open PowerShell window here". This will open a PowerShell window within the directory.

## Packet Analysis
- Install Wireshark + TShark.
- Run "Bluetooth Analyser.py" with Python 3 ("py Bluetooth Analyser.py" in Powershell)
- Press "Import PCAP" and select the file you wish to import.
- Click a packet to discover more information regarding the data and structure.
- Clicking the advertising data allows you to analyse the data entries for that advertising packet.

## Live Capture
- Install Wireshark + TShark.
- Download extcap extension for Wireshark by going to the following link and downloading the latest version zip file: https://www.nordicsemi.com/Software-and-tools/Development-Tools/nRF-Sniffer-for-Bluetooth-LE/Download
- Open Wireshark and go to Help > About Wireshark > Folders Tab. Take note of the directory for "Global Extcap path".
- Open the zip file and copy/merge the "extcap" folder to the extcap folder you took note of previously.
- The extcap folder in Wireshark should now contain various files and a folder called "SnifferAPI".
- Plug in your LE Sniffer into a usb port on your system.
- Run the application and press "Live Capture", imput the amount of seconds you wish to run the capture for.
- Press "Capture" and let the application run Wireshark, conduct the capture and automatically close Wireshark.
- Once the capture is finished and Wireshark closes, the capture will be imported to be analysed as usual.
- If you wish to export the capture for later analysis, press the "Export PCAP" button and choose a file name and location.