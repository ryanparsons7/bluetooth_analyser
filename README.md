# Python 3 Bluetooth Analyser

This repository is for my Honours Project at Edinburgh Napier University for Cybersecurity and Forensics.

## Basic Requirements
- Windows 10 or Linux System.
- Python 3 Installed.
- Wireshark Installed.
- TShark Installed. (included with Wireshark)
- Various Python Modules Installed:
    - pyserial
    - PySimpleGUI
    - pyshark
## Live Capture Requirements
- Bluefruit LE Sniffer. (found at https://www.adafruit.com/product/2269)

# Instructions
## Packet Analysis
- Install Wireshark + TShark.
- Run "Bluetooth Analyser.py" with Python 3 ("py Bluetooth Analyser.py" in Powershell or Linux shell)
- Press "Import PCAP" and select the file you wish to import.
- Click various packets to discover more information regarding their data and structure.

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