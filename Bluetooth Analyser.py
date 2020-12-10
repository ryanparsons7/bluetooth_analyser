#!/usr/bin/env python3
"""
Ryan Parsons\'s Python 3 Bluetooth Analyser Application, created for BENG Cybersecurity and Forensics Honours Project 2020/2021.
"""

__author__ = "Ryan Parsons"
__version__ = "0.1.0"
__license__ = "GNU General Public License v3.0"

import PySimpleGUI as sg # Importing PySimpleGUI Module for GUI Functionality
import pyshark # Importing pyshark for Wireshark functionality needed for parsing data
import sys # Importing sys module for system based functions
import datetime # Importing datetime module for date and time functions
import re

sg.theme('BlueMono')	# Theme choice, blue because of Bluetooth!

def GetFileLocation():
    """ Opens the importing popup window for the user, allowing them to select a file. Once a file is selected, it is checked to see if it has the correct
        file extensions. Will return the file location of a working file that was selected. """

    try:
        imported_pcap_location = ''
        imported_pcap_location = sg.popup_get_file('Please enter the file location for the PCAP file or click browse.', file_types=(("PCAPNG Files", "*.pcapng"),("PCAP Files", "*.pcap")), icon='icons/bluetooth.ico', keep_on_top=True)
        print(imported_pcap_location)
        if imported_pcap_location == '':
            sg.popup_error('No PCAP File Selected', title=None, icon='icons/bluetooth.ico')
            return(imported_pcap_location)
        elif not imported_pcap_location.endswith(('.pcapng','.pcap')):
            sg.popup_error('The file selected is not a PCAP file.', title=None, icon='icons/bluetooth.ico')
            return(imported_pcap_location)
        elif not imported_pcap_location == '':
            print(f'Returned the pcap file location as {imported_pcap_location}')
            return(imported_pcap_location)
    except:
        print("Unexpected error:", sys.exc_info()[0])

def OpenAboutPopup():
    """ Shows the about popup window, showing information about the application. """

    about_popup = f'Bluetooth Packet Analyser Created by Ryan Parsons\nNapier University, Cybersecurity and Forensics Honours Project'
    sg.popup(about_popup, title='About', keep_on_top=True, icon='icons/bluetooth.ico')

def CheckForBLE(capture):
    """ Checks the capture variable for any BTLE headers, returns true or false. """

    for i in capture:
        try:
            if i.btle:
                return True
        except:
            pass
    return False

def AddPacketsToList(parsed_dictionary):
    """ Creates the basic list shown on the main application window. """

    packet_list = []
    for packet in parsed_dictionary:
        packet_list.append(
            f'{"Packet #" + str(packet["Packet Number"]):<13} - {"Advertising Address: " + packet["Advertising Address"]:<38} - Packet Type: {packet["Packet Type"]}'
            )
    return packet_list

def ImportPCAP():
    """ Opens the importing popup window for the user, allowing them to select a file. Once a file is selected, it is checked to see if it has the correct
        file extensions and if it contains any BTLE headers. Will return the file location of a working file that was selected. """

    pcap_file_location = GetFileLocation() # Get the file location that the user selects
    if not (pcap_file_location == None or pcap_file_location == ''):
        cap = pyshark.FileCapture(pcap_file_location, use_json=True) # Get the capture from the file into a variable and use JSON format instead
        if CheckForBLE(cap):
            print(f'Bluetooth packets found in {pcap_file_location}, continuing') # File contains Bluetooth packets, will now continue to parse
            capture_dict = ParseBluetoothPCAP(cap)
            packetlistbox = AddPacketsToList(capture_dict)
            window.FindElement('PacketListBox').Update(values=packetlistbox)
        else:
            sg.popup_error(f'No Bluetooth LE packets found in {pcap_file_location}, please import another file.', title=None, icon='icons/bluetooth.ico') # File doesn't contain Bluetooth LE packets, informs user to use another file.
    else:
        print('No file was selected, Stopped importing')
    return(capture_dict)

def PacketDetailsPopup(packet_number, capture_dict):
    packet_number = int(packet_number) - 1
    sg.popup_scrolled(
        f'Packet Number: {packet_number + 1}\nAdvertising Address: {capture_dict[packet_number].get("Advertising Address")}\nScanning Address: {capture_dict[packet_number].get("Scanning Address")}\nRSSI: {capture_dict[packet_number].get("RSSI")} dBm\nFrequency Channel: {capture_dict[packet_number].get("Channel")}\nPacket Type: {capture_dict[packet_number].get("Packet Type")}',
        keep_on_top=True,
        background_color='lightblue',
        no_titlebar=True
        )

def PopulateUniqueDevicesList(capture_dict):
    AuxList = []
    for packet in capture_dict:
        AdvertisingAddress = packet.get("Advertising Address")
        ScanningAddress = packet.get("Scanning Address")
        if AdvertisingAddress not in AuxList and not AdvertisingAddress == 'N/A':
            AuxList.append(AdvertisingAddress)
        if ScanningAddress not in AuxList and not ScanningAddress == 'N/A':
            AuxList.append(ScanningAddress)
    window.FindElement('DeviceListBox').Update(values=AuxList)

def ParseBluetoothPCAP(capture):
    """ Takes in a capture variable from pyshark and seperates the data down into a arrayed dictionary, returning the dictionary when done """

    parsed_dict = [] # Creat an empty list to fill and return at the end of the function
    packet_number = 1 # Set the first packet number as 1, this will be incremented with each packet

    # Define dictionary of PDU types, so the hex can be converted easily from each packet
    PDU_Type_Dict = {
        '0x00000000': 'ADV_IND',
        '0x00000002': 'ADV_NONCONN_IND',
        '0x00000003': 'SCAN_REQ',
        '0x00000004': 'SCAN_RSP',
        '0x00000006': 'ADV_SCAN_IND'
    }

    for packet in capture:
        # Define empty dictionary for the packet, to fill in details later
        packet_information = { 
            'Packet Number': '',
            'Advertising Address': '',
            'Scanning Address': '',
            'RSSI': '',
            'Channel': '',
            'Packet Type': ''
            }
        
        # Filled in the packet number, no exception needed
        packet_information['Packet Number'] = packet_number

        # Try to fill in the advertising address, if an exception occurs, fill in as N/A
        try:
            packet_information['Advertising Address'] = packet.btle.advertising_address.upper()
        except Exception as e:
            packet_information['Advertising Address'] = 'N/A'
            print(e)
    
        # Try to fill in the scanning address, if an exception occurs, such as it not existing, fill in as N/A
        try:
            packet_information['Scanning Address'] = packet.btle.scanning_address.upper()
        except Exception as e:
            packet_information['Scanning Address'] = 'N/A'
            print(e)
        
        
        # Try to fill in the PDU type converted from HEX string to proper name, if an exception occurs, fill in as N/A
        try:
            packet_information['Packet Type'] = PDU_Type_Dict[packet.btle.advertising_header_tree.pdu_type]
        except Exception as e:
            packet_information['Packet Type'] = 'N/A'
            print(e)
        
        
        # Try to fill in the RSSI, if an exception occurs, fill in as N/A
        try:
            packet_information['RSSI'] = packet.nordic_ble.rssi
        except Exception as e:
            packet_information['RSSI'] = 'N/A'
            print(e)
        
        
        # Try to fill in the Channel Number, if an exception occurs, fill in as N/A
        try:
            packet_information['Channel'] = packet.nordic_ble.channel
        except Exception as e:
            packet_information['Channel'] = 'N/A'
            print(e)
        
        packet_number = packet_number + 1 # Increment the packet number before processing the next packet
        parsed_dict.append(packet_information) # Append the dictionary to the array
    return parsed_dict

packetlistbox = []
devicelistbox = []
connectionslistbox = []
capture_dict = {}

frame_layout_all_packets = [
                  [sg.Listbox(packetlistbox, key='PacketListBox', size=(120, 60), enable_events=True, font="TkFixedFont")]
               ]

frame_layout_device_list = [
                  [sg.Listbox(devicelistbox, key='DeviceListBox', size=(60, 29))]
               ]

frame_layout_connections_list = [
                  [sg.Listbox(connectionslistbox, size=(60, 29))]
               ]

# The layout of the nested side column
side_column_layout = [
    [sg.Frame('Unique Devices', frame_layout_device_list, font='Any 12', title_color='blue')],
    [sg.Frame('Unique Connections', frame_layout_connections_list, font='Any 12', title_color='blue')]
]

# The layout of the window.
layout = [
    [sg.Text('Bluetooth Sniffing Application'), sg.Button('Live Capture'), sg.Button('Import PCAP'), sg.Button('Export PCAP'), sg.Button('About')],
    [sg.Frame('Bluetooth Packets', frame_layout_all_packets, font='Any 12', title_color='blue'),
    sg.Column(side_column_layout, justification='r')]
]

# Create the window with a title and a window icon.
window = sg.Window('Bluetooth Sniffing Application', layout, icon='icons/bluetooth.ico')

def main():
    """ Main entry point of the app """

    # Create cap variable that starts empty, so if the user tries to export a pcap file with no capture loaded yet, it will pop an error popup
    cap = ''

    # The event loop
    while True:
        event, values = window.read()   # Read the event that happened and the values dictionary
        print(event, values)
        if event == sg.WIN_CLOSED or event == 'Exit':     # If user closed window with X or if user clicked "Exit" button then exit
            break
        if event == 'About':
            OpenAboutPopup()
        if event == 'Live Capture':
            #capture = pyshark.LiveCapture(interface='COM4')
            #capture.sniff(timeout=10)
            #print(capture)
            print('Live Capture TBD')
        if event == 'Export PCAP':
            if cap == '':
                sg.popup('No Live Capture Has Been Completed to Export, Please Run a Live Capture', title='No Capture', keep_on_top=True, icon='icons/bluetooth.ico')
        if event == 'Import PCAP':
            capture_dictionary = ImportPCAP()
            PopulateUniqueDevicesList(capture_dictionary)
        if event == 'PacketListBox':
            packet_number = re.search(r'\d+', values["PacketListBox"][0])
            PacketDetailsPopup(packet_number.group(0), capture_dictionary)

    window.close()


if __name__ == "__main__":
    """ This is executed when run from the command line """
    main()