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
import csv

sg.theme('BlueMono')	# Theme choice, blue because of Bluetooth!

def readKeyValues(inputCsvFile):
    """ A function that takes in a csv file and creates key value pair dictionary from the first and second columns. Code from https://ayeshalshukri.co.uk/category/dev/python-script-to-extract-key-value-pairs-from-csv-file/ """
	#input file reader
    infile = open(inputCsvFile, "r", encoding="utf8")
    read = csv.reader(infile)
	
    returnDictionary = {}
    returnList = []
    #for each row
    for row in read:
    	key   = row[0]
    	value = row[1]
    
    	#Add to dictionary 
    	#note will overwrite and store single occurrences
    	returnDictionary[key] = value
    
    	#Add to list (note, will store multiple occurrences)
    	returnList.append([key,value])
    return(returnDictionary)

def GetFileLocation():
    """ Opens the importing popup window for the user, allowing them to select a file. Once a file is selected, it is checked to see if it has the correct
        file extensions. Will return the file location of a working file that was selected. """

    try:
        imported_pcap_location = ''
        imported_pcap_location = sg.popup_get_file('Select PCAP File', file_types=(("PCAPNG Files", "*.pcapng"),("PCAP Files", "*.pcap")), icon='icons/bluetooth.ico', keep_on_top=True)
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
    try:
        for i in capture:
            try:
                if i.btle:
                    return True
            except:
                pass
        return False
    except Exception as e:
        sg.popup_error(f'ERROR: {e}')
        exit()

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
        else:
            sg.popup_error(f'No Bluetooth LE packets found in {pcap_file_location}, please import another file.', title=None, icon='icons/bluetooth.ico') # File doesn't contain Bluetooth LE packets, informs user to use another file.
    else:
        print('No file was selected, Stopped importing')
        return
    return(capture_dict)

def CompanyFromID(id):
    with open('data/companies.json') as f:
        data = json.load(f)
    print(data)

def PacketDetailsPopup(packet_number, capture_dict_array):
    """ Takes in a packet number and capure information in the form of a array of dictionaries when the user clicks on a specific packet.
        This will then create a window containing the information regarding that packet """

    packet_number = int(packet_number) - 1

    packet_detail_list = [
        f'Packet Number: {packet_number + 1}',
        f'Advertising Address: {capture_dict_array[packet_number].get("Advertising Address")}',
        f'Scanning Address: {capture_dict_array[packet_number].get("Scanning Address")}',
        f'RSSI: {capture_dict_array[packet_number].get("RSSI")} dBm',
        f'Frequency Channel: {capture_dict_array[packet_number].get("Channel")}',
        f'Packet Type: {capture_dict_array[packet_number].get("Packet Type")}',
        f'CRC: {capture_dict_array[packet_number].get("CRC")}',
        f'Company: {capture_dict_array[packet_number].get("Company")}',
        f'Advertising Data: {capture_dict_array[packet_number].get("Advertising Data")}']

    print(capture_dict_array[packet_number].get("Advertising Data"))

    layout2 = [[sg.Listbox(packet_detail_list, size=(60, 29), enable_events=True, font="TkFixedFont", key='PacketDetails')],       # note must create a layout from scratch every time. No reuse
                [sg.Button('Exit')]]

    PacketDetailsWindow = sg.Window('Packet Details', layout2, modal=True, icon='icons/bluetooth.ico')
    while True:
        event2, values2 = PacketDetailsWindow.read()
        if event2 == sg.WIN_CLOSED or event2 == 'Exit':
            PacketDetailsWindow.close()
            break
        if event2 == 'PacketDetails':
            packet_detail = values2["PacketDetails"][0]
            ExpandedPacketDetails(packet_detail)

def ExpandedPacketDetails(detail):
    """ Function that inputs the detail for the packet that was selected and shows popups of the requested information """

    
    # Dictionary containing packet details that are given to the user if they click on the specific packet detail.
    expanded_packet_detail_list = { 
            'Packet Number': 'This is the number of the packet in the order is was captured, starting from 1.',
            'Advertising Address': 'This address is of the advertising device\nThis can either be sent by the advertising device itself or a device asking that device for additional information in the from of a ADV_RSP packet, by sending a ADV_REQ packet.',
            'Scanning Address': 'This address is only used if the scanning device sends a packet to an advertising device, or vice-versa.\nFor example, a scanning device sends an advertising device a ADV_REQ packet, requesting for more information about the device.',
            'RSSI': 'RSSI or Recieved Signal Strength Indicator, is the measurement of power level at the receieving device.\nGenerally, the lower the number, the further the device is away from the reciever.',
            'Frequency Channel': 'This is the freqency band channel that the packet was captured on.\nChannels that are used for advertising are 37, 38, 39. With the rest being used for data.',
            'CRC': 'CRC or Cyclic Redundancy Check, is a code that is generated by protocol for each packet. This code can be checked against the packet data to see if the packet has been corrupted or modified in any way during transit.',
            'Company': 'The manufacturing company that is detailed within the packet.'
            }
    # Dictionary containing packet type details that are provided when the user clicks on the packet type information.
    expanded_packet_type_detail_list = { 
            'ADV_IND': 'Indicates the advertising device is connectable and is using undirected advertising.',
            'ADV_DIRECT_IND': 'Indicates the advertising device is connectable by only one specific central device and is using directed advertising.',
            'ADV_NONCONN_IND': 'Indicates a non-connectable advertising device, that also cannot respond to scanning requests for more info.',
            'SCAN_REQ': 'A scan request from a central device to a advertising device, requesting additional information about the device.',
            'SCAN_RSP': 'A response to the scan request (SCAN_REQ), containing additional information about the peripheral device.',
            'CONNECT_REQ': 'A connection request from a central device to a peripheral device.',
            'ADV_SCAN_IND': 'Indicates a non-connectable advertising device, that however, can respond to scanning requests for more info.'
            }
    detail_string = (re.search(r'.*: ', detail).group(0)[:-2]) # Extract the packet detail string, so it can be used to get the correct response from the dictionary.
    # If statement detecting if packet type was selected. If so, go through specific reponse for packet types. If it was not, continue with the other detail responses.
    if detail_string == 'Packet Type':
        type_string = (re.search(r':.*', detail).group(0)[2:]) # Get the packet type.
        sg.popup(expanded_packet_type_detail_list[type_string], title=type_string, keep_on_top=True, icon='icons/bluetooth.ico') # Popup showing packet type information.
    elif detail_string == 'Advertising Data':
        AdvertisingDataExpandedInfoPopup(detail)
    else:
        sg.popup(expanded_packet_detail_list[detail_string], title=detail_string, keep_on_top=True, icon='icons/bluetooth.ico') # Popup showing packet detail information, no packet type info.


def AdvertisingDataExpandedInfoPopup(advert_data):
    advert_data = advert_data[18:]
    if not advert_data == 'N/A':
        advert_data_explained = f'{advert_data}\n\n\n Above is the raw advertising data from this packet, depending on the packet type, different data will be provided.'
    else:
        advert_data_explained = 'No Advertising Data is found within this packet.\nPlease examine a packet with a type containing "ADV" in the name'
    sg.popup(advert_data_explained, title='Advertising Data', keep_on_top=True, icon='icons/bluetooth.ico') # Popup showing advertising data details.

def PopulateUniqueDevicesList(capture_dict):
    """ Function that takes in the capture details and populates the unique devices list """

    AuxList = []
    for packet in capture_dict:
        AdvertisingAddress = packet.get("Advertising Address")
        ScanningAddress = packet.get("Scanning Address")
        if AdvertisingAddress not in AuxList and not AdvertisingAddress == 'N/A':
            AuxList.append(AdvertisingAddress)
        if ScanningAddress not in AuxList and not ScanningAddress == 'N/A':
            AuxList.append(ScanningAddress)
    MainWindow.FindElement('DeviceListBox').Update(values=AuxList)

def PopulateUniqueConnectionsList(capture_dict):
    """ Function that takes in the capture details and populates the unique connections list """

    AuxList = []
    for packet in capture_dict:
        AdvertisingAddress = packet.get("Advertising Address")
        ScanningAddress = packet.get("Scanning Address")
        if AdvertisingAddress != 'N/A' and ScanningAddress != 'N/A':
            if packet.get("Packet Type") == 'SCAN_REQ':
                connection = f'{ScanningAddress} -> {AdvertisingAddress}'
            else:
                connection = f'{AdvertisingAddress} -> {ScanningAddress}'
            if connection not in AuxList:
                AuxList.append(connection)
    MainWindow.FindElement('ConnectionsListBox').Update(values=AuxList)

def PopulatePacketList(capture_dict):
    """ Function that takes in the capture details and populates the packet list """

    packetlistbox = AddPacketsToList(capture_dict)
    MainWindow.FindElement('PacketListBox').Update(values=packetlistbox)

def ParseBluetoothPCAP(capture):
    """ Takes in a capture variable from pyshark and seperates the data down into a arrayed dictionary, returning the dictionary when done """
    
    parsed_dict = [] # Creat an empty list to fill and return at the end of the function
    packet_number = 1 # Set the first packet number as 1, this will be incremented with each packet

    # Define dictionary of PDU types, so the hex can be converted easily from each packet
    PDU_Type_Dict = {
        '0x00000000': 'ADV_IND',
        '0x00000001': 'ADV_DIRECT_IND',
        '0x00000002': 'ADV_NONCONN_IND',
        '0x00000003': 'SCAN_REQ',
        '0x00000004': 'SCAN_RSP',
        '0x00000005': 'CONNECT_REQ',
        '0x00000006': 'ADV_SCAN_IND'
    }

    company_dict = readKeyValues('data/com.csv')

    for packet in capture:
        # Define empty dictionary for the packet, to fill in details later
        packet_information = {}
        
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
        
        
        # Try to fill in the CRC , if an exception occurs, fill in as N/A
        try:
            packet_information['CRC'] = packet.btle.crc
        except Exception as e:
            packet_information['CRC'] = 'N/A'
            print(e)
        
        
        # Try to fill in the Company ID , if an exception occurs, fill in as N/A
        try:
            if PDU_Type_Dict[packet.btle.advertising_header_tree.pdu_type] == 'ADV_IND':
                packet_information['Company'] = company_dict[packet.btle.advertising_data.entry[1].company_id]
            else:
                packet_information['Company'] = company_dict[packet.btle.advertising_data.entry.company_id]
        except Exception as e:
            packet_information['Company'] = 'N/A'
            print(e)
        
        # Try to fill in the Advertising Data , if an exception occurs, fill in as N/A
        try:
            packet_information['Advertising Data'] = packet.btle.advertising_data
        except Exception as e:
            packet_information['Advertising Data'] = 'N/A'
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
                  [sg.Listbox(connectionslistbox, key='ConnectionsListBox', size=(60, 29))]
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
MainWindow = sg.Window('Bluetooth Sniffing Application', layout, icon='icons/bluetooth.ico')

def main():
    """ Main function and the entry function for the application """

    # Create cap variable that starts empty, so if the user tries to export a pcap file with no capture loaded yet, it will pop an error popup
    cap = ''

    PacketDetailsWindowActive = False

    # The event loop
    while True:
        event1, values1 = MainWindow.read()   # Read the event that happened and the values dictionary
        print(event1, values1)
        if event1 == sg.WIN_CLOSED or event1 == 'Exit':     # If user closed window with X or if user clicked "Exit" button then exit
            break
        if event1 == 'About':
            OpenAboutPopup()
        if event1 == 'Live Capture':
            #capture = pyshark.LiveCapture(interface='COM4')
            #capture.sniff(timeout=10)
            #print(capture)
            print('Live Capture TBD')
        if event1 == 'Export PCAP':
            if cap == '':
                sg.popup('No Live Capture Has Been Completed to Export, Please Run a Live Capture', title='No Capture', keep_on_top=True, icon='icons/bluetooth.ico')
        if event1 == 'Import PCAP':
            capture_dictionary = ImportPCAP() # Start importing function
            if capture_dictionary != None: # Check if the returned capture is not empty, if it has data assigned, continue with the processes.
                PopulatePacketList(capture_dictionary)
                PopulateUniqueDevicesList(capture_dictionary) # Populate the unique devices list
                PopulateUniqueConnectionsList(capture_dictionary)
        if event1 == 'PacketListBox' and not PacketDetailsWindowActive:
            packet_number = re.search(r'\d+', values1["PacketListBox"][0]).group(0)
        
            PacketDetailsWindowActive = True

            PacketDetailsPopup(packet_number, capture_dictionary)

            PacketDetailsWindowActive = False

    MainWindow.close()


if __name__ == "__main__":
    """ This is executed when run from the command line """
    main()