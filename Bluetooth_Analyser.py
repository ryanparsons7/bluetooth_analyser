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
import re # Importing re module for regex usage
import csv # Importing csv module for 
import subprocess # Importing subprocess module for command line usage
import pathlib # Importing pathlib that is used to find paths
import time # Importing time module for time based functions
import os # Importing OS module for os functions
import shutil # Importing shutil module for shell utitilies
import pandas as pd # Importing pandas for graphs
import numpy as np # Importing numpy for graphs
import networkx as nx # Importing networkx for graphs
import matplotlib.pyplot as plt # Importing pyplot for graphs
from collections import Counter # Importing collections counter.
from plotly.offline import download_plotlyjs, init_notebook_mode, iplot # Importing plotly sections for network graph
import plotly.graph_objs as go # Importing plotly sections for network graph

file = open("data/theme.conf", "r")
theme_name = file.read()
file.close()

sg.theme(theme_name)	# Theme choice, blue because of Bluetooth!

def readKeyValues(inputCsvFile):
    """ A function that takes in a csv file and creates key value pair dictionary from the first and second columns. Code from https://ayeshalshukri.co.uk/category/dev/python-script-to-extract-key-value-pairs-from-csv-file/ """
	#input file reader
    infile = open(inputCsvFile, "r", encoding="utf8") # Open the spreadsheet file in read only mode and with encoding of utf8
    read = csv.reader(infile) # Read file variable
	
    returnDictionary = {} # Empty dictionary to store future data
    # for each row
    for row in read: # For every row in the spreadsheet
    	key   = row[0] # The key is the first row
    	value = row[1] # The value is the second row
    
    	returnDictionary[key] = value # Now add the key value pair to the dictionary
    
    return(returnDictionary) # Return the finished dictionary

def GetFileLocation():
    """ Opens the importing popup window for the user, allowing them to select a file. Once a file is selected, it is checked to see if it has the correct
        file extensions. Will return the file location of a working file that was selected. """

    try: # Try the following code, as errors could potentially occur
        imported_pcap_location = '' # Set an empty string for the location initially
        imported_pcap_location = sg.popup_get_file('Select PCAP File', file_types=(("PCAPNG Files", "*.pcapng"),("PCAP Files", "*.pcap")), icon='icons/bluetooth.ico', keep_on_top=True) # Get the location of the PCAP file from the user
        if imported_pcap_location == '': # If the location give is empty
            sg.popup_error('No PCAP File Selected', title=None, icon='icons/bluetooth.ico') # tell the user no file was selected
            return(imported_pcap_location) # And return the empty string
        elif not imported_pcap_location.endswith(('.pcapng','.pcap')): # If the file location string is not empty but doesn't end in the selected extensions
            sg.popup_error('The file selected is not a PCAP file.', title=None, icon='icons/bluetooth.ico') # Tell the user the file extension is not correct
            return(imported_pcap_location) # And return the empty string
        elif not imported_pcap_location == '': # And finally, if the previous checks don't trigger
            print(f'Returned the pcap file location as {imported_pcap_location}') # Print to the log the location of the file
            return(imported_pcap_location) # And return the file location
    except:
        print("Unexpected error:", sys.exc_info()[0]) # If any errors occur, print the error to the log and continue

def OpenAboutPopup():
    """ Shows the about popup window, showing information about the application. """

    about_popup = f'Bluetooth Packet Analyser Created by Ryan Parsons\nNapier University, Cybersecurity and Forensics Honours Project' # Text to show on popup
    sg.popup(about_popup, title='About', keep_on_top=True, icon='icons/bluetooth.ico') # Display about popup

def CheckForBLE(capture):
    """ Checks the capture variable for any BTLE headers, returns true or false. """
    try: # Try the following code
        for i in capture: # For every packet in the capture
            try:
                if i.btle: # If the packet contains a BTLE section
                    return True # Return True, indicating that the capture has at least 1 BLE packet
            except:
                pass # If the check fails due to error, go to the next packet
        return False
    except Exception as e: # If some big error occurs with reading the capture, produce a popup showing the error
        sg.popup_error(f'ERROR: {e}')
        exit() # Exit app

def AddPacketsToList(parsed_dictionary):
    """ Creates the basic list shown on the main application window. """

    packet_list = [] # Create empty array for the packets
    for packet in parsed_dictionary: # For every packet in the parsed dictionary
        packet_list.append(
            f'{"Packet #" + str(packet["Packet Number"]):<13} - {"Adv Address: " + packet["Advertising Address"]:<32} - {"Scan Address: " + packet["Scanning Address"]:<32} - Packet Type: {packet["Packet Type"]}' # Append the brief summary for that packet to be displayed on the main window
            )
    return packet_list # Return the packet list when done with all packets

def ImportPCAP(*pcap_file_location):
    """ Opens the importing popup window for the user, allowing them to select a file. Once a file is selected, it is checked to see if it has the correct
        file extensions and if it contains any BTLE headers. Will return the file location of a working file that was selected. """

    if pcap_file_location == (): # If the pcap file location is empty, there is no temp file being used.
        pcap_file_location = GetFileLocation() # Get the file location that the user selects
    else: # If their is a file location passed through
        pcap_file_location = pcap_file_location[0] # Get the file location from the variable.
    if not (pcap_file_location == None or pcap_file_location == ''): #  Check to make sure the file location isn't an empty string or is a none.
        cap = pyshark.FileCapture(pcap_file_location, use_json=True) # Get the capture from the file into a variable and use JSON format instead
        if CheckForBLE(cap): # Check the capture for BLE packets
            print(f'Bluetooth packets found in {pcap_file_location}, continuing') # File contains Bluetooth packets, will now continue to parse
            capture_dict = ParseBluetoothPCAP(cap) # Parse the capture and put parsed data into a variable.
        else:
            sg.popup_error(f'No Bluetooth LE packets found in {pcap_file_location}, please import another file.', title=None, icon='icons/bluetooth.ico') # File doesn't contain Bluetooth LE packets, informs user to use another file.
    else:
        print('No file was selected, Stopped importing')
        return
    if capture_dict != None: # Check if the returned capture is not empty, if it has data assigned, continue with the processes.
                PopulatePacketList(capture_dict) # Populate packet list
                PopulateUniqueDevicesList(capture_dict) # Populate the unique devices list
                PopulateUniqueConnectionsList(capture_dict) # Populate unique connections list
    return(capture_dict)

def createDir(folder_path):
    '''Function that takes in a relative or absolute path, checks if that
    path exists, and if it does, it will delete it's contents. If the directory
    doesn\'t exist, it will create it'''

    # Try block, if permission errors occur, the error details will be printed
    try:
        # IF the path exists, run the code that will delete it's contents
        if os.path.exists(folder_path):
            filelist = [f for f in os.listdir(folder_path)]
            for f in filelist:
                os.remove(os.path.join(folder_path, f))
            print(f'Output data folder already exists, '
                  f'deleted the contents of folder: {folder_path}')
        # Else, if the path doesn't exist, just make the directory
        else:
            os.mkdir(folder_path)
            print(f'Output data folder doesn\'t exist, '
                  f'created folder: {folder_path}\n')
    # If a permission error occurs, recommend solution and quit the script
    except PermissionError as err:
        print(f'Exception Occured: {err}\nTry running the script elevated')
        quit()
    # If any other exceptions occur, print the error details and quit
    except Exception as err:
        print(f'Exception Occured: {err}')
        quit()

def GetAdvertisingDataType(type_hex):
    """ Takes in the advertising entry type in hex and outputs a string of the type. """

    # Dictionary for advertising data types
    type_dict = {
        '0x1': 'Flags',
        '0x2': 'Incomplete List of 16-bit Service Class UUIDs',
        '0x3': 'Complete List of 16-bit Service Class UUIDs',
        '0x4': 'Incomplete List of 32-bit Service Class UUIDs',
        '0x5': 'Complete List of 32-bit Service Class UUIDs',
        '0x6': 'Incomplete List of 128-bit Service Class UUIDs',
        '0x7': 'Complete List of 128-bit Service Class UUIDs',
        '0x8': 'Shortened Local Name',
        '0x9': 'Complete Local Name',
        '0xa': 'Tx Power Level',
        '0xb': 'OOB Optional Data Length',
        '0xd': 'Class of Device',
        '0xe': 'Simple Pairing Hash C',
        '0xf': 'Simple Pairing Randomizer R',
        '0x10': 'Security Manager TK Value',
        '0x11': 'Security Manager Out of Band Flags',
        '0x12': 'Slave Connection Interval Range',
        '0x14': 'List of 16-bit Service Solicitation UUIDs',
        '0x15': 'List of 128-bit Service Solicitation UUIDs',
        '0x16': 'Service Data - 16-bit UUID',
        '0x17': 'Public Target Address',
        '0x18': 'Random Target Address',
        '0x19': 'Appearance',
        '0x1a': 'Advertising Interval',
        '0x1b': 'LE Bluetooth Device Address',
        '0x1c': 'LE Role',
        '0x1d': 'Simple Pairing Hash C-256',
        '0x1e': 'Simple Pairing Randomizer R-256',
        '0x1f': 'List of 32-bit Service Solicitation UUIDs',
        '0x20': 'Service Data - 32-bit UUID',
        '0x21': 'Service Data - 128-bit UUID',
        '0x22': 'LE Secure Connections Confirmation Value',
        '0x23': 'LE Secure Connections Random Value',
        '0x24': 'URI',
        '0x25': 'Indoor Positioning',
        '0x26': 'Transport Discovery Data',
        '0x27': 'LE Supported Features',
        '0x28': 'Channel Map Update Indication',
        '0x29': 'PB-ADV',
        '0x2b': 'Mesh Message',
        '0x2b': 'Mesh Beacon',
        '0x2c': 'BIGInfo',
        '0x2d': 'Broadcast_Code',
        '0x3d': '3D Information Data',
        '0xff': 'Manufacturer Specific Data'
    }

    return type_dict[type_hex] # Return the correct data type name to the calling code


def PacketDetailsPopup(packet_number, capture_dict_array):
    """ Takes in a packet number and capure information in the form of a array of dictionaries when the user clicks on a specific packet.
        This will then create a window containing the information regarding that packet """

    packet_number = int(packet_number) - 1 # Because the packet number is starting at 0, increase it by one to start at 1.

    if capture_dict_array[packet_number].get("Advertising Data") == 'N/A': # If the packet doesn't have advertising data
        advertising_data_string = 'N/A' # Get the advertising data string to N/A
    else: 
        advertising_data_string = 'Click for more info' # Else set a string so the user can select it to view the data

    # Array containing packet details taken from capture
    packet_detail_list = [
        f'Packet Number: {packet_number + 1}',
        f'Advertising Address: {capture_dict_array[packet_number].get("Advertising Address")}',
        f'Scanning Address: {capture_dict_array[packet_number].get("Scanning Address")}',
        f'RSSI: {capture_dict_array[packet_number].get("RSSI")} dBm',
        f'Frequency Channel: {capture_dict_array[packet_number].get("Channel")}',
        f'Packet Type: {capture_dict_array[packet_number].get("Packet Type")}',
        f'CRC: {capture_dict_array[packet_number].get("CRC")}',
        f'Company: {capture_dict_array[packet_number].get("Company")}',
        f'Advertising Data: {advertising_data_string}']

    # Create the new layout from scratch
    layout2 = [[sg.Listbox(packet_detail_list, size=(60, 29), enable_events=True, font="TkFixedFont", key='PacketDetails')],
                [sg.Button('Exit')]]

    PacketDetailsWindow = sg.Window('Packet Details', layout2, modal=True, icon='icons/bluetooth.ico') # Create window

    # While true loop to capture events and values
    while True:
        event2, values2 = PacketDetailsWindow.read() # Get events and values from the reading of the window
        if event2 == sg.WIN_CLOSED or event2 == 'Exit': # If the user closes the window or presses Exit
            PacketDetailsWindow.close() # Close the window
            break # and break the loop
        if event2 == 'PacketDetails': # If the user clicks on an item in the list box
            packet_detail = values2["PacketDetails"][0] # Get what they clicked on
            if packet_detail.startswith('Advertising Data:'): # If the item starts with advertising data
                if not packet_detail.startswith('Advertising Data: N/A'): # and the item isn't an empty advertising data entry
                    ExpandedAdvertisingDataPopup(capture_dict_array[packet_number].get("Advertising Data"), capture_dict_array[packet_number].get("Packet Type")) # Call the advertising data window function to show the user the advertising info
            else:
                ExpandedPacketDetails(packet_detail) # Else just show the regular expanded packet details window via the function

def ExpandedAdvertisingDataPopup(advert_data, packet_type):
    """ This function runs whenever the user presses on the advertising data section to see more information.
    The function will then take in the packet type and advertising data, determine what format the data will be stored in and display it to user. """

    # A dictionary for details regarding different entry data points
    expanded_advertising_detail_list = { 
        'Length': 'This value indicates how long the entry is in bytes.',
        'UUID 16': 'The universally unique identifier (UUID) is a ID that is allocated to a specific group or company.',
        'Type': 'This indicates the type of entry.',
        'Data': 'This is the data for this entry in raw format.',
        'Low Energy General Discoverable Mode': 'This indicates to scanning devices that the advertising device is in General Discoverable Mode.\n0x01 = Enabled\n0x00 = Disabled',
        'Low Energy Limited Discoverable Mode': 'This indicates to scanning devices that the advertising device is in Limited Discoverable Mode. This mode generally has higher priority over General mode, and has a faster advertising interval.\n0x01 = Enabled\n0x00 = Disabled',
        'Power Level': 'The transmitted power of the packet in dBm.',
        'Low Energy BREDR Support Controller': 'Indicates that the use of both Low Energy and BR/EDR to the same device (Controller), is allowed.',
        'Low Energy BREDR Support Host': 'Indicates that the use of both Low Energy and BR/EDR to the same device (Host), is allowed.',
        'Company ID': 'The manufacturer company ID, this is converted for you to the company name in the previous window.',
        'BREDR Not Supported': 'Indicates that the device does not support BR/EDR (Enhanced Data Rate)'
        }

    entries = [] # Set entries to an empty list
    entry_length = 1 # Set the default entry length to 1

    if type(advert_data.entry) == pyshark.packet.layer.JsonLayer: # if the entry is of type jsonlayer, it means its only 1 entry and not a list of entries
        entries.append(f'Entry 1: {GetAdvertisingDataType(hex(int(advert_data.entry.type)))}') # Because of this, list it as the only entry, entry 1, with the type named
    else: # if their is more than 1 entry
        entry_length = 0 # Set the entry length to 0
        for idx, entry in enumerate(advert_data.entry): # enumerate through the entries
            print(f'Entry {idx + 1}:\n{entry}') # Print what entry is found for debug purposes
            entries.append(f'Entry {idx + 1}: {GetAdvertisingDataType(hex(int(advert_data.entry[idx].type)))}') # Append the entry to the entries list with the entry number and the type name
            entry_length = entry_length + 1 # increment the entry length

    print(f'Number of Entries: {entry_length}') # After going through all entries, print the number of entries
    
    # Create layout for new window from scratch
    layout3 = [[sg.Listbox(entries, size=(100, 20), enable_events=True, font="TkFixedFont", key='AdvertDetails')],
                [sg.Button('Exit')]]

    AdvertisingDataDetailsWindow = sg.Window('Advertising Data Details', layout3, modal=True, icon='icons/bluetooth.ico') # Create window from layout

    # While true loop to catch events and values
    while True:
        event3, values3 = AdvertisingDataDetailsWindow.read() # Get events and values to variables
        print(event3, values3) # Print any values or events that get produced
        if event3 == sg.WIN_CLOSED or event3 == 'Exit': # If the user closes the window or presses Exit
            AdvertisingDataDetailsWindow.close() # Close the window
            break # and break the true loop
        if event3 == 'AdvertDetails': # If the user clicks on a item within the window list
            if values3["AdvertDetails"][0] == '< Back': # If the the item is the back button
                AdvertisingDataDetailsWindow.FindElement('AdvertDetails').Update(values=entries) # reload the list with the original entries listing
            # if the item selected starts with a specific string, show a popup that details what that detail means to the user.
            elif values3["AdvertDetails"][0].startswith('Length'):
                sg.popup(expanded_advertising_detail_list['Length'], title='Length', keep_on_top=True, icon='icons/bluetooth.ico')
            elif values3["AdvertDetails"][0].startswith('UUID 16'):
                sg.popup(expanded_advertising_detail_list['UUID 16'], title='UUID 16', keep_on_top=True, icon='icons/bluetooth.ico')
            elif values3["AdvertDetails"][0].startswith('Type'):
                sg.popup(expanded_advertising_detail_list['Type'], title='Type', keep_on_top=True, icon='icons/bluetooth.ico')
            elif values3["AdvertDetails"][0].startswith('Data'):
                sg.popup(expanded_advertising_detail_list['Data'], title='Data', keep_on_top=True, icon='icons/bluetooth.ico')
            elif values3["AdvertDetails"][0].startswith('Low Energy General Discoverable Mode'):
                sg.popup(expanded_advertising_detail_list['Low Energy General Discoverable Mode'], title='Low Energy General Discoverable Mode', keep_on_top=True, icon='icons/bluetooth.ico')
            elif values3["AdvertDetails"][0].startswith('Low Energy Limited Discoverable Mode'):
                sg.popup(expanded_advertising_detail_list['Low Energy Limited Discoverable Mode'], title='Low Energy Limited Discoverable Mode', keep_on_top=True, icon='icons/bluetooth.ico')
            elif values3["AdvertDetails"][0].startswith('Power Level'):
                sg.popup(expanded_advertising_detail_list['Power Level'], title='Power Level', keep_on_top=True, icon='icons/bluetooth.ico')
            elif values3["AdvertDetails"][0].startswith('Low Energy BREDR Support Controller'):
                sg.popup(expanded_advertising_detail_list['Low Energy BREDR Support Controller'], title='Low Energy BREDR Support Controller', keep_on_top=True, icon='icons/bluetooth.ico')
            elif values3["AdvertDetails"][0].startswith('Low Energy BREDR Support Host'):
                sg.popup(expanded_advertising_detail_list['Low Energy BREDR Support Host'], title='Low Energy BREDR Support Host', keep_on_top=True, icon='icons/bluetooth.ico')
            elif values3["AdvertDetails"][0].startswith('BREDR Not Supported'):
                sg.popup(expanded_advertising_detail_list['BREDR Not Supported'], title='BREDR Not Supported', keep_on_top=True, icon='icons/bluetooth.ico')
            elif values3["AdvertDetails"][0].startswith('Company ID'):
                sg.popup(expanded_advertising_detail_list['Company ID'], title='Company ID', keep_on_top=True, icon='icons/bluetooth.ico')
            
            # If the item starts with entry, it means the user has selected one of the entries in the list
            elif values3["AdvertDetails"][0].startswith('Entry'):
                entry_number = int(values3["AdvertDetails"][0][6:7]) # Get the entry number
                print(entry_number) # Print it for debug purposes
                new_list = ['< Back'] # Create a new list with the back button as the first value

                # If the packet type is ADV_SCAN_IND
                if packet_type == 'ADV_SCAN_IND':
                    try:
                        test_var = advert_data.entry[1].service_data # See if the packet type is the first of the 2 sub-types
                        ADV_SCAN_IND_Type = 1 # if the above line works, it will confirm type 1
                    except AttributeError:
                        ADV_SCAN_IND_Type = 2 # otherwise, set type 2
                    if ADV_SCAN_IND_Type == 1: # If the sub-type is 1, add the details to the displayed list for that sub-type
                        if entry_number == 1: # If the entry number equals 1, append the correct details
                            new_list.append(f'Length: {advert_data.entry[0].length}')
                            new_list.append(f'UUID 16: {hex(int(advert_data.entry[0].uuid_16))}')
                            new_list.append(f'Type: {GetAdvertisingDataType(hex(int(advert_data.entry[0].type)))}')
                        if entry_number == 2: # If the entry number equals 2, append the correct details
                            new_list.append(f'Length: {advert_data.entry[1].length}')
                            new_list.append(f'UUID 16: {hex(int(advert_data.entry[1].uuid_16))}')
                            new_list.append(f'Service Data: {advert_data.entry[1].service_data}')
                            new_list.append(f'Type: {GetAdvertisingDataType(hex(int(advert_data.entry[1].type)))}')

                    if ADV_SCAN_IND_Type == 2: # If the sub-type is 2, add the details to the displayed list for that sub-type
                        if entry_number == 1: # If the entry number equals 1, append the correct details
                            new_list.append(f'Length: {advert_data.entry[0].length}')
                            new_list.append(f'UUID 16: {hex(int(advert_data.entry[0].uuid_16))}')
                            new_list.append(f'Type: {GetAdvertisingDataType(hex(int(advert_data.entry[0].type)))}')
                        if entry_number == 2: # If the entry number equals 2, append the correct details
                            new_list.append(f'Length: {advert_data.entry[1].length}')
                            new_list.append(f'UUID 16: {hex(int(advert_data.entry[1].uuid_16))}')
                            new_list.append(f'Type: {GetAdvertisingDataType(hex(int(advert_data.entry[1].type)))}')
                    
                # If the packet type is ADV_IND
                if packet_type == 'ADV_IND':
                    if entry_length == 3: # if the amount of entries equal 3
                        try:
                            test_var = advert_data.entry[0].le_general_discoverable_mode # See if the packet is the first of the 2 sub-types for this length
                            ADV_IND_Type = 1 # If the above line works, set the sub-type as 1
                        except AttributeError:
                            ADV_IND_Type = 2 # else set sub-type of 2
                        if ADV_IND_Type == 1: # If the sub-type is 1, add the details to the displayed list for that sub-type
                            if entry_number == 1: # If the entry number equals 1, append the correct details
                                new_list.append(f'Low Energy General Discoverable Mode: {advert_data.entry[0].le_general_discoverable_mode}')
                                new_list.append(f'Low Energy Limited Discoverable Mode: {advert_data.entry[0].le_limited_discoverable_mode}')
                                new_list.append(f'Length: {advert_data.entry[0].length}')
                                new_list.append(f'Type: {GetAdvertisingDataType(hex(int(advert_data.entry[0].type)))}')
                                new_list.append(f'Low Energy BREDR Support Host: {advert_data.entry[0].le_bredr_support_host}')
                                new_list.append(f'Low Energy BREDR Support Controller: {advert_data.entry[0].le_bredr_support_controller}')
                                new_list.append(f'BREDR Not Supported: {advert_data.entry[0].bredr_not_supported}')
                            if entry_number == 2: # If the entry number equals 2, append the correct details
                                new_list.append(f'Type: {GetAdvertisingDataType(hex(int(advert_data.entry[1].type)))}')
                                new_list.append(f'Power Level: {advert_data.entry[1].power_level}')
                                new_list.append(f'Length: {advert_data.entry[1].length}')
                            if entry_number == 3: # If the entry number equals 3, append the correct details
                                new_list.append(f'Length: {advert_data.entry[2].length}')
                                new_list.append(f'Data: {advert_data.entry[2].data}')
                                new_list.append(f'Type: {GetAdvertisingDataType(hex(int(advert_data.entry[2].type)))}')
                                new_list.append(f'Company ID: {advert_data.entry[2].company_id}')
                        elif ADV_IND_Type == 2: # If the sub-type is 2, add the details to the displayed list for that sub-type
                            if entry_number == 1: # If the entry number equals 1, append the correct details
                                new_list.append(f'Device Name: {advert_data.entry[0].device_name}')
                                new_list.append(f'Length: {advert_data.entry[0].length}')
                                new_list.append(f'Type: {GetAdvertisingDataType(hex(int(advert_data.entry[0].type)))}')
                            if entry_number == 2: # If the entry number equals 2, append the correct details
                                new_list.append(f'Length: {advert_data.entry[1].length}')
                                new_list.append(f'Type: {GetAdvertisingDataType(hex(int(advert_data.entry[1].type)))}')
                            if entry_number == 3: # If the entry number equals 3, append the correct details
                                new_list.append(f'SSP OOB Length: {advert_data.entry[2].ssp_oob_length}')
                                new_list.append(f'Length: {advert_data.entry[2].length}')
                                new_list.append(f'Type: {GetAdvertisingDataType(hex(int(advert_data.entry[2].type)))}')
                    elif entry_length == 2:  # if the amount of entries equal 2
                        try:
                            test_var = advert_data.entry[1].data # See if the packet is the first of the 2 sub-types for this length
                            ADV_IND_Type = 1 # If the above line works, set the sub-type as 1
                        except AttributeError:
                            ADV_IND_Type = 2 # else set sub-type of 2
                        if ADV_IND_Type == 1: # If the sub-type is 1, add the details to the displayed list for that sub-type
                            if entry_number == 1: # If the entry number equals 1, append the correct details
                                new_list.append(f'Low Energy General Discoverable Mode: {advert_data.entry[0].le_general_discoverable_mode}')
                                new_list.append(f'Low Energy Limited Discoverable Mode: {advert_data.entry[0].le_limited_discoverable_mode}')
                                new_list.append(f'Length: {advert_data.entry[0].length}')
                                new_list.append(f'Type: {GetAdvertisingDataType(hex(int(advert_data.entry[0].type)))}')
                                new_list.append(f'Low Energy BREDR Support Host: {advert_data.entry[0].le_bredr_support_host}')
                                new_list.append(f'Low Energy BREDR Support Controller: {advert_data.entry[0].le_bredr_support_controller}')
                                new_list.append(f'BREDR Not Supported: {advert_data.entry[0].bredr_not_supported}')
                            if entry_number == 2: # If the entry number equals 2, append the correct details
                                new_list.append(f'Length: {advert_data.entry[1].length}')
                                try:
                                    new_list.append(f'Data: {advert_data.entry[1].data}') # Try to get this data
                                except Exception:
                                    print('No data field, skipping field') # If it fails, just skip it and print an error to log
                                new_list.append(f'Type: {GetAdvertisingDataType(hex(int(advert_data.entry[1].type)))}')
                                new_list.append(f'Company ID: {advert_data.entry[1].company_id}')                 
                        if ADV_IND_Type == 2: # If the sub-type is 2, add the details to the displayed list for that sub-type
                            if entry_number == 1: # If the entry number equals 1, append the correct details
                                new_list.append(f'Low Energy General Discoverable Mode: {advert_data.entry[0].le_general_discoverable_mode}')
                                new_list.append(f'Low Energy Limited Discoverable Mode: {advert_data.entry[0].le_limited_discoverable_mode}')
                                new_list.append(f'Length: {advert_data.entry[0].length}')
                                new_list.append(f'Type: {GetAdvertisingDataType(hex(int(advert_data.entry[0].type)))}')
                                new_list.append(f'Low Energy BREDR Support Host: {advert_data.entry[0].le_bredr_support_host}')
                                new_list.append(f'Low Energy BREDR Support Controller: {advert_data.entry[0].le_bredr_support_controller}')
                                new_list.append(f'BREDR Not Supported: {advert_data.entry[0].bredr_not_supported}')
                            if entry_number == 2: # If the entry number equals 2, append the correct details
                                new_list.append(f'Length: {advert_data.entry[1].length}')
                                new_list.append(f'UUID 16: {advert_data.entry[1].uuid_16}')
                                new_list.append(f'Type: {GetAdvertisingDataType(hex(int(advert_data.entry[1].type)))}')

                # If the packet type is ADV_NONCONN_IND, append the related details to the list
                if packet_type == 'ADV_NONCONN_IND':
                    new_list.append(f'Company ID: {advert_data.entry.company_id}')
                    new_list.append(f'Data: {advert_data.entry.data}')
                    new_list.append(f'Length: {advert_data.entry.length}')
                    new_list.append(f'Type: {GetAdvertisingDataType(hex(int(advert_data.entry.type)))}')

                # When the correct details have been appended to the list, update the window list box
                AdvertisingDataDetailsWindow.FindElement('AdvertDetails').Update(values=new_list)

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
            'Company': 'The manufacturing company that is stored within the packet.'
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
        try:
            type_string = (re.search(r':.*', detail).group(0)[2:]) # Get the packet type.
            sg.popup(expanded_packet_type_detail_list[type_string], title=type_string, keep_on_top=True, icon='icons/bluetooth.ico') # Popup showing packet type information.
        except KeyError:
            sg.popup_error('The packet type was not found within the database.', icon='icons/bluetooth.ico')
    else:
        sg.popup(expanded_packet_detail_list[detail_string], title=detail_string, keep_on_top=True, icon='icons/bluetooth.ico') # Popup showing packet detail information, no packet type info.

def PopulateUniqueDevicesList(capture_dict):
    """ Function that takes in the capture details and populates the unique devices list """

    AuxList = [] # Set an empty array
    for packet in capture_dict: # For every packet in the capture
        AdvertisingAddress = packet.get("Advertising Address") # Get the advertising address
        ScanningAddress = packet.get("Scanning Address") # Get the scanning address
        if AdvertisingAddress not in AuxList and not AdvertisingAddress == 'N/A': # If the advertising address is not already in the aux list and it's not N/A
            AuxList.append(AdvertisingAddress) # append it to the aux list
        if ScanningAddress not in AuxList and not ScanningAddress == 'N/A': # If the scanning address is not already in the aux list and it's not N/A
            AuxList.append(ScanningAddress) # append it to the aux list
    MainWindow.FindElement('DeviceListBox').Update(values=AuxList) # Update the unique device list element with the new device list
    AddrFilterList = AuxList # Add the unique device list to the address filter list variable
    AddrFilterList.insert(0, 'Any') # Add the Any option to the top of the list
    MainWindow.FindElement('AddrFilter').Update(values=AddrFilterList) # Update the filter list with the new device list

def PopulateUniqueConnectionsList(capture_dict):
    """ Function that takes in the capture details and populates the unique connections list """

    AuxList = [] # Set an empty array
    for packet in capture_dict: # For every packet in the capture
        AdvertisingAddress = packet.get("Advertising Address") # Get the advertising address
        ScanningAddress = packet.get("Scanning Address") # Get the scanning address
        if AdvertisingAddress != 'N/A' and ScanningAddress != 'N/A': # If the advertising address and scanning address are both not N/A
            if packet.get("Packet Type") == 'SCAN_REQ': # If the packet type is SCAN_REQ
                connection = f'{ScanningAddress} -> {AdvertisingAddress}' # The connection goes from scanning address to advertising address
            else:
                connection = f'{AdvertisingAddress} -> {ScanningAddress}' # Otherwise, it goes the other way around
            if connection not in AuxList: # If the connection formed is not in the aux list
                AuxList.append(connection) # append it, this avoids duplicates
    MainWindow.FindElement('ConnectionsListBox').Update(values=AuxList) # Now update the unique connections window with the unique connections list

def PopulatePacketList(capture_dict):
    """ Function that takes in the capture details and populates the packet list """

    packetlistbox = AddPacketsToList(capture_dict)
    MainWindow.FindElement('PacketListBox').Update(values=packetlistbox)
    UpdatePacketCount(len(packetlistbox))

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

    company_dict = readKeyValues('data/com.csv') # read key values from the spreadsheet and place into variable

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
                try:
                    packet_information['Company'] = company_dict[packet.btle.advertising_data.entry[1].company_id]
                except:
                    packet_information['Company'] = company_dict[packet.btle.advertising_data.entry[2].company_id]
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
    return parsed_dict # Return the final parsed capture

def LiveCapture():
    """ When the function is ran, a window is displayed to the user that allows them to configure live capture parameters and start a live capture """
    
    # Create a layout for the live capture window
    live_capture_layout = [
            [sg.Text('Please select your parameters and click the Capture button to start')],
            [sg.Text('Capture time in seconds'), sg.InputText()],
            [sg.Button('Capture'), sg.Button('Exit')]
    ]
    
    # Create new window using the layout above
    CaptureWindow = sg.Window('Live Capture', live_capture_layout, modal=True, icon='icons/bluetooth.ico')

    # Start event and values true loop to capture user events
    while True:
        event2, values2 = CaptureWindow.read() # Capture any user events into events and values
        if event2 == sg.WIN_CLOSED or event2 == 'Exit': # If the user closes the window or presses exit
            CaptureWindow.close() # Close the window 
            break # and break the true loop
        if event2 == 'Capture': # If the user presses capture
            if not values2[0] == '' and values2[0].isnumeric(): # If the user enters something that is numeric only
                current_folder = pathlib.Path(__file__).parent.absolute() # Get the current folder of the application
                timer = float(values2[0]) # Get the user set number from the values capture
                arguments = f'-i COM3 -k -w "{current_folder}\\temp\\temp_capture.pcapng" -a duration:{timer}' # Set the arguments for the Wireshark application
                install_location = 'C:\\Program Files\\Wireshark\\Wireshark.exe' # Default location for Wireshark
                if not os.path.isfile(install_location): # If Wireshark isn't installed in the default location
                    sg.popup_error('The Wireshark Executable is not located at the default location. Please navigate and select the "Wireshark.exe".', icon='icons/bluetooth.ico') # Inform the user about Wireshark not being the default location
                    install_location = sg.popup_get_file('Choose Wireshark.exe', icon='icons/bluetooth.ico') # Get the user to select the Wireshark executable in the true installation folder
                if install_location is None: # If the user closes the file selector popup
                    CaptureWindow.close() # exit out of the window
                    break # and break the true loop
                ext_cap_folder = install_location.removesuffix('Wireshark.exe') + 'extcap' # Set the folder for the extcap installation
                if not os.path.isdir(f'{ext_cap_folder}\\SnifferAPI'): # If the folder for the sniffer API does not exist
                    sg.popup_error('The Sniffer API is not installed correctly, please follow the installation guide on the GitHub page".', icon='icons/bluetooth.ico') # Inform the user the API isn't installed correctly
                    CaptureWindow.close() # close the window
                    break # and break the true loop
                wireshark_proc = subprocess.Popen(f'{install_location} {arguments}') # Open Wireshark with the arguments
                time.sleep(timer + 10) # Wait for the capture to finish with 10 seconds on top of that to account for loading times
                wireshark_proc.kill() # Kill Wireshark process
                CaptureWindow.close() # Close the capture window
                temp_file = f'{current_folder}\\temp\\temp_capture.pcapng' # Set a string for the location of the temp file
                if not os.path.isfile(temp_file): # if the temp file that Wireshark outputted doesn't exist
                    # Inform the user the capture failed for some reason and break the true loop
                    sg.popup_error('The capture file from Wireshark was not created, this may be due to the sniffer not being connected properly. Please read any error messages that appear in the Wireshark application when it opens.', icon='icons/bluetooth.ico')
                    break
                ImportPCAP(temp_file) # if the capture goes successfully, import the capture from the temporary location
                break # and break the true loop
            else: # If the user didn't enter a number
                sg.popup_error('Please enter a number.', icon='icons/bluetooth.ico') # Inform the user via a popup

def ExportPCAP():
    """ Checks if the temporary capture file exist and if it does, it will copy it to the file that the user selects """
    
    if os.path.isfile('temp/temp_capture.pcapng'): # If the temporary capture file exists
        file_save = sg.popup_get_file('Save PCAP File', save_as=True, icon='icons/bluetooth.ico') # Ask the user where they wish to save the file to
        if not file_save.endswith('.pcapng'): # If the file location provided doesn't end in .pcapng
            file_save = "".join((file_save, '.pcapng')) # Add it to the end of the file name
        shutil.copy('temp/temp_capture.pcapng', file_save) # Copy the temp file to a new file called what was determined previously
        if os.path.isfile(file_save): # Check if the file has been copied
            sg.popup_ok(f'Capture has been saved to {file_save}') # If the file has been copied successfully, tell the user where it was saved
        else: # If the temp file doesn't exist
            sg.popup_error('Capture failed to save, try again.') #  Tell the user the capture didn't get saved
    else:
        sg.popup_error('No Live Capture Temporary File Is Available, Please Run a Live Capture', title='Error in Exporting', icon='icons/bluetooth.ico')

def ApplyFilter(capture_dict, type_filter, address_filter):
    """ Applies filters to the capture dictionary and resubmits it to the displays """
    
    new_capture = [] # Set empty array
    for packet in capture_dict: # For every packet in the capture
        match = True # Set the match to a default of True
        if packet['Packet Type'] != type_filter and type_filter != 'Any': # If the packet type doesn't match the type filter selected and the filter also isn't set to Any
            match = False # Set the match to False
        if (packet['Advertising Address'] != address_filter and packet['Scanning Address'] != address_filter) and address_filter != 'Any': # If the advertising and scanning address doesn't match the address filter, and the filter isn't set to any
            match = False # Set the match to False
        if match == True: # If the packet matches the filter set
            new_capture.append(packet) # Append the packet to the new capture
    
    if new_capture != None: # Check if the returned capture is not empty, if it has data assigned, continue with the processes.
        PopulatePacketList(new_capture) # Populate packet list

def NetworkMapInfoGen(capture_dict):
    """ Generates a dictionary of packets with address as the key, and the manufacter as the value """

    device_dict = {} # Create an empty dictionary for the devices

    for packet in capture_dict: # For every packet in the capture
        AdvertisingAddress = packet.get("Advertising Address") # Get the advertising address
        ScanningAddress = packet.get("Scanning Address") # Get the scanning address
        if AdvertisingAddress not in device_dict and not AdvertisingAddress == 'N/A': # If the advertising address is not in the device dictionary already and isn't N/A
            device_dict[AdvertisingAddress] = 'N/A' # append it to the dictionary with the value of N/A
        if ScanningAddress not in device_dict and not ScanningAddress == 'N/A': # If the scanning address is not the in device dictionary already and isn't N/A
            device_dict[ScanningAddress] = 'N/A' # append it to the dictionary with the value of N/A

    for packet in capture_dict: # For every packet in the capture again
        if packet['Packet Type'] == 'ADV_IND' or packet['Packet Type'] == 'ADV_DIRECT_IND' or packet['Packet Type'] == 'ADV_NONCONN_IND' or packet['Packet Type'] == 'ADV_SCAN_IND': # If the packet has a type that is used for advertising
            device_dict[packet['Advertising Address']] = packet['Company'] # Add the company to the value of the key/device
    return(device_dict) # Return the dictionary

def UpdatePacketCount(count_num):
    """ When run, will update the packet count text """

    MainWindow.FindElement('PacketNumberText').Update(f'Number of Packets That Match Filter: {count_num}') # reload the list with the original entries listing

def NetworkMap(capture_dict):
    """ Creates a map of the network from the capture file """

    device_dictionary = NetworkMapInfoGen(capture_dict) # Get the device dictionary for each unique device on the network along with its company as the value

    # Create some empty arrays for later
    SourceList = []
    DestinationList = []
    StandaloneList = []

    for packet in capture_dict: # For every packet in the capture
        AdvertisingAddress = packet.get("Advertising Address") # Get the advertising address
        ScanningAddress = packet.get("Scanning Address") # Get the scanning address
        if AdvertisingAddress != 'N/A' and ScanningAddress != 'N/A': # If the advertising address and scanning address isn't N/A
            if packet.get("Packet Type") == 'SCAN_REQ': # If the packet type is SCAN_REQ
                source = ScanningAddress # The source is the scanning address
                destination = AdvertisingAddress # and the destination is the advertising address
            else: # Otherwise it's the otherway around
                destination = ScanningAddress
                source = AdvertisingAddress
            SourceList.append(source) # Append the source to the source list
            DestinationList.append(destination) # Append the destination to the destination list
        
        # If the advertising address is not in the list and isn't N/A, append it. This avoids duplicates
        if AdvertisingAddress not in StandaloneList and not AdvertisingAddress == 'N/A':
            StandaloneList.append(AdvertisingAddress)
        
        # If the scanning address is not in the list and isn't N/A, append it. This avoids duplicates
        if ScanningAddress not in StandaloneList and not ScanningAddress == 'N/A':
            StandaloneList.append(ScanningAddress)

    G = nx.Graph() # Define networkx graph

    G.add_nodes_from(StandaloneList) # Add nodes from the list of unique devices

    # For every device in the source list
    for i in range(len(SourceList)):
        G.add_edge(SourceList[i], DestinationList[i]) # add an edge between the source and destination

    pos = nx.spring_layout(G, k=0.5, iterations=50) # Set a spring layout of the nodes on the graph

    # For every node, set their position based on the layout above
    for n, p in pos.items():
        G.nodes[n]['pos'] = p
    
    # Configure the edges based on the nodes they connect to and the positions at each end
    edge_x = []
    edge_y = []
    for edge in G.edges(): # For every edge in the networkx graph, create the edge in the plotly graph
        x0, y0 = G.nodes[edge[0]]['pos']
        x1, y1 = G.nodes[edge[1]]['pos']
        edge_x.append(x0)
        edge_x.append(x1)
        edge_x.append(None)
        edge_y.append(y0)
        edge_y.append(y1)
        edge_y.append(None)

    # Create the edges between nodes
    edge_trace = go.Scatter(
        x=edge_x, y=edge_y,
        line=dict(width=0.5, color='#888'),
        hoverinfo='text',
        mode='lines')

    # Create the nodes
    node_x = []
    node_y = []
    for node in G.nodes():
        x, y = G.nodes[node]['pos']
        node_x.append(x)
        node_y.append(y)

    # Add the information and metadata for the nodes
    node_trace = go.Scatter(
        x=node_x, y=node_y,
        mode='markers',
        hoverinfo='text',
        marker=dict(
            showscale=True,
            # colorscale options
            #'Greys' | 'YlGnBu' | 'Greens' | 'YlOrRd' | 'Bluered' | 'RdBu' |
            #'Reds' | 'Blues' | 'Picnic' | 'Rainbow' | 'Portland' | 'Jet' |
            #'Hot' | 'Blackbody' | 'Earth' | 'Electric' | 'Viridis' |
            colorscale='RdBu',
            reversescale=True,
            color=[],
            size=10,
            colorbar=dict(
                thickness=15,
                title='Device Connections',
                xanchor='left',
                titleside='right'
            ),
            line_width=2))

    # Add node adjacencies that also contain the address for the node and company information
    node_adjacencies = []
    node_text = []
    for node, adjacencies in enumerate(G.adjacency()):
        node_adjacencies.append(len(adjacencies[1]))
        node_text.append('Address: ' + adjacencies[0] + '<br>' + str(len(adjacencies[1])) + ' device(s) have sent or recieved packets from this device.' + '<br>' + 'Company Name: ' + str(device_dictionary[adjacencies[0]]))

    node_trace.marker.color = node_adjacencies # Set the colour of the nodes depending on the amount of adjacencies
    node_trace.text = node_text # Set the text for each node

    # Create the figure for the network graph
    fig = go.Figure(data=[edge_trace, node_trace],
                layout=go.Layout(
                    title='Bluetooth Capture Network Graph',
                    titlefont_size=16,
                    showlegend=False,
                    hovermode='closest',
                    margin=dict(b=20,l=5,r=5,t=40),
                    annotations=[ dict(
                        text="Python code: <a href='https://plotly.com/ipython-notebooks/network-graphs/'> https://plotly.com/ipython-notebooks/network-graphs/</a>",
                        showarrow=False,
                        xref="paper", yref="paper",
                        x=0.005, y=-0.002 ) ],
                    xaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
                    yaxis=dict(showgrid=False, zeroline=False, showticklabels=False))
                    )
    fig.show() # Show the figure to the user by opening their default browser

# Declaring empty arrays for various pieces of data
packetlistbox = []
devicelistbox = []
connectionslistbox = []
capture_dict = {}

# Packet list layout
frame_layout_all_packets = [
                  [sg.Listbox(packetlistbox, key='PacketListBox', size=(120, 40), enable_events=True, font="TkFixedFont")]
               ]

# Device list layout
frame_layout_device_list = [
                  [sg.Listbox(devicelistbox, key='DeviceListBox', size=(60, 19))]
               ]

# Connections list layout
frame_layout_connections_list = [
                  [sg.Listbox(connectionslistbox, key='ConnectionsListBox', size=(60, 19))]
               ]

# The layout of the nested side column
side_column_layout = [
    [sg.Frame('Unique Devices', frame_layout_device_list, font='Any 12', title_color='blue')],
    [sg.Frame('Unique Connections', frame_layout_connections_list, font='Any 12', title_color='blue')]
]

# The layout of the main window.
layout = [
    [sg.Text('Bluetooth Sniffing Application'), sg.Button('Live Capture'), sg.Button('Import PCAP'), sg.Button('Export PCAP'), sg.Button('Network Map'), sg.Button('About'), sg.Text('Theme:'), sg.Combo(sg.theme_list(), default_value=theme_name, key='Theme'), sg.Button('Update Theme')],
    [sg.Text('Filter | Packet Type:'), sg.Combo(['Any', 'ADV_IND', 'ADV_DIRECT_IND', 'ADV_NONCONN_IND', 'SCAN_REQ', 'SCAN_RSP', 'CONNECT_REQ', 'ADV_SCAN_IND'], key='TypeFilter', default_value='Any', size=(30, 1)), sg.Text('Address:'), sg.Combo(['Any'], key='AddrFilter', default_value='Any', size=(30, 1)), sg.Button('Apply Filter'), sg.Text('Number of Packets That Match Filter: N/A', key='PacketNumberText')],
    [sg.Frame('Bluetooth Packets', frame_layout_all_packets, font='Any 12', title_color='blue'),
    sg.Column(side_column_layout, justification='r')]
]


def main():
    """ Main function and the entry function for the application """
    
    MainWindow = sg.Window('Bluetooth Sniffing Application', layout, icon='icons/bluetooth.ico') # Main window variable and creation

    if not sys.platform.startswith('win32'): # If the OS running is not Windows
        sg.popup_error('Please run this application on Windows!', icon='icons/bluetooth.ico') # Tell the user that they need to run the app on Windows
        MainWindow.close() # And close out of the app

    PacketDetailsWindowActive = False # Declare that the packet details window is not being shown as default

    createDir('temp') # Run the function to create a directory called temp
    
    capture_dictionary = []

    # The event loop
    while True:
        event1, values1 = MainWindow.read()   # Read the event that happened and the values dictionary
        print(event1, values1) # Print any values or events that get produced
        if event1 == sg.WIN_CLOSED or event1 == 'Exit':     # If user closed window with X or if user clicked "Exit" button then exit
            break
        if event1 == 'About': # If the user clicks on the About button, open the about popup window
            OpenAboutPopup()
        if event1 == 'Update Theme': # If the user clicks on the Update Theme button, update the theme
            file = open("data/theme.conf", "w")
            file.write(values1['Theme'])
            file.close()
            sg.popup('Theme configuration updated, please restart the application.', icon='icons/bluetooth.ico')
        if event1 == 'Live Capture': # If the user clicks on Live Capture, start the live capture function
            LiveCapture()
        if event1 == 'Import PCAP': # If the user clicks on the Import PCAP button, start the ImportPCAP function
            capture_dictionary = ImportPCAP()
        if event1 == 'Export PCAP': # If the user clicks on the Export PCAP button, start the ExportPCAP function
            ExportPCAP()
        if event1 == 'Apply Filter': # If the user clicks on the Apply Filter button, start the ApplyFilter function
            if capture_dictionary != []:
                ApplyFilter(capture_dictionary, values1["TypeFilter"], values1["AddrFilter"])
            else:
                sg.popup_error('No capture loaded, please import a capture or create a new capture.') # Tell the user no capture is found
        if event1 == 'Network Map': # If the user clicks on the Export PCAP button, start the ExportPCAP function
            if capture_dictionary != []:
                NetworkMap(capture_dictionary)
            else:
                sg.popup_error('No capture loaded, please import a capture or create a new capture.') # Tell the user no capture is found
        if event1 == 'PacketListBox' and not PacketDetailsWindowActive: # If the user clicks on any item within the packet list box
            try: # Try the following code
                packet_number = re.search(r'\d+', values1["PacketListBox"][0]).group(0) # Get the packet number from the event
            
                PacketDetailsWindowActive = True # Declare the packet details window is going to open

                PacketDetailsPopup(packet_number, capture_dictionary) # Open the packet details window with the correct info and packet number

                PacketDetailsWindowActive = False # After the window has closed, declare it is no longer active
            except IndexError: # If the user clicks on the empty packet list box
                print('User clicks on the empty packet list.') # Print in the log
                pass # And just ignore

    MainWindow.close()

# if the application/script is run directly from command line, execute the main function
if __name__ == "__main__":
    """ This is executed when run from the command line """

    main()