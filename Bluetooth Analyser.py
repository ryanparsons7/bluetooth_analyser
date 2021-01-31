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
from collections import Counter
from plotly.offline import download_plotlyjs, init_notebook_mode, iplot
import plotly.graph_objs as go

sg.theme('BlueMono')	# Theme choice, blue because of Bluetooth!

def readKeyValues(inputCsvFile):
    """ A function that takes in a csv file and creates key value pair dictionary from the first and second columns. Code from https://ayeshalshukri.co.uk/category/dev/python-script-to-extract-key-value-pairs-from-csv-file/ """
	#input file reader
    infile = open(inputCsvFile, "r", encoding="utf8") # Open the spreadsheet file in read only mode and with encoding of utf8
    read = csv.reader(infile) # Read file variable
	
    returnDictionary = {} # Empty dictionary to store future data
    #for each row
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

    if  pcap_file_location == ():
        pcap_file_location = GetFileLocation() # Get the file location that the user selects
    else:
        pcap_file_location = pcap_file_location[0]
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

def PacketDetailsPopup(packet_number, capture_dict_array):
    """ Takes in a packet number and capure information in the form of a array of dictionaries when the user clicks on a specific packet.
        This will then create a window containing the information regarding that packet """

    packet_number = int(packet_number) - 1

    if capture_dict_array[packet_number].get("Advertising Data") == 'N/A':
        advertising_data_string = 'N/A'
    else:
        advertising_data_string = 'Click for more info'

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
            if packet_detail.startswith('Advertising Data:'):
                if not packet_detail.startswith('Advertising Data: N/A'):
                    ExpandedAdvertisingDataPopup(capture_dict_array[packet_number].get("Advertising Data"))
            else:
                ExpandedPacketDetails(packet_detail)

def ExpandedAdvertisingDataPopup(advert_data):
    """ WRITE UP """

    for idx, entry in enumerate(advert_data.entry):
        print(f'Entry {idx + 1}:\n{entry}')
    
    layout3 = [[sg.Listbox(str(advert_data), size=(60, 29), enable_events=True, font="TkFixedFont", key='PacketDetails')],       # note must create a layout from scratch every time. No reuse
                [sg.Button('Exit')]]

    AdvertisingDataDetailsWindow = sg.Window('Packet Details', layout3, modal=True, icon='icons/bluetooth.ico')
    while True:
        event3, values3 = AdvertisingDataDetailsWindow.read()
        if event3 == sg.WIN_CLOSED or event3 == 'Exit':
            AdvertisingDataDetailsWindow.close()
            break

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

    AuxList = []
    for packet in capture_dict:
        AdvertisingAddress = packet.get("Advertising Address")
        ScanningAddress = packet.get("Scanning Address")
        if AdvertisingAddress not in AuxList and not AdvertisingAddress == 'N/A':
            AuxList.append(AdvertisingAddress)
        if ScanningAddress not in AuxList and not ScanningAddress == 'N/A':
            AuxList.append(ScanningAddress)
    MainWindow.FindElement('DeviceListBox').Update(values=AuxList)
    AddrFilterList = AuxList
    AddrFilterList.append('Any')
    MainWindow.FindElement('AddrFilter').Update(values=AddrFilterList)

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
        
        if packet_number == 246:
            print(packet)

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
    return parsed_dict

def LiveCapture():
    """ When the function is ran, a window is displayed to the user that allows them to configure live capture parameters and start a live capture """
    
    live_capture_layout = [
            [sg.Text('Please select your parameters and click the Capture button to start')],
            [sg.Text('Capture time in seconds'), sg.InputText()],
            [sg.Button('Capture'), sg.Button('Exit')]
    ]

    CaptureWindow = sg.Window('Live Capture', live_capture_layout, modal=True, icon='icons/bluetooth.ico')
    while True:
        event2, values2 = CaptureWindow.read()
        if event2 == sg.WIN_CLOSED or event2 == 'Exit':
            CaptureWindow.close()
            break
        if event2 == 'Capture':
            if not values2[0] == '' and values2[0].isnumeric():
                current_folder = pathlib.Path(__file__).parent.absolute()
                timer = float(values2[0])
                print('Windows OS Being Used')
                arguments = f'-i COM3 -k -w "{current_folder}\\temp\\temp_capture.pcapng" -a duration:{timer}'
                install_location = 'C:\\Program Files\\Wireshark\\Wireshark.exe'
                if not os.path.isfile(install_location):
                    sg.popup_error('The Wireshark Executable is not located at the default location. Please navigate and select the "Wireshark.exe".', icon='icons/bluetooth.ico')
                    install_location = sg.popup_get_file('Choose Wireshark.exe', icon='icons/bluetooth.ico')
                ext_cap_folder = install_location.removesuffix('Wireshark.exe') + 'extcap'
                if not os.path.isdir(f'{ext_cap_folder}\\SnifferAPI'):
                    sg.popup_error('The Sniffer API is not installed correctly, please follow the installation guide.".', icon='icons/bluetooth.ico')
                    CaptureWindow.close()
                    break
                wireshark_proc = subprocess.Popen(f'{install_location} {arguments}')
                time.sleep(timer + 10)
                wireshark_proc.kill()
                CaptureWindow.close()
                temp_file = f'{current_folder}\\temp\\temp_capture.pcapng'
                if not os.path.isfile(temp_file):
                    sg.popup_error('The capture file from Wireshark was not created, this may be due to the sniffer not being connected properly. Please read any error messages that appear in the Wireshark application when it opens.', icon='icons/bluetooth.ico')
                    break
                ImportPCAP(temp_file)
                break
            else:
                sg.popup_error('Please enter a number.', icon='icons/bluetooth.ico')

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
    new_capture = []
    for packet in capture_dict:
        match = True
        if packet['Packet Type'] != type_filter and type_filter != 'Any':
            match = False
        if (packet['Advertising Address'] != address_filter and packet['Scanning Address'] != address_filter) and address_filter != 'Any':
            match = False
        if match == True:
            new_capture.append(packet)
    
    if new_capture != None: # Check if the returned capture is not empty, if it has data assigned, continue with the processes.
        PopulatePacketList(new_capture) # Populate packet list
    

def NetworkMap(capture_dict):
    """ Creates a map of the network from the capture file """
    SourceList = []
    DestinationList = []
    for packet in capture_dict:
        AdvertisingAddress = packet.get("Advertising Address")
        ScanningAddress = packet.get("Scanning Address")
        if AdvertisingAddress != 'N/A' and ScanningAddress != 'N/A':
            if packet.get("Packet Type") == 'SCAN_REQ':
                source = ScanningAddress
                destination = AdvertisingAddress
            else:
                destination = ScanningAddress
                source = AdvertisingAddress
            SourceList.append(source)
            DestinationList.append(destination)

    G = nx.Graph()

    for i in range(len(SourceList)):
        G.add_edge(SourceList[i], DestinationList[i])

    pos = nx.spring_layout(G, k=0.5, iterations=50)
    for n, p in pos.items():
        G.nodes[n]['pos'] = p
    
    edge_x = []
    edge_y = []
    for edge in G.edges():
        x0, y0 = G.nodes[edge[0]]['pos']
        x1, y1 = G.nodes[edge[1]]['pos']
        edge_x.append(x0)
        edge_x.append(x1)
        edge_x.append(None)
        edge_y.append(y0)
        edge_y.append(y1)
        edge_y.append(None)

    edge_trace = go.Scatter(
        x=edge_x, y=edge_y,
        line=dict(width=0.5, color='#888'),
        hoverinfo='none',
        mode='lines')

    node_x = []
    node_y = []
    for node in G.nodes():
        x, y = G.nodes[node]['pos']
        node_x.append(x)
        node_y.append(y)

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

    node_adjacencies = []
    node_text = []
    for node, adjacencies in enumerate(G.adjacency()):
        node_adjacencies.append(len(adjacencies[1]))
        node_text.append(adjacencies[0] + '<br>' + str(len(adjacencies[1])) + ' device(s) have sent or recieved packets from this device.')

    node_trace.marker.color = node_adjacencies
    node_trace.text = node_text

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
    fig.show()

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
    [sg.Text('Bluetooth Sniffing Application'), sg.Button('Live Capture'), sg.Button('Import PCAP'), sg.Button('Export PCAP'), sg.Button('Network Map'), sg.Button('About')],
    [sg.Text('Filter | Packet Type:'), sg.Combo(['Any', 'ADV_IND', 'ADV_DIRECT_IND', 'ADV_NONCONN_IND', 'SCAN_REQ', 'SCAN_RSP', 'CONNECT_REQ', 'ADV_SCAN_IND'], key='TypeFilter', default_value='Any', size=(30, 1)), sg.Text('Address:'), sg.Combo(['Any'], key='AddrFilter', default_value='Any', size=(30, 1)), sg.Button('Apply Filter')],
    [sg.Frame('Bluetooth Packets', frame_layout_all_packets, font='Any 12', title_color='blue'),
    sg.Column(side_column_layout, justification='r')]
]

MainWindow = sg.Window('Bluetooth Sniffing Application', layout, icon='icons/bluetooth.ico') # Main window variable and creation

def main():
    """ Main function and the entry function for the application """

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


if __name__ == "__main__":
    """ This is executed when run from the command line """
    main()