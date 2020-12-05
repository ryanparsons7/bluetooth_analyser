import PySimpleGUI as sg # Importing PySimpleGUI Module for GUI Functionality
import pyshark # Importing pyshark for Wireshark functionality needed for parsing data
import sys
import datetime

sg.theme('BlueMono')	# Theme choice, blue because of Bluetooth!

def ImportPCAP():
    try:
        imported_pcap_location = ''
        imported_pcap_location = sg.popup_get_file('Please enter the file location for the PCAP file or click browse.', file_types=(("PCAPNG Files", "*.pcapng"),("PCAP Files", "*.pcap")))
        print(imported_pcap_location)
        if imported_pcap_location == '':
            sg.popup_error('No PCAP File Selected', title=None)
        elif not imported_pcap_location.endswith(('.pcapng','.pcap')):
            sg.popup_error('The file selected is not a PCAP file.', title=None)
        elif not imported_pcap_location == '':
            print(f'Returned the pcap file location as {imported_pcap_location}')
            return(imported_pcap_location)
    except:
        print("Unexpected error:", sys.exc_info()[0])

def OpenAboutPopup():
    sg.popup(about_popup, title='About', keep_on_top=True)

def CheckForBLE(capture):
    for i in capture:
        try:
            if i.btle:
                return True
        except:
            pass
    return False

def AddPacketsToList(capture):
    for i in capture:
        if i.btle:
            try:
                epoch_time = int(float(i.sniff_timestamp))
                utc_time = datetime.datetime.fromtimestamp(epoch_time).strftime('%Y-%m-%d %H:%M:%S')
                packetlistbox.append(f'Time: {utc_time} UTC,\t Advertising Address: {i.btle.advertising_address},\t\t RSSI: {i.nordic_ble.rssi}dBm, \tChannel: {i.nordic_ble.channel}')
            except Exception as e:
                print(e)


packetlistbox = []
devicelistbox = []
connectionslistbox = []

about_popup = f'Bluetooth Packet Analyser Created by Ryan Parsons\nNapier University, Cybersecurity and Forensics Honours Project'

frame_layout_all_packets = [
                  [sg.Listbox(packetlistbox, key='PacketList', size=(120, 60))]
               ]

frame_layout_device_list = [
                  [sg.Listbox(devicelistbox, size=(60, 29))]
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
        capture = pyshark.LiveCapture(interface='nRF Sniffer for Bluetooth LE COM4')
        capture.sniff(timeout=50)
        print(capture)
    if event == 'Export PCAP':
        if cap == '':
            sg.popup('No Live Capture Has Been Completed to Export, Please Run a Live Capture', title='No Capture', keep_on_top=True)
    if event == 'Import PCAP':
        pcap_file_location = ImportPCAP() # Get the file location that the user selects
        if not pcap_file_location =='':
            print(pcap_file_location)
            cap = pyshark.FileCapture(pcap_file_location) # Get the capture from the file into a variable
            if CheckForBLE(cap):
                print(f'Bluetooth packets found in {pcap_file_location}, continuing') # File contains Bluetooth packets, will now continue to parse
            else:
                sg.popup_error(f'No Bluetooth LE packets found in {pcap_file_location}, please import another file.', title=None) # File doesn't contain Bluetooth LE packets, informs user to use another file.
            packet1 = cap[0]
            AddPacketsToList(cap)
            window.FindElement('PacketList').Update(values=packetlistbox)

window.close()