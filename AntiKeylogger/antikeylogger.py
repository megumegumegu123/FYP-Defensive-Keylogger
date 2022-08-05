from cgitb import text
from concurrent.futures import thread
import subprocess
import os
from tkinter.messagebox import askquestion, showerror, showinfo, showwarning
from wsgiref.simple_server import software_version
import vt
import aiohttp
import hashlib
import argparse
import getopt
import psutil
import tkinter as tk
from tkinter import *
from tkinter import filedialog
from tkinter import Grid
from os.path import exists
from fileinput import filename
from subprocess import Popen, PIPE
from subprocess import call
from prettytable import PrettyTable
from datetime import datetime
from win32com.client import GetObject
from sys import stdout
from threading import *
# Virustotal API key    
client = vt.Client("9227fccdca71a13c63c2cffba56b893341dc44b73b6e567aa8197d4d5ca0c0d3")
#client = vt.Client("2ccc95e2724256413dbaa1afcb4eef24f05fb708f3075c76b5fb7fc820465be6")

# get current working directory
cwd = os.getcwd()
print(cwd)
try:
    with open(cwd + "\\textfiles\\blacklistNames.txt", "r") as f:
        blacklistNames = f.read().splitlines()
except FileNotFoundError:
    with open(cwd + "\\textfiles\\blacklistNames.txt", "w+") as f:
        blacklistNames = f.read().splitlines()
try:
    with open(cwd + "\\textfiles\\blacklistedSoftware.txt", "r") as f:
        blacklisted_software = f.read().splitlines()
except FileNotFoundError:
    with open(cwd + "\\textfiles\\blacklistedSoftware.txt", "w+") as f:
        blacklisted_software = f.read().splitlines()
try:
    with open(cwd + "\\textfiles\\whitelistedSoftware.txt", "r") as f:
        whitelisted_software = f.read().splitlines()
except FileNotFoundError:
    with open(cwd + "\\textfiles\\whitelistedSoftware.txt", "w+") as f:
        whitelisted_software = f.read().splitlines()

# Process class to retrieve process name and process PID
class Process(object):
    def __init__(self, process_info):
        self.name = process_info[0]
        self.pid = process_info[1]

# Function to remove keylogger
def removeKeylogger(pid):
    stdout.write("Killing process")
    # 9 because it represents termination https://en.wikipedia.org/wiki/Signal_(IPC)
    os.kill(int(pid), 9)


# Function to retrieve processes
def retrieveProcessList():
    processList = []
    keyloggerDetected = 0
    # Function to use cmd and use "tasklist" to list all running processes
    processes = Popen(['tasklist'], shell=False, stdout=PIPE)
    # Remove unwanted lines
    processes.stdout.readline()
    processes.stdout.readline()
    processes.stdout.readline()

    # Loop to look at all processes individually
    for line in processes.stdout:
        # Put processes into an array
        processInfo = line.decode('utf-8').replace("b'", "").split()
        # Debug
        # print(processInfo)
        # Append process into processList array if the list has a length of 6(Normal)
        if len(processInfo) == 6:
            processList.append(Process(processInfo))

    # Loop through processList to look at each process
    for process in processList:
        # Loop through blacklisted terms and see if it matches the process
        for blacklisted in blacklistNames:
            # Upper so that processes with capital and small letters are matched evenly
            if(process.name.upper().find(blacklisted.upper()) > -1):
                # So exe doesnt kill itself
                if(process.name.upper() == "DARK.EXE"):
                    keyloggerDetected = 0
                else:
                    keyloggerDetected += 1
                    option = askquestion('Select your option', 'Keylogger detected with the process name of: ' + process.name + '\nPID: ' +
                                        process.pid + '\nDo you want to delete the file?\n(NO will result in ending the process.)')
                    # print('Keylogger detected with the process name of: ' + process.name + '\nPID: ' + process.pid)
                    # option = input("Delete File? (Y/N)")
                    if (option == "yes"):
                        # Find file path
                        print(  
                            f'The location of the file is: {Process_path(int(process.pid))}')
                        # Delete file at that file path
                        try:
                            os.remove(Process_path(int(process.pid)))
                            showinfo(root, 'Deleted ' + process.name)
                        except FileNotFoundError:
                            print("Error finding file")
                            showerror(
                                root, 'There is some error deleting the file, recommending manual deletion after ending the process.')
                        keyloggerDetected += 1
                    elif (option == "no"):
                        # Remove process
                        removeKeylogger(process.pid)
                        showinfo(root, 'Keylogger killed')
                        keyloggerDetected += 1
    if keyloggerDetected == 0:
        print("No keylogger was detected.")
        showinfo(root, message="No keylogger was detected.")

# Retrieve process path
def Process_path(pid):
    WMI = GetObject('winmgmts:')
    processes = WMI.InstancesOf('Win32_Process')
    for p in processes:
        if p.Properties_("ProcessID").Value == pid:
            return p.Properties_[7].Value
    return "no such process"


def scanFileWin():
    # Remind the process cannot be stopped until it is done scanning file
    showinfo(root, message="Remember this process cannot be stopped! No access to other function while scanning.")
    # Make the file input for scan file only to global so the scan file function can get the input
    global fileInputSF
    # Asking for the file that needs to be scanned
    fileInputSF = tk.filedialog.askopenfilename(
        parent=root, title='Choose a file')
    # Start the thread for scan file function
    scanFileThread = Thread(target=scan_file)
    scanFileThread.start()
    # allow the scan file window to be referrenced in scan file function
    global scanningWin
    # code to start scan file window
    scanningWin = Toplevel(root)
    scanningWin.title("Scan File")
    scanningWin.geometry("300x100")
    scanningLabel = Label(scanningWin, text="Scanning in Progress")
    scanningLabel.pack()
    scanningWin.resizable(False,False)
    scanningLabel.place(x=100, y=50)
    scanningWin.grab_set()

    def disable_event():
        pass
    scanningWin.wm_protocol("WM_DELETE_WINDOW", disable_event)


# Scan file if it is malicious or not
def scan_file():
    # try except to catch FileNotFoundError
    try:
        with open(fileInputSF, 'rb') as f:
            # try except to catch no internet connection
            try:
                # Scan file
                analysis = client.scan_file(f)
                print("Scanning...")
                # Keep looping until analysis is completed
                while True:
                    analysis = client.get_object("/analyses/{}", analysis.id)
                    print(analysis.status)
                    # End loop when analysis is completed
                    if analysis.status == "completed":
                        scanningWin.destroy()
                        break
                # Find number of malicious detections
                numberOfMaliciousDetections = analysis.stats['malicious']
                # Run remove_file function
                remove_file(numberOfMaliciousDetections, fileInputSF)
            except aiohttp.ClientConnectorError:
                print("No internet detected")
                showerror(
            title="Error!",
            message="No internet is detected"
        )
    except FileNotFoundError:
        print("Please input a valid file")
        showerror(
            title="Error!",
            message="Please input a valid file"
        )
        scanningWin.destroy()
        pass

# Function to convert file to SHA1
def convertToHash(file):
    # make a hash object
    h = hashlib.sha1()
    # open file for reading in binary mode
    with open(file, 'rb') as f:
        # loop till the end of the file
        chunk = 0
        while chunk != b'':
            # read only 1024 bytes at a time
            chunk = f.read(1024)
            h.update(chunk)
    # return the hex representation of digest
    return h.hexdigest()

# Function to scan digital signature of file


def scanSignatureWinFun():
    # Remind the process cannot be stopped until it is done scanning file
    showinfo(root, message="Remember this process cannot be stopped! Only file signatures that have previously been uploaded will have a result! No access to other function while scanning.")
    # Make the file input for scanSignature only to global so the scan signature function can get the input
    global fileInputSign
    # Asking for the file that needs to be scanned
    fileInputSign = tk.filedialog.askopenfilename(
        parent=root, title='Choose a file')
    # Start the thread for scan signature function
    scanSignThread = Thread(target=scan_signature)
    scanSignThread.start()
    # allow the scan signature window to be referrenced in scan signature function
    global scanSignWin
    # code to start scan file window
    scanSignWin = Toplevel(root)
    scanSignWin.title("Scan File")
    scanSignWin.geometry("400x100")
    scanSignWin.resizable(False,False)
    scanSignLabel = Label(
        scanSignWin, text="Scanning file using file signature in Progress")
    scanSignLabel.pack()
    scanSignLabel.place(x=75, y=50)
    scanSignWin.grab_set()
    # Prevent the process from stopping

    def disable_event():
        pass
    scanSignWin.wm_protocol("WM_DELETE_WINDOW", disable_event)


def scan_signature():
    # Ask for filename
    try:
        hash = convertToHash(fileInputSign)
        # Debug
        # print(hash)
        # Send request to API
        print(hash)
        # try except to catch file not found
        try:
            # try except to catch no interenet detected
            try:
                file = client.get_object("/files/{}", hash)
                # Find number of malicious detections
                numberOfMaliciousDetections = file.last_analysis_stats['malicious']
                # Run remove_file function
                scanSignWin.destroy()
                remove_file(numberOfMaliciousDetections, fileInputSign)
            except aiohttp.ClientConnectorError:
                print("No internet detected")
                showerror(
            title="Error!",
            message="No internet is detected"
        )
        except:
            print(
                "Error! Please use file signatures that have previously been uploaded into the database.")
            showerror(
                title="Error!", message="Error! Please use file signatures that have previously been uploaded into the database.")
            scanSignWin.destroy()
            return
    except FileNotFoundError:
        showerror(
            title="Error!",
            message="Please input a valid file"
        )
        scanSignWin.destroy()
        pass

# Function to delete file


def remove_file(num, fileInput):
    # If >0 then remove file
    if(num) > 0:
        os.remove(fileInput)
        print("File has been deleted! :D")
        showinfo(title="Results",
                 message="File is malicious and has been removed!")
        client.close()
    else:
        print("File is not malicious! :D")
        showinfo(title="Results", message="File is not malicious.")
        client.close()

def procMon():
    # https://www.geeksforgeeks.org/how-to-make-a-process-monitor-in-python/
    # Run an infinite loop to constantly monitor the system
    while True:
        # Creating a table for the entire thing
        endTable = ""
        # Clear the screen using a bash command
        os.system('cls')
        endTable += "==============================        Process Monitor\
        ======================================\n"

        # Fetch the Network information
        endTable += "----Networks----\n"
        network_table = PrettyTable(['Network', 'Status', 'Speed'])
        for key in psutil.net_if_stats().keys():
            name = key
            up = "Up" if psutil.net_if_stats()[key].isup else "Down"
            speed = psutil.net_if_stats()[key].speed
            network_table.add_row([name, up, speed])
        endTable += str(network_table) + "\n"

        # Fetch the memory information
        endTable += "----Memory----\n"
        memory_table = PrettyTable(["Total", "Used",
                                    "Available", "Percentage"])
        vm = psutil.virtual_memory()
        memory_table.add_row([
            vm.total,
            vm.used,
            vm.available,
            vm.percent
        ])
        endTable += str(memory_table) + "\n"

        # Fetch the last 10 processes from available processes
        endTable += "----Processes----\n"
        process_table = PrettyTable(['PID', 'PNAME', 'STATUS',
                                     'CPU', 'NUM THREADS'])
        for process in psutil.pids()[-10:]:
            # While fetching the processes, some of the subprocesses may exit
            # Hence we need to put this code in try-except block
            try:
                p = psutil.Process(process)
                process_table.add_row([
                    str(process),
                    p.name(),
                    p.status(),
                    str(p.cpu_percent())+"%",
                    p.num_threads()
                ])
            except Exception as e:
                pass

        endTable += str(process_table) + "\n"
        return endTable

# Creating the Window to show the table in the GUI


def procMonWin():
    # Setting the variable to get value from function procMon
    table = procMon()
    # To allow the table to seen in the console
    print(table)
    # Creating the new window
    procMonWin = Toplevel(root)
    procMonWin.title("Process Monitor")
    procMonWin.geometry('700x600')
    procMonWin.resizable(False,False)
    # Changing the table var to a var that tkinter accpet
    procMonTableString = StringVar()
    procMonTableString.set(table)
    # Adding the table to the window
    procMonTable = Label(procMonWin, textvariable=procMonTableString)
    procMonTable.pack()
    procMonTable.place(x=0, y=0)
    # Preventing interaction with the Main GUI when procMon is running
    procMonWin.grab_set()
    # Function to close the procMon Window

    def exitWin():
        procMonWin.destroy()

    # Function to update the table on the procMon Winodw
    def updateTable():
        table = procMon()
        procMonTableString.set(table)
        print(table)
        print("Update")
        procMonTable['textvariable'] = procMonTableString
        procMonWin.after(1000, updateTable)
    # A button to exit the window
    exitBtn = Button(procMonWin, text="Exit", command=exitWin)
    exitBtn.pack()
    exitBtn.place(x=450, y=550)
    # Start updating the table
    updateTable()

# Updates both whitelist and blacklist in portMon Window
def updateList():
    whiteListString = StringVar()
    blackListString = StringVar()
    whiteListString.set(whitelisted_software)
    blackListString.set(blacklisted_software)
    blacklistListbox['listvariable'] = blackListString
    whitelistListbox['listvariable'] = whiteListString

# add new process to blacklist
def addProBlackL():
    # setting filetypes
    filetypes = (('exe files', '*.exe'), ('All files', '*.*'))
    fileNameRaw = tk.filedialog.askopenfilename(
        title='Select a file', initialdir='/', filetypes=filetypes)
    print(len(fileNameRaw))
    if fileNameRaw == '' or len(fileNameRaw) == 0:
        return None
    fileNameList = fileNameRaw.split('/')
    fileName = fileNameList[-1]
    if(fileName in blacklisted_software):
        showinfo(title='Exit', message=fileName + ' is already in the blacklist.')
        return None
    elif (fileName in whitelisted_software):
        showinfo(title='Exit', message=fileName + ' is already in the whitelist.')
        return None
    else:
        option = askquestion(
            'Selected file', 'Are you sure you want to add ' + fileName + ' to your blacklist?')
        if (option == 'yes'):
            showinfo('Adding to Blacklist', 'Adding ' +
                    fileName + ' to the blacklist')
            blacklisted_software.append(fileName)
            with open(cwd + "\\textfiles\\blacklistedSoftware.txt", "a") as f:
                f.write('%s\n' % fileName)
            updateList()
        else:
            showinfo(title='Exit', message=fileName + ' is not added.')
            return None

# add new process to whitelist
def addProWhiteL():
    # setting filetypes
    filetypes = (('exe files', '*.exe'), ('All files', '*.*'))
    fileNameRaw = tk.filedialog.askopenfilename(
        title='Select a file', initialdir='/', filetypes=filetypes)
    print(len(fileNameRaw))
    if fileNameRaw == '' or len(fileNameRaw) == 0:
        return None
    fileNameList = fileNameRaw.split('/')
    fileName = fileNameList[-1]
    if(fileName in blacklisted_software):
        showinfo(title='Exit', message=fileName + ' is already in the blacklist.')
        return None
    elif (fileName in whitelisted_software):
        showinfo(title='Exit', message=fileName + ' is already in the whitelist.')
        return None
    else:
        option = askquestion(
            'Selected file', 'Are you sure you want to add ' + fileName + ' to your whitelist?')
        if (option == 'yes'):
            showinfo('Adding to whitelist', 'Adding ' +
                    fileName + ' to the whitelist')
            whitelisted_software.append(fileName)
            with open(cwd + "\\textfiles\\whitelistedSoftware.txt", "a") as f:
                f.write('%s\n' % fileName)
            updateList()
        else:
            showinfo(title='Exit', message=fileName + ' is not added.')
            return None

# portMon window function
def portMonWinFun():
    def deletewhitelistItem():
        #getting the selection in the whitelist listbox
        item = whitelistListbox.curselection()
        #error handling if nothing is selected and delete button is pressed
        if item == ():
            return None
        itemName = whitelistListbox.get(item)        
        whitelisted_software.remove(itemName)
        whitelistListbox.delete(item)
        # read file
        with open(cwd + "\\textfiles\\whitelistedSoftware.txt", "r") as f:
            softwares = f.readlines()
        # write file
        with open(cwd + "\\textfiles\\whitelistedSoftware.txt", "w") as f:
            for software in softwares:
                if software.strip() != itemName:
                    f.write(software)
            f.truncate

    def deleteblacklistItem():
        #getting the selection in the blacklist listbox
        item = blacklistListbox.curselection()
        #error handling if nothing is selected and delete button is pressed
        if item == ():
            return None
        #get the item name in the list box so can be removed from txt file
        itemName = blacklistListbox.get(item)
        blacklisted_software.remove(itemName)
        #delete the item in the listbox
        blacklistListbox.delete(item)
        # read file
        with open(cwd + "\\textfiles\\blacklistedSoftware.txt", "r") as f:
            softwares = f.readlines()
        # write file
        with open(cwd + "\\textfiles\\blacklistedSoftware.txt", "w") as f:
            for software in softwares:
                if software.strip() != itemName:
                    f.write(software)
            f.truncate

    # Need to thread the portMonitor function as tkinter need its own thread
    scanPortThread = Thread(target=portMonitor)
    scanPortThread.start()   
    # Creating portMon Window
    portMonWin = Toplevel(root)
    portMonWin.title("Port Monitor")
    portMonWin.geometry("500x300")
    portMonWin.resizable(False,False)
    # initialising the variable for tkinter to accept them
    whitelistString = StringVar()
    blacklistString = StringVar()
    # setting the variable so tkinter can accept them
    whitelistString.set(whitelisted_software)
    blacklistString.set(blacklisted_software)
    # Labeling the whitelist listbox
    whitelistLabel = Label(portMonWin, text='Whitelisted Softwares')
    whitelistLabel.pack()
    whitelistLabel.place(x=0, y=0)
    # allow constant update using another function thus need to global it
    global whitelistListbox
    # Allow scrollbar to fit in nicely with listbox using frame
    whitelistFrame = Frame(portMonWin)
    whitelistFrame.pack()
    whitelistFrame.place(x=0, y=30)
    # Creating the whitelist Listbox
    whitelistListbox = Listbox(
        whitelistFrame, listvariable=whitelistString, height=5, width=35)
    whitelistListbox.pack(side='left', fill='y')
    # add new entry to whitelist with button
    addWhitelistBtn = Button(portMonWin, text='Add...', command=addProWhiteL)
    addWhitelistBtn.pack()
    addWhitelistBtn.place(x=90, y=125)
    # delete whitelist items
    deleteWhiteLBtn = Button(portMonWin, text='Delete',
                             command=deletewhitelistItem)
    deleteWhiteLBtn.pack()
    deleteWhiteLBtn.place(x=150, y=125)
    # Scroll bar for whitelist
    whitelistScroll = Scrollbar(
        whitelistFrame,
        orient='vertical',
        command=whitelistListbox.yview
    )
    whitelistListbox['yscrollcommand'] = whitelistScroll.set
    whitelistScroll.pack(side='right', fill='y')
    # Labeling the blacklist Listbox
    blacklistLabel = Label(portMonWin, text='Blacklisted Softwares')
    blacklistLabel.pack()
    blacklistLabel.place(x=250, y=0)
    # allow constant update using another function thus need to global it
    global blacklistListbox
    # Allow scrollbar to fit in nicely with listbox using frame
    blacklistFrame = Frame(portMonWin)
    blacklistFrame.pack()
    blacklistFrame.place(x=250, y=30)
    # Creating the blacklist Listbox
    blacklistListbox = Listbox(
        blacklistFrame, listvariable=blacklistString, height=5, width=35)
    blacklistListbox.pack(side='left', fill='y')
    # button to allow add a new process to the blacklist
    addBlacklistBtn = Button(portMonWin, text='Add...', command=addProBlackL)
    addBlacklistBtn.pack()
    addBlacklistBtn.place(x=340, y=125)
    # delete blacklist item
    deleteBlackLBtn = Button(portMonWin, text='Delete',
                             command=deleteblacklistItem)
    deleteBlackLBtn.pack()
    deleteBlackLBtn.place(x=400, y=125)
    # scroll bar for blacklist listbox
    blacklistScroll = Scrollbar(
        blacklistFrame,
        orient='vertical',
        command=blacklistListbox.yview
    )
    blacklistListbox['yscrollcommand'] = blacklistScroll.set
    blacklistScroll.pack(side='right', fill='y')
    # Reminding the user it is monitoring
    scanningLabel = Label(portMonWin, text="Monitoring Ports...")
    scanningLabel.pack()
    scanningLabel.place(x=200, y=250)
    # disable the ability to close the portMon window so it can run constantly

    def disable_event():
        pass
    portMonWin.wm_protocol('WM_DELETE_WINDOW', disable_event)

# Monitors SMTP ports for any activities
def portMonitor():
    btnPortMon['state'] = DISABLED
    time = 1
    while True:
        if time == 1:
            print("\nMonitoring in progress...")

        proc = subprocess.Popen('netstat -ano -p tcp | findStr "587 465 2525"', shell=True, stdin=subprocess.PIPE,
                                stdout=subprocess.PIPE)
        out, err = proc.communicate()
        output = out.decode()
        my_list = output.split(" ")
        # PID will be the last number once split
        pid = my_list[-1]
        # obtain output from checking the application name of PID
        cmd_output = subprocess.getoutput(f'tasklist /fi "pid eq {pid}"')
        # to make finding process name easier, split cmd_output
        process_name = cmd_output.split()
        time += 1
        if "ESTABLISHED" in output:
            # delete empty list elements
            my_list = list(filter(None, my_list))
            # get the full IP address with port number from the last element from output
            port_num = my_list[-3]
            # split at the ':' to get port number at last index of list
            get_port = port_num.split(":")
            port = get_port[-1]

            # debugging
            # print(my_list)
            # print(pid)
            # print(process_name)

            # 13th element in process_name will always be application name
            process_name = process_name[13]
            p = psutil.Process(int(pid))
            if process_name not in whitelisted_software:
                print("KEYLOGGER DETECTED!")
                showwarning(title="Unknown process found!",
                            message="We found a unknown process that is not stated in the whitelisted software.")
                # terminate process if it exists in blacklist
                if process_name in blacklisted_software:
                    p.kill()
                    print(
                        "Blacklist application found running.\nProcess automatically terminated.")
                    showinfo(title="Killing process",
                             message="This process is found in the blacklist. Stopping the process now!")
                    time = 1
                # if process is not in whitelist, check if it should be
                elif process_name not in whitelisted_software:
                    print("Pausing application...\n")
                    if pid != 0:
                        p.suspend()
                    print(
                        "Information on application identified in your system to be potential threat...")
                    print(f'Application name: {process_name}\n'
                          f'Process ID (PID): {pid}'
                          f'Trying to communicate on port {port}\n')
                    selected = False
                    while not selected:
                        is_safe = askquestion('Add to whitelist?', 'Information on application identified in your system to be potential threat...\nApplication name: ' + process_name + '\nProcess ID (PID): ' + pid +
                                              '\nTrying to communicate on port: ' + port_num + '\n\nWould you like to whitelist this application? (No will result in adding this application to blacklist and terminates the process!)')
                        # is_safe = input(
                        #     "Would you like to whitelist this application? (Y/N): ").lower()
                        if is_safe == 'no':
                            print("Terminating process...")
                            p.kill()
                            print("Adding to blacklist...")
                            showinfo('Adding to Blacklist', 'Adding ' +
                                     process_name + ' to the blacklist')
                            blacklisted_software.append(process_name)
                            with open(cwd + "\\textfiles\\blacklistedSoftware.txt", "a") as f:
                                f.write('%s\n' % process_name)
                            updateList()
                            selected = True
                            time = 1
                        elif is_safe == 'yes':
                            print("Resuming process...")
                            if pid != 0:
                                p.resume()
                            print("Adding to whitelist...")
                            whitelisted_software.append(process_name)
                            showinfo('Adding to Whitelist', 'Adding ' +
                                     process_name + ' to the whitelist')
                            with open(cwd + "\\textfiles\\whitelistedSoftware.txt", "a") as f:
                                f.write('%s\n' % process_name)
                            updateList()
                            selected = True
                            time = 1


# Main GUI
root = tk.Tk()
root.title('Anti Keylogger')
root.geometry('700x100')
btnRetrieveProcesses = tk.Button(
    root, text="Retrieve Processes", command=retrieveProcessList).place(x=50, y=50)
btnScanFile = tk.Button(root, text="Scan File",
                        command=scanFileWin).place(x=200, y=50)
btnScanSignature = tk.Button(
    root, text="Scan File Signature", command=scanSignatureWinFun).place(x=300, y=50)
btnProcMon = tk.Button(root, text="Process Monitor",
                       command=procMonWin).place(x=450, y=50)
btnPortMon = Button(root, text="Port Monitor",
                    command=portMonWinFun)
def exitCommand():
    os._exit(0)
# exitBtn = Button(root, text = "Exit", command =exitCommand).place(x=1,y=1)
def disable_event():
    pass
root.wm_protocol('WM_DELETE_WINDOW', exitCommand)
btnPortMon.place(x=600, y=50)
root.resizable(False,False)#make sure the root window is not resizable
root.mainloop()