from cgitb import text
from concurrent.futures import thread
import subprocess
import sys
import os
import signal
from tkinter.messagebox import askquestion, showerror, showinfo, showwarning
import vt
import shutil
import time
import aiohttp
import hashlib
import fileinput
import requests
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
try:
    client = vt.Client("9227fccdca71a13c63c2cffba56b893341dc44b73b6e567aa8197d4d5ca0c0d3")
except:
    client = vt.Client("2ccc95e2724256413dbaa1afcb4eef24f05fb708f3075c76b5fb7fc820465be6")

# Names of software which should be removed
# Add a box which shows the blacklist and allow to add
try:
    with open("blacklistNames.txt", "r") as f:
        blacklistNames = f.read().splitlines()
except FileNotFoundError:
    with open("blacklistNames.txt", "w+") as f:
        blacklistNames = f.read().splitlines()
try:
    with open("blacklistedSoftware.txt", "r") as f:
        blacklisted_software = f.read().splitlines()
except FileNotFoundError:
    with open("blacklistedSoftware.txt", "w+") as f:
        blacklisted_software = f.read().splitlines()
try:
    with open("whitelistedSoftware.txt", "r") as f:
        whitelisted_software = f.read().splitlines()
except FileNotFoundError:
    with open("whitelistedSoftware.txt", "w+") as f:
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

# Button here to run this function
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
                keyloggerDetected += 1
                option = askquestion(root, 'Keylogger detected with the process name of: ' + process.name + '\nPID: ' +
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
    #Remind the process cannot be stopped until it is done scanning file
    showinfo(root, message="Remember this process cannot be stopped!")
    #Make the file input for scan file only to global so the scan file function can get the input
    global fileInputSF
    #Asking for the file that needs to be scanned
    fileInputSF = tk.filedialog.askopenfilename(
        parent=root, title='Choose a file')
    #Start the thread for scan file function
    scanFileThread = Thread(target=scan_file)
    scanFileThread.start()
    #allow the scan file window to be referrenced in scan file function
    global scanningWin
    #code to start scan file window
    scanningWin = Toplevel(root)
    scanningWin.title("Scan File")
    scanningWin.geometry("300x100")
    scanningLabel = Label(scanningWin, text="Scanning in Progress")
    scanningLabel.pack()
    scanningLabel.place(x=100, y=50)

    def disable_event():
        pass
    scanningWin.wm_protocol("WM_DELETE_WINDOW", disable_event)

# Button
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
    #Remind the process cannot be stopped until it is done scanning file
    showinfo(root, message="Remember this process cannot be stopped! Only file signatures that have previously been uploaded will have a result!    ")
    #Make the file input for scanSignature only to global so the scan signature function can get the input
    global fileInputSign
    #Asking for the file that needs to be scanned
    fileInputSign = tk.filedialog.askopenfilename(
        parent=root, title='Choose a file')
    #Start the thread for scan signature function
    scanSignThread = Thread(target=scan_signature)
    scanSignThread.start()
    #allow the scan signature window to be referrenced in scan signature function
    global scanSignWin
    #code to start scan file window
    scanSignWin = Toplevel(root)
    scanSignWin.title("Scan File")
    scanSignWin.geometry("400x100")
    scanSignLabel = Label(scanSignWin, text="Scanning file using file signature in Progress")
    scanSignLabel.pack()
    scanSignLabel.place(x=75, y=50)
    #Prevent the process from stopping
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
                file = client.get_object("/files/{}",hash)
                # Find number of malicious detections
                numberOfMaliciousDetections = file.last_analysis_stats['malicious']
                # Run remove_file function
                remove_file(numberOfMaliciousDetections, fileInputSign)
            except aiohttp.ClientConnectorError:
                print("No internet detected")
        except:
            print("Error! Please use file signatures that have previously been uploaded into the database.")
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

# GUI Auto Update Page


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


def portMonWinFun():
    global portMonWin
    scanPortThread = Thread(target=portMonitor)
    scanPortThread.start()
    portMonWin = Toplevel(root)
    portMonWin.title("Port Monitor")
    portMonWin.geometry("500x300")
    whiteListString = StringVar()
    for software in whitelisted_software:
        whiteList = 'Whitelisted Softwares: ' + str(software)
        whiteListString.set(whiteList)
    blackListString = StringVar()
    for software in blacklisted_software:
        blackList = 'Blacklisted Softwares: ' + str(software)
        blackListString.set(blackList)
    whiteListLabel = Label(
        portMonWin, text="Whitelisted Softwares:", textvariable=whiteListString)
    whiteListLabel.pack()
    whiteListLabel.place(x=0, y=0)
    blackListLabel = Label(portMonWin, textvariable=blackListString)
    blackListLabel.pack()
    blackListLabel.place(x=0, y=100)
    scanningLabel = Label(portMonWin, text="Monitoring Ports...")
    scanningLabel.pack()
    scanningLabel.place(x=200, y=250)
    def disable_event():
        pass
    portMonWin.wm_protocol('WM_DELETE_WINDOW', disable_event)


# GUI Showing blacklisted_software + whitelisted_software and detected ports and software
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
            # delete empty array elements
            my_list = list(filter(None, my_list))
            # get the full IP address with port number from the last element from output
            port_num = my_list[-3]
            # split at the ':' to get port number at last index of array
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
                showwarning(title="Unknown process found!", message="We found a unknown process that is not stated in the whitelisted software.")
                # terminate process if it exists in blacklist
                if process_name in blacklisted_software:
                    p.kill()
                    print(
                        "Blacklist application found running.\nProcess automatically terminated.")
                    showinfo(title="Killing process", message="This process is found in the blacklist. Stopping the process now!")
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
                        is_safe = askquestion('Add to whitelist?','Information on application identified in your system to be potential threat...\nApplication name: ' + process_name + '\nProcess ID (PID): ' + pid + '\nTrying to communicate on port: ' + port_num + '\n\nWould you like to whitelist this application? (No will result in adding this application to blacklist and terminates the process!)')
                        # is_safe = input(
                        #     "Would you like to whitelist this application? (Y/N): ").lower()
                        if is_safe == 'no':
                            print("Terminating process...")
                            p.kill()
                            print("Adding to blacklist...")
                            showinfo('Adding to Blacklist', 'Adding ' + process_name + ' to the blacklist')
                            blacklisted_software.append(process_name)
                            with open("blacklistedSoftware.txt", "a") as f:
                                f.write('%s\n' % process_name)
                            selected = True
                            time = 1
                        elif is_safe == 'yes':
                            print("Resuming process...")
                            if pid != 0:
                                p.resume()
                            print("Adding to whitelist...")
                            whitelisted_software.append(process_name)
                            showinfo('Adding to Whitelist', 'Adding ' + process_name + 'to the whitelist')
                            with open("whitelistedSoftware.txt", "a") as f:
                                f.write('%s\n' % process_name)
                            selected = True
                            time = 1


# Main GUI
root = tk.Tk()
root.title('Anti Keylogger')
root.geometry('700x500')
btnRetrieveProcesses = tk.Button(
    root, text="Retrieve Processes", command=retrieveProcessList).place(x=50, y=450)
btnScanFile = tk.Button(root, text="Scan File",
                        command=scanFileWin).place(x=200, y=450)
btnScanSignature = tk.Button(
    root, text="Scan File Signature", command=scanSignatureWinFun).place(x=300, y=450)
btnProcMon = tk.Button(root, text="Process Monitor",
                       command=procMonWin).place(x=450, y=450)
btnPortMon = Button(root, text="Port Monitor",
                       command=portMonWinFun)
btnPortMon.place(x=600,y=450)
root.mainloop()
