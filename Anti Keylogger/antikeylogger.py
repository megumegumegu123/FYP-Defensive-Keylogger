import subprocess
import sys
import os
import signal
import vt
import shutil
import time
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
#Virustotal API key (Stay Hidden)
#client = vt.Client("9227fccdca71a13c63c2cffba56b893341dc44b73b6e567aa8197d4d5ca0c0d3")
client = vt.Client("2ccc95e2724256413dbaa1afcb4eef24f05fb708f3075c76b5fb7fc820465be6")

#Names of software which should be removed
###Add a box which shows the blacklist and allow to add
blacklistNames = ['keylogger']
blacklisted_software = []
whitelisted_software = []

#Menu
def option():
    choice = input("1. Kill process || 2. Scan file signature || 3. Scan file digital signature || 4. Process Monitor || 5. Monitor SMTP Ports ")
    choice = int(choice)
    if(choice == 1):
        retrieveProcessList()
    if(choice == 2):
        scan_file()
    if(choice == 3):
        scan_signature()
    if(choice == 4):
        procMon()
    if(choice == 5):
        portMonitor()

#Process class to retrieve process name and process PID
class Process(object):
    def __init__(self, process_info):
        self.name = process_info[0]
        self.pid = process_info[1]

#Function to remove keylogger
def removeKeylogger(pid):
    stdout.write("Killing process")
    ##9 because it represents termination https://en.wikipedia.org/wiki/Signal_(IPC)
    os.kill(int(pid), 9)

###Button here to run this function
#Function to retrieve processes
def retrieveProcessList():
    processList = []
    keyloggerDetected = 0
    #Function to use cmd and use "tasklist" to list all running processes
    processes = Popen(['tasklist'],shell = False, stdout = PIPE)
    #Remove unwanted lines
    processes.stdout.readline()
    processes.stdout.readline()
    processes.stdout.readline()


    #Loop to look at all processes individually
    for line in processes.stdout:
        #Put processes into an array
        processInfo = line.decode('utf-8').replace("b'","").split()
        #Debug
        #print(processInfo)
        ##Append process into processList array if the list has a length of 6(Normal)
        if len(processInfo) == 6:
            processList.append(Process(processInfo))
    
    #Loop through processList to look at each process
    for process in processList:
        #Loop through blacklisted terms and see if it matches the process
        for blacklisted in blacklistNames:
            #Upper so that processes with capital and small letters are matched evenly
            if(process.name.upper().find(blacklisted.upper()) > -1):
                print('Keylogger detected with the process name of: ' + process.name + '\nPID: ' + process.pid)
                option = input("Delete File? (Y/N)")
                if (option == "Y" or option == "y"):
                    #Find file path
                    print(f'The location of the file is: {Process_path(int(process.pid))}')
                    #Delete file at that file path
                    try:    
                        os.remove(Process_path(int(process.pid)))
                    except FileNotFoundError:
                        print("Error finding file")
                    keyloggerDetected += 1
                elif (option == "N" or option == "n"):  
                    #Remove process
                    removeKeylogger(process.pid)
                    keyloggerDetected += 1
    if keyloggerDetected == 0:
        print("No keylogger was detected.")

#Retrieve process path
def Process_path(pid):
    WMI = GetObject('winmgmts:')
    processes = WMI.InstancesOf('Win32_Process')                
    for p in processes :                                
        if p.Properties_("ProcessID").Value == pid: 
            return p.Properties_[7].Value               
    return "no such process"       

###Button
#Scan file if it is malicious or not
def scan_file():
    #Ask for filename
    fileInput = tk.filedialog.askopenfilename(parent=root,title='Choose a file')
    #try except to catch FileNotFoundError
    try:
        with open(fileInput,'rb') as f:
            #Scan file
            analysis = client.scan_file(f)
            print("Scanning...")
            #Keep looping until analysis is completed
            while True:
                analysis = client.get_object("/analyses/{}", analysis.id)
                print(analysis.status)
                #End loop when analysis is completed
                if analysis.status == "completed":
                    break
            #Find number of malicious detections
            numberOfMaliciousDetections = analysis.stats['malicious']
            #Run remove_file function
            remove_file(numberOfMaliciousDetections, fileInput)
    except FileNotFoundError:
        print("Please input a valid file")
        pass

#Function to convert file to SHA1
def convertToHash(file):
   #make a hash object
   h = hashlib.sha1()
   #open file for reading in binary mode
   with open(file,'rb') as f:
       #loop till the end of the file
       chunk = 0
       while chunk != b'':
           #read only 1024 bytes at a time
           chunk = f.read(1024)
           h.update(chunk)
   #return the hex representation of digest
   return h.hexdigest()

#Function to scan digital signature of file
def scan_signature():
    #Ask for filename
    fileInput = tk.filedialog.askopenfilename(parent=root,title='Choose a file')
    try:
        hash = convertToHash(fileInput)
        #Debug
        #print(hash)
        #Send request to API
        file = client.get_object(f'/files/{hash}')
        #Find number of malicious detections
        numberOfMaliciousDetections = file.last_analysis_stats['malicious']
        #Run remove_file function
        remove_file(numberOfMaliciousDetections, fileInput)
    except FileNotFoundError:
        print("Please input a valid file")
        pass

#Function to delete file
def remove_file(num, fileInput):
    #If >0 then remove file
    if(num)>0:
        os.remove(fileInput)
        print("File has been deleted! :D")
        client.close()
    else:
        print("File is not malicious! :D")
        client.close()

###GUI Auto Update Page
def procMon():
    #https://www.geeksforgeeks.org/how-to-make-a-process-monitor-in-python/
    # Run an infinite loop to constantly monitor the system
    while True:
        # Clear the screen using a bash command
        os.system('cls')
        print("==============================Process Monitor\
        ======================================")
    
        # Fetch the Network information
        print("----Networks----")
        table = PrettyTable(['Network', 'Status', 'Speed'])
        for key in psutil.net_if_stats().keys():
            name = key
            up = "Up" if psutil.net_if_stats()[key].isup else "Down"
            speed = psutil.net_if_stats()[key].speed
            table.add_row([name, up, speed])
        print(table)
    
        # Fetch the memory information
        print("----Memory----")
        memory_table = PrettyTable(["Total", "Used",
                                    "Available", "Percentage"])
        vm = psutil.virtual_memory()
        memory_table.add_row([
            vm.total,
            vm.used,
            vm.available,
            vm.percent
        ])
        print(memory_table)
        
        # Fetch the last 10 processes from available processes
        print("----Processes----")
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
        print(process_table)

        # Create a 1 second delay
        time.sleep(1)

###GUI Showing blacklisted_software + whitelisted_software and detected ports and software
#Monitors SMTP ports for any activities
def portMonitor():
    
    time = 1
    while True:
        if time == 1:
            print("\nScanning in progress...")
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

                # terminate process if it exists in blacklist
                if process_name in blacklisted_software:
                    p.kill()
                    print("Blacklist application found running.\nProcess automatically terminated.")
                    time = 1
                # if process is not in whitelist, check if it should be
                elif process_name not in whitelisted_software:
                    print("Pausing application...\n")
                    p.suspend()
                    print("Information on application identified in your system to be potential threat...")
                    print(f'Application name: {process_name}\n'
                          f'Process ID (PID): {pid}'
                          f'Trying to communicate on port {port}\n')
                    selected = False
                    while not selected:
                        is_safe = input("Would you like to whitelist this application? (Y/N): ").lower()
                        if is_safe == 'n':
                            print("Terminating process...")
                            p.kill()
                            print("Adding to blacklist...")
                            blacklisted_software.append(process_name)
                            selected = True
                            time = 1
                        elif is_safe == 'y':
                            print("Resuming process...")
                            p.resume()
                            print("Adding to whitelist...")
                            whitelisted_software.append(process_name)
                            selected = True
                            time = 1

#Main GUI
root = tk.Tk()
root.title('Anti Keylogger')
root.geometry('700x500')
btnRetrieveProcesses = tk.Button(root, text = "Retrieve Processes", command=retrieveProcessList).place(x=100,y=450)
btnScanFile = tk.Button(root, text = "Scan File", command=scan_file).place(x=300,y=450)
btnScanSignature = tk.Button(root, text = "Scan File Signature", command=scan_signature).place(x=500,y=450)
root.mainloop()
