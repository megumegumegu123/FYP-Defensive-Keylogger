from subprocess import Popen, PIPE
import os
import signal
import vt
import time
from sys import stdout

##Names of software which should be removed
blacklist = ['keylogger', 'Keylogger']

##Process class to retrieve process name and process PID
class Process(object):
    def __init__(self, process_info):
        self.name = process_info[0]
        self.pid = process_info[1]

##Function to remove keylogger
def removeKeylogger(pid):
    stdout.write("Killing process")
    ##9 because it represents termination https://en.wikipedia.org/wiki/Signal_(IPC)
    os.kill(int(pid), 9)

def retrieveProcessList():
    processList = []
    keyloggerDetected = 0

    ##Function to use cmd and use "tasklist" to list all running processes
    processes = Popen(['tasklist'],shell = False, stdout = PIPE)
    ##Remove unwanted lines
    processes.stdout.readline()
    processes.stdout.readline()
    processes.stdout.readline()

    ##Loop to look at all processes individually
    for line in processes.stdout:
        ##Put processes into an array
        processInfo = line.decode('utf-8').replace("b'","").split()
        ##Debug
        #print(processInfo)

        ##Append process into processList array if the list has a length of 6(Normal)
        if len(processInfo) == 6:
            processList.append(Process(processInfo))
    
    ##Loop through processList to look at each process
    for process in processList:
        ##Loop through blacklisted terms and see if it matches the process
        for blacklisted in blacklist:
            ##Upper so that processes with capital and small letters are matched evenly
            if(process.name.upper().find(blacklisted.upper()) > -1):
                print('Keylogger detected with the process name of: ' + process.name + '\nPID: ' + process.pid)
                ##Remove process
                removeKeylogger(process.pid)
                keyloggerDetected += 1
    if keyloggerDetected == 0:
        print("No keylogger was detected.")
    exit()

##Virustotal API key
client = vt.Client("9227fccdca71a13c63c2cffba56b893341dc44b73b6e567aa8197d4d5ca0c0d3")
##Need to implement file input here
file = client.get_object("xx")
##Need to implement button to run this code
with open("logfile", "rb") as f:
    analysis = client.scan_file(file, wait_for_completion=True)

##Start
if __name__ == '__main__':
    retrieveProcessList()