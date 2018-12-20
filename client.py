import socket
import datetime
import logging
from time import sleep
import base64
from Crypto.Cipher import AES
import hashlib
import random
import string
import sys

""" Values initialisation """
now = str(datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")) #get timestamp for logging
logPath = "logPi1.txt" #set log path
ID = 1 #set IP addresses
if(ID == 1):
    this_wifi_ip = "192.168.1.1"
    this_eth_ip = "192.168.0.1"
    target_wifi_ip = "192.168.1.2"
    target_eth_ip = "192.168.0.2"
    port=8000
if(ID == 2):
    this_wifi_ip = "192.168.1.2"
    this_eth_ip = "192.168.0.2"
    target_wifi_ip = "192.168.1.1"
    target_eth_ip = "192.168.0.1"
    port = 8000
    
#method to send a message to a specific IP using socket
def send(message, target):
    try:
        #set all socket parameters
        socket1 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        socket1.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        socket1.settimeout(1)
        socket1.connect((target, port))
        socket1.send(message)
        socket1.shutdown(socket.SHUT_RDWR)
        socket1.close
    except socket.error as err:
        logging.error(str(err)+": cannot reach "+target)

#method used to send a message on both channels
def sendMessage(message):
    send(message, target_wifi_ip)
    sleep(0.5)
    send(message, target_eth_ip)

#method used to listen and retreive a message send from another client
def listen(ip_adr):
    try:
        socket2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        socket2.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        socket2.settimeout(30)
        host = ip_adr #host IP
        socket2.bind((host, port))
        while True:
            socket2.listen()
            print("Listening on "+ip_adr)
            client, address = socket2.accept() #accept incoming messages
            print("{} connected".format(address))
            response = client.recv(255)
            if response != "":
                logging.info("Message received from "+ip_adr)
                return response
        client.close()
        socket2.shutdown(socket.SHUT_RDWR)
        stock.close()
    except socket.timeout as err:
        logging.error(str(err)+": no message received")
        return(bytes("Timeout error detected", "utf-8"))

#get keyboard input from user
def getChoice():
    while True:
        choice = str(input("Press s to send a message l to listen for a message or q to quit: "))
        if(choice=="s" or choice=="l" or choice=="q"):
            return choice

#AES ciphering
def cryptAES(message, key, iv):
    print("Key Loaded")
    print("Iv Generated")
    print("Ciphering message using AES")
    aes = AES.new(key, AES.MODE_CFB, iv)
    ciphered = aes.encrypt(message)
    return(ciphered)

#AES deciphering
def decryptAES(encrypted, key, iv):
    print("Key Loaded")
    print("Iv Retreived")
    decryption = AES.new(key, AES.MODE_CFB, iv)
    clear = decryption.decrypt(encrypted)
    return(clear)

#SHA256 checksum computing
def getChecksum(data):
    check = hashlib.sha256()
    check.update(data)
    read = check.digest()
    return(str(read))

    
if __name__=="__main__":
    #key is defined in advance, know by both clients
    key="azertyuiopqsdfghjklmwxcvbn123456"
    
    while True:
        choice = getChoice()
        if(choice == "q"):  #quit the script
            break

        if(choice == "s"):
            message = str(input("Enter message: "))
            #generate randomly initalisation vector needed for AES
            iv = ''.join(random.choice(string.ascii_uppercase + string.ascii_lowercase + string.digits) for x in range(16))
            #cipher message in AES and convert it to bytes
            encoded = cryptAES(message, key, iv)
            #get checksum from sender side
            checksum = getChecksum(encoded)
            logging.info(checksum)
            #create a first package with vector and checksum
            control = iv+" "+checksum
            sendMessage(bytes(control,'utf-8'))
            sleep(0.5)
            #send the ciphered message
            sendMessage(encoded)
        try:
            controlWifi = bytes(listen(this_wifi_ip))
        except socket.error as err:
            logging.error(str(err)+": cannot reach Wifi control")
            controlWifi = ""
            
        try:
            controlEther = bytes(listen(this_eth_ip))
        except socket.error as err:
            logging.error(str(err)+": cannot reach Ether control")
            controlEther=""
            
        try:
            responseEther = listen(this_wifi_ip)
        except socket.error as err:
            logging.error(str(err)+": cannot reach Ether response")
            
        try:
            responseWifi = listen(this_eth_ip)
        except socket.error as err:
            logging.error(str(err)+": cannot reach Wifi response")
        
        #split and get iv and checksum
        ether = controlEther.split()
        wifi = controlWifi.split()
        
        for i in ether :
            responseEtherIV = ether[0]
            receivedChecksumEther = ether[1]
            
        for i in wifi :
            responseWifiIV = wifi[0]
            receivedChecksumWifi = wifi[1]

        #get the desired output on console depending on possible errors
        #operation result is written in log file
        if(responseEther == bytes("Timeout error detected", "utf-8")):
            logging.error("no message received from Ethernet")
            log = open(logPath, "a+")
            logMessage = now + ": Timeout, no message received from Ethernet"
            log.write(logMessage+"\n")
            log.close()
            responseWifiIV = bytes("0000000000000000", "utf-8")
        if(responseWifi == bytes("Timeout error detected", "utf-8")):
            logging.error("no message received from Wifi")
            log = open(logPath, "a+")
            logMessage = now + ": Timeout, no message received from wifi"
            log.write(logMessage+"\n")
            log.close()
        
        if (responseEtherIV == responseWifiIV):
            if(responseEther == responseWifi):
                checkEther = getChecksum(responseEther)
                checkWifi = getChecksum(responseWifi)
                print("CHECKSUM CHECKING: \n")
                print("Received checksum wifi:")
                sys.stdout.buffer.write(receivedChecksumWifi)
                print("\n")
                print("Computed checksum wifi: \n"+str(checkWifi)+"\n")
                print("\n")
                print("Received checksum ethernet: ")
                sys.stdout.buffer.write(receivedChecksumEther)
                print("\n")
                print("Computed checksum ethernet: \n"+str(checkEther)+"\n")
                print("\n")
                #try to decipher message
                try :
                    clearMessage = decryptAES(responseWifi, key, responseWifiIV)
                    print("Message received: ")
                    sys.stdout.buffer.write(clearMessage)
                    print("\n")
                    log = open(logPath, "a+")
                    logMessage = now + ": Message received successfully: "+ str(clearMessage)
                    log.write(logMessage+"\n")
                    log.close()
                except Exception as err:
                    print(str(err)+"Cannot read message, check AES parameters")
                    log = open(logPath, "a+")
                    logMessage = now + ": received message cannot be deciphered"
                    log.write(logMessage+"\n")
                    log.close()
            elif():
                print("Different IVs")
                log = open(logPath, "a+")
                logMessage = now + ": Error with AES vectors, message discarded "
                log.write(logMessage+"\n")
                log.close()
        elif():
            print("Messages are different")
            log = open(logPath, "a+")
            logMessage = now + ": Received data mismatch, message discarded "
            log.write(logMessage+"\n")
            log.close()
