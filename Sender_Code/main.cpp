/* University of the West of England - UWE Bristol
   Faculty:           Environment & Technology
   Department:        Computer Science and Creative Technologies
   Program:           MSc Cyber Security
 

    This is the code for a sender demonstrating end-to-end encryption using AES algorithm
    This code is based heavily on the lab assessment done with the IOT systems security module also.

    Azeez Animashaun - Student No. 21077233


                                    

/* ********************************************************************************************************* */

#include "MicroBit.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <string>
#include <iostream>
#include <sstream>
#include <iomanip>
#include "aes.hpp"
#include "sha256.h"
// #include "SerialStreamer.h"
#include "StreamNormalizer.h"
#include "LevelDetector.h"

MicroBit uBit;

// ManagedString sendData;
//  int salt = 0;
// std::string generateCypher(std::string command,std::string key);
void generateandSendCypher(std::string command, std::string key, std::string salt);
std::string generateKey(std::string secret, std::string salt);
std::string generateSalt(void);

std::string sharedSecret("sharedsecret");//shared secret known to only the transmitter and receiver

std::string salt_string;
std::string privKey, raw_command, att_command;
// char in[300] = {0};

int thresholdtemp = 31; //above this temperature, an attack happens
int maxthresholdtemp = 40;//the temperature progressively increases till it reaches this value
int tempStep = 3;
int x = 0;
int y = 0;
int z = 0;
int px = 0;
int py = 0;
bool isAccel = false ;
//int z2 = 0;

int g_to_pix(int g)
{
    int v = 2;
    if (g < -200)
        v--;
    if (g < -500)
        v--;
    if (g > 200)
        v++;
    if (g > 500)
        v++;

    return v;
}
/*
*This is the code of the transmitter and it simulates three different basic IOT Commands done securely over the AES.
**
*/
int main()
{

   uBit.init();//initializing the microbit

   uBit.radio.enable();//enabling the radio communication

    while (1)
    {
        // check button entry
        // if button is 1, execute module 1
        // if button is 2, execute module 2
        if (uBit.buttonA.isPressed()) // if found the button A pressed at the time of call
        {
            // generate the salt and convert to a string
            salt_string = generateSalt();
            // build the secret key
            privKey = generateKey(sharedSecret, salt_string);
            raw_command = "---commandone---";//16 byte raw command

           
            uBit.display.scroll("001");//visible checkpoint for the code
            // create payload showinf cipher and salt delim = " "
            generateandSendCypher(raw_command, privKey, salt_string);
            // uBit.serial.send("\r\n Button A Pressed ");
            // add a delay so button is not press multiple times in error
            uBit.sleep(2000);
        }
        else if (uBit.buttonB.isPressed())
        {
            /*
            If button b is pressed, the microbit acts as a rudimentary gps system
            it gets the relative position and transmits same as the salt
            this is done using the example codes gotten from the microbit docs
            */
            x = uBit.accelerometer.getX();
            y = uBit.accelerometer.getY();
            z = uBit.accelerometer.getZ();

            DMESG("Acc [X:%d][Y:%d][Z:%d]", x, y, z);
            //the position is converted to relative pixel positions below
            px = g_to_pix(x);
            py = g_to_pix(y);
            isAccel = true;//this is done replace the salt with the relative positions

            // uBit.sleep(100);
            // generate the salt and convert to a string
            salt_string = generateSalt();
            isAccel = false;
            // build the secret key
            privKey = generateKey(sharedSecret, salt_string);
            
            raw_command = "---commandtwo---";
            uBit.display.scroll("002");
            // createpayload showinf cipher and salt delim = <delim>
            generateandSendCypher(raw_command, privKey, salt_string);
             
            // add a delay
            uBit.sleep(2000);
            
        }
                 // uBit.sleep(100);
        //}

 
        //  uBit.display.scroll("HELLO WORLD!");
    }
    release_fiber();
}
// function to generate cypher and returns a managed string
void generateandSendCypher(std::string command, std::string key, std::string salt)
{
    struct AES_ctx ctx; // following the aes library implementation
    // malloc the spac required for 3 c_string buffers that i can manipulate
    uint8_t *ivptr = (uint8_t *)malloc(16 * sizeof(uint8_t));
    uint8_t *keyptr = (uint8_t *)malloc(32 * sizeof(uint8_t));
    uint8_t *commandptr = (uint8_t *)malloc(16 * sizeof(uint8_t));

    char res[33] = {0};

    // load up the iv with hex values through 16
    uint8_t c = 0x00;
    for (c; c < 16; c++)
    {
        *(ivptr + c) = c + 1;
    }
    // key is already in hex format but as a string and this needs to be changed
    c = 0;
    for (size_t i = 0; i < key.length(); i += 2)
    {
        std::string byte = key.substr(i, 2);
        uint8_t chr = (uint8_t)(int)strtol(byte.c_str(), NULL, 16);
        *(keyptr + c) = chr;
        c++;
    }
    // convert command string to hex
    for (size_t i = 0; i < command.length(); ++i)
    {
        commandptr[i] = (unsigned char)command[i];
    }
    // initialize the iv
    AES_init_ctx_iv(&ctx, keyptr, ivptr);
    AES_CBC_encrypt_buffer(&ctx, commandptr, 16);
    // converting result back to a ascii string
    for (c = 0; c < 16; c++)
    {
        snprintf(&res[c * 2], 3, "%02x", (char)commandptr[c]);
    }

    ManagedString s(res, 32);

    char bufSalt[5] = {0}; // buffer to hold salt cstyle
    // bufSalt = salt.c_str();
    strcpy(bufSalt, salt.c_str());
    ManagedString msSalt(bufSalt, 4);

    ManagedString space("+");
    ManagedString finalPayload = s + space + msSalt;
    uBit.serial.send(finalPayload);
    uBit.serial.send("\r\n");
    // c = 100;
    int ac = uBit.radio.datagram.send(msSalt);

    if (ac == MICROBIT_OK)
    {
        uBit.serial.send("SENT\r\n");
        uBit.sleep(200);
        ac = 12;
        ac = uBit.radio.datagram.send(s);
        if (ac == MICROBIT_OK)
        {
            //add debug statements here if needed
           // uBit.display.scroll("SE1");
            //uBit.serial.send("SENTNEW\r\n");
        }
            
    }
    else if (ac == MICROBIT_INVALID_PARAMETER)
    {
        uBit.serial.send("NOT SENT\r\n");
    }
    // free the allocated space

    free(ivptr);
    free(keyptr);
    free(commandptr);
    return;
}
std::string generateSalt(void)
{
    std::ostringstream ss;
    
    uint32_t rand_num = uBit.random(9999);
    if (isAccel==true){ //replace salt coordinates 
        rand_num = (px*10)+py;
    }
    ss << std::setw(4) << std::setfill('0') << rand_num;

    return ss.str();
}
std::string generateKey(std::string secret, std::string salt)
{
    SHA256 sha256;
    std::string ans_wer;

    // concatenate secret and salt
    ans_wer = secret + salt;
    // sha256 the answer
    return sha256(ans_wer);
}
