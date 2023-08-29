/* University of the West of England - UWE Bristol
   Faculty:           Environment & Technology
   Department:        Computer Science and Creative Technologies
   Program:           MSc Cyber Security
 

    This is the code for a receiver demonstrating end-to-end encryption using AES algorithm
    This code is based heavily on the lab assessment done with the IOT systems security module also.

    Azeez Animashaun - Student No. 21077233


   References:        References to main code used is at the end                                             */

/* ********************************************************************************************************* */

/* Headers and Libraries declaration      */

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
MicroBit uBit;

/* Structure and variable declaration                                                                                  */


/* **********************     Functions declaration       *****************************              */

int px = 0, py = 0;
char salt[5] = {0};
std::string sharedSecret("sharedsecret");
std::string salt_string;
std::string privKey, dec_command;
std::string generateKey(std::string secret, std::string salt);
void decryptCypher(std::string cipher, std::string key);

const char *const happy_emoji = "\
    000,255,000,255,000\n\
    000,000,000,000,000\n\
    255,000,000,000,255\n\
    000,255,255,255,000\n\
    000,000,000,000,000\n";
const char *const wink_emoji = "\
    000,255,000,000,000\n\
    000,000,000,000,000\n\
    255,000,000,000,255\n\
    000,255,255,255,000\n\
    000,000,000,000,000\n";

void display_wink()
{
    // DMESG("DISPLAY_WINK:");

    MicroBitImage smile(happy_emoji);
    MicroBitImage wink(wink_emoji);

    uBit.display.print(smile);
    uBit.sleep(1000);
    uBit.display.print(wink);
    uBit.sleep(1000);
    uBit.display.print(smile);
    uBit.sleep(1000);

    uBit.display.clear();
}

void onData(MicroBitEvent e)
{
    uint8_t buffer[38] = {0};
    int i = 0, b = 0;

    char payload[33] = {0};
    int ac = uBit.radio.datagram.recv(buffer, 32);
    if (ac > 0)
    {
       // uBit.display.scroll(ac);
        if (ac == 4)
        {
            for (b = 0; b < 4; b++)
            {
                // saltcounter=b+33;
                salt[b] = (char)buffer[b];
                salt_string = salt;
            }
        }
        else if (ac == 32)
        {
            for (i = 0; i < 32; i++)
            {
                payload[i] = (char)buffer[i];
            }
            ManagedString pu(payload, 32);
            ManagedString ye(salt, 4);
            uBit.serial.send(pu);
            uBit.serial.send("\r\n");
            uBit.sleep(200);
            uBit.serial.send(ye);
            uBit.serial.send("\r\n");
            privKey = generateKey(sharedSecret, salt_string);
            dec_command = payload;
            decryptCypher(dec_command, privKey);
            memset(salt, 0, sizeof(salt));
        }
    }

    // std::string cipherString(payload);

    // decryptCypher(dec_command,privKey);
    return;
}

/* **********************     MAIN Function        *****************************              */

int main()
{
    uBit.init();
    uBit.messageBus.listen(MICROBIT_ID_RADIO, MICROBIT_RADIO_EVT_DATAGRAM, onData);
    uBit.radio.enable();

    while (1)
    {
        uBit.sleep(500);
    }
    release_fiber();
}

/* **********************     END of MAIN Function        *****************************              */


/* **********************     AES-CBC to Decrypt Function  *****************************              */

void decryptCypher(std::string cipher, std::string key)
{
    struct AES_ctx ctx; // following the aes library implementation
    char result[17] = {0};
    uint8_t *ivptr = (uint8_t *)malloc(16 * sizeof(uint8_t));
    uint8_t *keyptr = (uint8_t *)malloc(32 * sizeof(uint8_t));
    uint8_t *cipherptr = (uint8_t *)malloc(16 * sizeof(uint8_t));

    uint8_t c = 0x00;
    for (c=0; c < 16; c++)
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
    // cipher is already in hex format but as a string and this needs to be changed
    c = 0;
    for (size_t i = 0; i < cipher.length(); i += 2)
    {
        std::string byte2 = cipher.substr(i, 2);
        uint8_t chr = (uint8_t)(int)strtol(byte2.c_str(), NULL, 16);
        *(cipherptr + c) = chr;
        c++;
    }

    AES_init_ctx_iv(&ctx, keyptr, ivptr);
    AES_CBC_decrypt_buffer(&ctx, cipherptr, 16);

    for (c = 0; c < 16; c++)
    {
        result[c] = (char)cipherptr[c];
        //  uBit.display.print(result[c]);
        // uBit.sleep(800);
    }
    // uBit.display.scroll("001");

    ManagedString g(result, 16);
    ManagedString hel("---commandone---");
    ManagedString tw("---commandtwo---");
    // uBit.serial.send("the decrypted command: \r\n");
    uBit.serial.send(g);
    // uBit.serial.send("\r\n");
    if (g == hel)
    {
        display_wink();
    }
    else if (g == tw)
    {
        int bufacc = std::stoi(salt_string);
        py = bufacc % 10;
        px = ((bufacc % 100) - py) / 10;
        uBit.display.image.clear();
        uBit.display.image.setPixelValue(px,py,255);
        uBit.sleep(500);
    }
    // uBit.display.scroll("ONE");

    free(ivptr);
    free(keyptr);
    free(cipherptr);
    return;
}

/* ********************** SHA-256 hash generation for authentication process  ********************** */

std::string generateKey(std::string secret, std::string salt)
{
    SHA256 sha256;
    std::string ans_wer;

    // concatenate secret and salt
    ans_wer = secret + salt;
    // sha256 the answer
    return sha256(ans_wer);
}

