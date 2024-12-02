# logical_peapod
PEAPOD logical expansion.

## Requirements
Linux

Maven 3.8.7

Java 17

## Build & Run
Once per terminal session, from main dir, run:
```console
  . classpath
```
To compile:
```console
  make
```
To clean:
```console
  make clean
```
To run client:
```console
  ./runClient.sh [port] -ip [ipadd] [other args]
```
To run server:
```console
  ./runServer.sh [port]
```
To kill server:
```console
  ./killServer.sh
```
## Code References
1. One of Anthony's old projects for the client/server RMI setup
   
3. https://encryption-decryption.mojoauth.com/elgamal-variable-key-size-encryption--java/

4. https://www.baeldung.com/java-aes-encryption-decryption
