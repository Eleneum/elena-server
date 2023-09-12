# Elena Server
Implementation of the Elena Server in Python.

## Disclaimer
This code is in its early stages, with several aspects to be rewritten and improved. The software will undergo continuous modifications, separating functions and adding classes, such as 'peers' and 'contracts,' among others.

## Installation on Ubuntu 20.04
It is recommended to install this software on Ubuntu 20.04, as Ubuntu 22.04 may have issues with the 'php-mongodb' package. If you plan to set up a mining pool, it could lead to additional challenges, though not overly complicated to resolve.

### Installing MongoDB
Ubuntu 20.04 includes MongoDB version 3.6 in its repositories. While it can be used, it is advisable to install MongoDB version 4.x or higher from the official repositories (versions 5.x and 6.x have been tested and function correctly). You can follow this tutorial for installation instructions: [How to Install MongoDB on Ubuntu 20.04](https://www.digitalocean.com/community/tutorials/how-to-install-mongodb-on-ubuntu-20-04).

### Dependencies
After installing MongoDB, follow these steps:

```bash
sudo apt-get update
sudo apt-get install python3-pip git cmake screen
pip3 install pymongo pycryptodomex web3 ethereum
pip3 install git+https://github.com/Eleneum/pyrx
```

### Configuration
Edit the 'eleneum.json' file and paste your private key (without the '0x' prefix), then launch the server.

```bash
git clone https://github.com/Eleneum/elena-server
cd elena-server
nano eleneum.json
```

### Running the server
Currently, the program cannot function as a daemon. Therefore, it is best to run it within a screen session:

```bash
screen
python3 eleneum.py
```

This will keep the program running even if you disconnect from the terminal. To detach from the screen session, press Ctrl+A followed by Ctrl+D.

At the moment, the server is using port 9090, and it cannot be changed. However, I will be adding the option to change it in future versions (which I don't expect to take too long).
