# RMCWallet
Lightweight wallet for RMC with Qt based interface 

## Build instructions

### Windows
1. Install Visual Studio Community 2017 with C++ and Windows SDK.
2. Setup Git for Windows.
2. Download 32 or 64 bit dependency archive and unpack it either to C:\MyProjects32\ or C:\MyProjects\ respectively.
3. Run qmake_env_static.cmd and use opened command prompt for the next actions.
3. Clone this repository:
    git clone http://github.com/RussianMiningCoin/RMCWallet
4. Run the following commands:
    cd RMCWallet
    mkdir build
    cd build && qmake ..
    nmake
5. You're done ;)

## Build dependencies

Windows x86 dependencies:

https://drive.google.com/open?id=1JrLTExdlVGEy2Y8zC8n9hJrKvomHWJrW

Windows x64 dependencies:

https://drive.google.com/open?id=1hVwqMdqxgz8V1Ck8DQfWjvrYzMZGWhoZ

These builds were made with MT Release configuration using Visual Studio 2017.
