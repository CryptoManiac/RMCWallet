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
```
    cd RMCWallet
    mkdir build
    cd build && qmake ..
    nmake
```    
5. You're done ;)

### Mac OS X
1. Install Apple XCode and setup Homebrew
2. Download Qt for Mac OS  from the official site and setup it as usual.
3. Install the following Homebrew packages:
    brew install boost openssl cmake protobuf scons
4. Clone and build ripple-libpp:
```
    git clone https://github.com/RussianMiningCoin/rmc-libpp
    cd rmc-libpp && git update submodule --init --recursive
    mkdir build && cd build
    cmake .. && make
    cd ../..
```
5. Clone this repository and open RMCWallet.pro in Qt Creator.
6. You should be able to build your project as usual. If it doesn't work then ensure that rmc-libpp tree is sharing parent directory with RMCWallet project.

### Other NIXes
Should be similar to OS X steps. You may also need to build boost 1.66 though. Please consider reading rmc-libpp build instructions first.

## Build dependencies

Windows x86 dependencies:

https://drive.google.com/open?id=1JrLTExdlVGEy2Y8zC8n9hJrKvomHWJrW

Windows x64 dependencies:

https://drive.google.com/open?id=1hVwqMdqxgz8V1Ck8DQfWjvrYzMZGWhoZ

These builds were made with MT Release configuration using Visual Studio 2017.
