# FeLink
FeLink is a lightweight and cross-platform encrypted networking communication framework for IoT.
FeLink consists of a "base" and several "dev", the "base" side acts as a gateway to forward the user's control data and provide advanced functions, and the "dev" side performs the corresponding control actions.
  
### Directory  
1. framework/  : contains "base" side framework and "dev" side framework  
2. template/   : contains instances of "base" side, "dev" side, and user client  
### Framework usage  
1. "dev" side:  
    1. move "FeLinkDevice/" folder to your project  
    2. complete the user interface functions in "userio.c"  
    3. complete the user configuration in "userconf.h" as required  
    4. just call the interface where needed  
1. "base" side:  
    1. move "FeLinkBase/" folder to your project  
    2. complete the user configuration in "userconf.h" as required  
    3. just call the interface where needed  
