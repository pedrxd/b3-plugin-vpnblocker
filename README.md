

                      .___                 .___
    ______   ____   __| _/_________  ___ __| _/
    \____ \_/ __ \ / __ |\_  __ \  \/  // __ | 
    |  |_> >  ___// /_/ | |  | \/>    </ /_/ | 
    |   __/ \___  >____ | |__|  /__/\_ \____ | 
    |__|        \/     \/             \/    \/ 

# A VPN blocker for BigBrotherBot
## Introduction
Vpn blocker developed by pedrxd for bigbrotherbot focused on urbanterror
will help you to administrate the servers kicking all players trying 
to access using a vpn. Most of this users are cheats ragers etc...
If some player need join using a vpn, you can allow it with a simple command.

## Installation
You need have installed and configurated bigbrotherbot with a mysql database.
**IPy is required**
1. **Merge extplugins** folder with the same folder of bigbrotherbot
2. Add the **vpnblock.sql** inside sql folder to the b3 database
3. Go to the webpage **iphub.info and get a token** . (You can get the free one)
4. On the file vpnblocker.py **replace the line** where is **'PUTYOURTOKENHERE'** 
   with your **token**
 5. Add the plugin to the **b3.xml** without any config file.
 6. Start b3 :D

## Commands
All comands that include this plugins are listed bellow:
  - allowvpn/av <player/ip>   //Add a player to the whitelist
  - denyvpn/dv  <player/ip>   //Remove a player on whitelist

If you add a ip the nextplayer connected with that ip will be allowed to connect using vpn.
**If you deny a ip only IP's not assinged to a player will be removed**

