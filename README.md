

                      .___                 .___
    ______   ____   __| _/_________  ___ __| _/
    \____ \_/ __ \ / __ |\_  __ \  \/  // __ | 
    |  |_> >  ___// /_/ | |  | \/>    </ /_/ | 
    |   __/ \___  >____ | |__|  /__/\_ \____ | 
    |__|        \/     \/             \/    \/ 

# A VPN blocker for BigBrotherBot
## Introduction
Vpn blocker developed by pedrxd for bigbrotherbot focused on all dedicated games
will help you to administrate the servers kicking all players trying 
to access using a vpn or proxy. Most of this users are cheats ragers etc...
If some player need join using a vpn or proxy, you can allow it with a simple command.

## Installation
You need have installed and configurated bigbrotherbot with a mysql database.
**IPy is required**
1. **Merge extplugins** folder with the same folder of bigbrotherbot
2. Add the **vpnblock.sql** inside sql folder to the b3 database
3. Go to the webpage [iphub.info](https://iphub.info/) and get free or paid token, then go to [proxycheck.io](https://proxycheck.io/) and get free or paid token. for [xdefcon.com](https://www.xdefcon.com/) you don't need a token. But for zwambro DB you need a token (contact mee on discord `Zwambro#8854` to create api for your clan).
4. On the file vpnblocker.py **replace** the line where is `'past your proxycheck.io token here'` with your **proxycheck** token, then replace the line where is `'past your iphub.info token here'` with your **iphub.info** token, then replace the line where is `'past your zwmabro.pw token here'` with your **Zwambro.pw** token
 5. Add the plugin to the **b3.xml** without any config file.
 6. Start b3 :D

## Commands
All comands that include this plugins are listed bellow:
  - allowvpn/av <player/ip>   //Add a player to the whitelist
  - denyvpn/dv  <player/ip>   //Remove a player on whitelist

If you add a ip the nextplayer connected with that ip will be allowed to connect using vpn.
**If you deny a ip only IP's not assinged to a player will be removed**

