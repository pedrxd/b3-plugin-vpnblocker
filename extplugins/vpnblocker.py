"""
    This plugin for bigbrotherbot is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    any later version.

    This plugin is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
"""
#  05.03.2019 - v2.0.1 - Zwambro
#  - Adding "proxycheck.io" and "xdefcon.com" plus "iphub.info" tokens
#    for more protections against VPN users
#
#  28.11.2019 - v2.0.2 - Zwambro
#  Fixing Connection failure.
#
#  05.01.2020 - v2.0.3 - Zwambro
#  Fixing xdefcon.com connection failed
#
#  08.05.2020 - v2.0.4 - Zwambro
#  Check each API alone
#
#  22.05.2020 - v2.0.5b - Zwambro
#  less queries by checking only players under 50 connections.
#  save kicked players's IP on db

__version__ = '2.0.5b'
__author__ = 'pedrxd'

import b3
import b3.events
import b3.plugin

# you have to install ipy : pip install ipy
from IPy import IP
import requests
import json


class VpnblockerPlugin(b3.plugin.Plugin):
    requiresConfigFile = False

    # Visit www.proxycheck.io and create an account to get your API token
    apiKey1 = 'add proxycheck api token here'

    # Visit www.iphub.info and create an account to get your API token
    apiKey2 = 'add iphub api token here'

    # You don't need a token from xdefcon it's free anyway.

    def onStartup(self):
        self._adminPlugin = self.console.getPlugin('admin')

        if not self._adminPlugin:
            self.error('Could not find admin plugin')
            return

        self._adminPlugin.registerCommand(self, 'allowvpn', 80, self.cmd_allowVpn, 'av')
        self._adminPlugin.registerCommand(self, 'denyvpn', 80, self.cmd_denyVpn, 'dv')

        self.registerEvent(b3.events.EVT_CLIENT_AUTH, self.onConnect)

    def onConnect(self, event):
        client = event.client

        self.waitingForRegistration(client)
        if self.byPassProtection(client):
            self.debug('Player {} ({}) bypassed VpnProtection'.format(
                client.name, client.ip))
            return

        self.debug('Checking {} ip...'.format(client.name))

        info = {'ip': str(client.ip)}

        if client.connections < 51:
            if self.isVpnZwa(client.ip):
                self.debug('Access denied by Zwambro antishit for {} ({})'.format(client.name, client.ip))
                client.kick('^6Proxy/VPN Detected!^7')
                return
            elif self.isVpnXde(client.ip):
                self.addvpn(client.ip, info)
                self.debug('Access denied by xdefcon for {} ({})'.format(client.name, client.ip))
                client.kick('^6Proxy/VPN Detected!^7')
                return                
            elif self.isVpnProxy(client.ip):
                self.addvpn(client.ip, info)
                self.debug('Access denied by Proxycheck for {} ({})'.format(client.name, client.ip))
                client.kick('^6Proxy/VPN Detected!^7')
                return
            elif self.isVpnHub(client.ip):
                self.addvpn(client.ip, info)
                self.debug('Access denied by Iphub for {} ({})'.format(client.name, client.ip))
                client.kick('^6Proxy/VPN Detected!^7')
                return

            elif self.isVpnIpCom(client.ip):
                self.addvpn(client.ip, info)
                self.debug('Access denied by Ipinfofor {} ({})'.format(client.name, client.ip))
                client.kick('^6Proxy/VPN Detected!^7')
                return

            else:
                self.debug('player dont have vpn')
                return
        else:
            self.debug('Player have more than 50 connections')
            return

    def cmd_denyVpn(self, data, client, cmd=None):
        """
        <player/ip> - Deny a player or a ip to use vpn
        """
        if not data:
            client.message('Correct usage: !dv <player/ip>')
            return

        argv = self._adminPlugin.parseUserCmd(data)
        if self.validIP(argv[0]):
            if self.removeIPQueue(argv[0]):
                client.message('The ip has been deleted from queue')
            else:
                client.message('That ip is not on the list')
        else:
            sclient = self._adminPlugin.findClientPrompt(data, client)
            if not sclient:
                return
            client.message(
                '{} has been deleted from the list if exists'.format(sclient.name))
            self.removePlayer(sclient)

    def cmd_allowVpn(self, data, client, cmd=None):
        """
        <player/ip> - Allow a player or a ip to use vpn
        """
        if not data:
            client.message('Correct usage: !av <player/ip>')
            return

        argv = self._adminPlugin.parseUserCmd(data)
        if self.validIP(argv[0]):
            if self.addIpQueue(argv[0]):
                client.message(
                    'The ip has been added to the list, next player with that ip will be allowed')
            else:
                client.message('That ip is on the list.')
        else:
            sclient = self._adminPlugin.findClientPrompt(data, client)
            if not sclient:
                return
            if self.registerPlayer(sclient):
                client.messasge('{} was allowed previusly')
            else:
                client.message('{} allowed to use vpn'.sclient.name)

    def addIpQueue(self, ip):
        """
        Add the ip to the vpnblockwaiting table.
        Return True if the ip is added or false if exist previusly
        """
        query = "SELECT * FROM vpnblockwaiting WHERE ip='{}'".format(ip)
        s = self.console.storage.query(query)
        if s.rowcount == 0:
            query = "INSERT INTO vpnblockwaiting VALUES (NULL, '{0}')".format(
                ip)
            self.console.storage.query(query)
            return True
        return False

    def removeIPQueue(self, ip):
        """
        Remove the ip to the vpnblockwaiting table.
        Return True if the ip is removed or false if doesn't exist
        """
        query = "SELECT * FROM vpnblockwaiting WHERE ip='{}'".format(ip)
        s = self.console.storage.query(query)
        if s.rowcount == 0:
            query = "DELETE FROM vpnblockwaiting WHERE ip='{0}'".format(ip)
            self.console.storage.query(query)
            return True
        return False

    def removePlayer(self, client):
        """
        Remove a player for bypass protection
        """
        query = "DELETE FROM vpnblock WHERE client_id={0}".format(client.id)
        self.console.storage.query(query)

    def registerPlayer(self, client):
        """
        Add a player for allow bypass protection
        Return true if added or false if exist
        """
        if not self.byPassProtection(client):
            query = "INSERT INTO vpnblock VALUES (NULL, {0})".format(client.id)
            self.console.storage.query(query)
            return True
        return False

    def waitingForRegistration(self, client):
        """
        If some player is on the waitinglist, it will be added
        Return True if register or false if nothing happend
        """
        query = "SELECT * FROM vpnblockwaiting WHERE ip='{0}'".format(
            client.ip)
        result = self.console.storage.query(query)
        if result.rowcount >= 1:
            rmq = "DELETE FROM vpnblockwaiting WHERE ip='{0}'".format(
                client.ip)
            self.console.storage.query(rmq)
            if not self.registerPlayer(client):
                return False
            return True
        return False

    def byPassProtection(self, client):
        """
        Check from database if a player can bypass protection
        Return True if can bypass and False if not
        """
        query = "SELECT * FROM vpnblock WHERE client_id={0}".format(client.id)
        result = self.console.storage.query(query)
        if result.rowcount == 1:
            return True
        return False

    def isVpnZwa(self, ip):
        """
        Check if a ip is a vpn
        Return True if is vpn and False if not
        """
        try:
            r = requests.get('https://globanlist.zwambro.pw/checkvpn.php?ip={}' .format(ip), timeout=2)
            if r.status_code == 200:
                finalRes = r.json()
                if finalRes["vpn"] == True:
                    self.debug('Zwambro db detect this ip ({}) is a VPN/Proxy' .format(ip))
                    return True
        except:
            self.debug('Connection to zwambro db failed!!')
        return False

    def isVpnXde(self, ip):
        """
        Check if a ip is a vpn
        Return True if is vpn and False if not
        """
        try:
            r = requests.get(
                'https://api.xdefcon.com/proxy/check/?ip={}&vpn=1' .format(ip), timeout=2)
            if r.status_code == 200:
                finalRes = r.json()
                if finalRes["proxy"] == True:
                    self.debug('Xdefcon db detect this ip ({}) is a VPN/Proxy' .format(ip))
                    return True
        except:
            self.debug('Connection to xdefcon.com failed!!')
        return False

    def isVpnProxy(self, ip):
        """
        Check if a ip is a vpn
        Return True if is vpn and False if not
        """
        try:
            r2 = requests.get(
                'http://proxycheck.io/v2/{}?key={}&vpn=1' .format(ip, self.apiKey1), timeout=3)
            if r2.status_code == 200:
                finalRes2 = r2.json()
                if finalRes2[ip]["proxy"] == "yes":
                    self.debug('proxycheck db detect this ip ({}) is a VPN/Proxy' .format(ip))
                    return True
        except:
            self.debug('Connection to proxycheck.io failed!!')
        return False

    def isVpnHub(self, ip):
        """
        Check if a ip is a vpn
        Return True if is vpn and False if not
        """
        try:
            r3 = requests.get('http://v2.api.iphub.info/ip/{}'.format(ip),
                              headers={'X-Key': self.apiKey2}, timeout=3)
            if r3.status_code == 200:
                finalRes3 = r3.json()
                if finalRes3["block"] == 1:
                    self.debug('Iphub db detect this ip ({}) is a VPN/Proxy' .format(ip))
                    return True
        except:
            self.debug('Connection to iphub.info failed!!')
        return False

    def isVpnIpCom(self, ip):
        """
        Check if a ip is a vpn
        Return True if is vpn and False if not
        """
        try:
            r4 = requests.get(
                'http://ip-api.com/json/{}?fields=status,mobile,proxy,hosting,query' .format(ip), timeout=2)
            if r4.status_code == 200:
                finalRes4 = r4.json()
                if finalRes4["proxy"] == True:
                    self.debug('IP info db detect this ip ({}) is a VPN/Proxy' .format(ip))
                    return True
                elif finalRes4["hosting"] == True:
                    self.debug('IP info db detect this ip ({}) is a VPN/Proxy' .format(ip))
                    return True
        except:
            self.debug('Connection to ip.info failed!!')
        return False
        
    def addvpn(self, ip, info=None):
        try:
            headers = {'Content-type': 'application/json'}
            r = requests.post('https://globanlist.zwambro.pw/addvpn.php', data=json.dumps(info), headers=headers)
            if r.status_code == 201:
                self.debug('VPN IP added perfeclty')
                return True
        except ValueError, e:
            self.debug('error: ' + e)
            raise
        return False        

    def validIP(self, ip):
        """
        Check if a ip has a correct format
        Return True when is valid and False when not
        """
        try:
            IP(ip)
        except:
            return False
        return True
