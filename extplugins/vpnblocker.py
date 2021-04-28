#
# This plugin for bigbrotherbot is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# any later version.

# This plugin is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

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
#
#  07.06.2020 - v2.0.5 - Zwambro
#  add vpnblocker.ini conf for
#  do not check players have level above than maxlevel on settings
#
#  10.06.2020 - v2.0.51 - Zwambro
#  update zwambro db links
#
#  27.02.2021 - v2.1.0 - Zwambro
#  updating zwambro db links
#  add zwamro api token for more security
#
#  03.04.2021 - v2.1.1 - Zwambro
#  add config file
#
#  10.04.2021 - v2.1.11 - Zwambro
#  add a custom User-Agent header for xdefcon DB
#  fix command unrecognized error
#  add max connections option to config

__version__ = '2.1.11'
__author__ = 'pedrxd'

import b3
import b3.events
import b3.plugin
from b3.functions import getCmd

# you have to install ipy : pip install ipy
from IPy import IP
import requests
import json
import uuid


class VpnblockerPlugin(b3.plugin.Plugin):

    _adminPlugin = None
    _checklevel = 1
    _maxConnections = 100
    serverId = ""
    apiKey1 = ""
    apiKey2 = ""
    apiKey3 = ""
    allowvpn = 100
    denyvpn = 100

    def onStartup(self):
        self._adminPlugin = self.console.getPlugin('admin')

        if not self._adminPlugin:
            self.error('Could not find admin plugin')
            return

        # register our commands
        if 'commands' in self.config.sections():
            for cmd in self.config.options('commands'):
                level = self.config.get('commands', cmd)
                sp = cmd.split('-')
                alias = None
                if len(sp) == 2:
                    cmd, alias = sp

                func = getCmd(self, cmd)
                if func:
                    self._adminPlugin.registerCommand(self, cmd, level, func, alias)

        self.registerEvent(b3.events.EVT_CLIENT_AUTH, self.onConnect)

        #prepare user-agent
        hostIp= str(self.console._publicIp)
        HostPort= str(self.console._port)
        spr = '%s:%s' %(hostIp, HostPort)
        self.serverId = str(uuid.uuid5(uuid.NAMESPACE_DNS, spr))

    def onLoadConfig(self):
        try:
            self._checklevel = self.config.getint('settings', 'maxlevel')
            self._maxConnections = self.config.getint('settings', 'maxconnactions')
            self.apiKey1 = self.getSetting('settings', 'proxycheck.io', b3.STR, self.apiKey1)
            self.apiKey2 = self.getSetting('settings', 'iphub.info', b3.STR, self.apiKey2)
            self.apiKey3 = self.getSetting('settings', 'zwambro.pw', b3.STR, self.apiKey3)
        except Exception, err:
            self.error(err)

    def onConnect(self, event):
        client = event.client

        self.debug('Checking {} ip...'.format(client.name))

        info = {'ip': str(client.ip)}

        if client.maxLevel > self._checklevel:
            self.debug("%s is a higher level user, he can't be checked" % client.name)
            return

        else:
            self.debug('%s is a lower level user, checking his ip ...' %client.name)

            if client.connections > self._maxConnections:
                self.debug('%s has more than %s connections, not affected by the plugin' % (client.name, self._maxConnections))
                return

            else:
                self.debug('%s have less than %s connections, we will check his ip now ... ' % (client.name, self._maxConnections))

                self.waitingForRegistration(client)

                if self.byPassProtection(client):
                    self.debug('Player {} ({}) bypassed VpnProtection'.format(client.name, client.ip))
                    return

                elif self.zwamBroDb(client.ip):
                    self.debug('Access denied by Zwambro db for {} ({})'.format(client.name, client.ip))
                    client.kick('^6Proxy/VPN Detected!^7')
                    return

                elif self.xdefConDb(client.ip):
                    self.zwamBroAddVpn(client.ip, info)
                    self.debug('Access denied by xdefcon for {} ({})'.format(client.name, client.ip))
                    client.kick('^6Proxy/VPN Detected!^7')
                    return

                elif self.proxyCheckDb(client.ip):
                    self.zwamBroAddVpn(client.ip, info)
                    self.debug('Access denied by Proxycheck for {} ({})'.format(client.name, client.ip))
                    client.kick('^6Proxy/VPN Detected!^7')
                    return

                elif self.ipHubDb(client.ip):
                    self.zwamBroAddVpn(client.ip, info)
                    self.debug('Access denied by Iphub for {} ({})'.format(client.name, client.ip))
                    client.kick('^6Proxy/VPN Detected!^7')
                    return

                elif self.ipApiDb(client.ip):
                    self.zwamBroAddVpn(client.ip, info)
                    self.debug('Access denied by Ipinfo for {} ({})'.format(client.name, client.ip))
                    client.kick('^6Proxy/VPN Detected!^7')
                    return

                else:
                    self.debug('({}) not a VPN'.format(client.ip))

    def cmd_denyvpn(self, data, client, cmd=None):
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
            client.message('{} has been deleted from the list if exists'.format(sclient.name))
            self.removePlayer(sclient)

    def cmd_allowvpn(self, data, client, cmd=None):
        """
        <player/ip> - Allow a player or a ip to use vpn
        """
        if not data:
            client.message('Correct usage: !av <player/ip>')
            return

        argv = self._adminPlugin.parseUserCmd(data)
        if self.validIP(argv[0]):
            if self.addIpQueue(argv[0]):
                client.message('The ip has been added to the list, next player with that ip will be allowed')
            else:
                client.message('That ip is on the list.')
        else:
            sclient = self._adminPlugin.findClientPrompt(data, client)
            if not sclient:
                return
            if self.registerPlayer(sclient):
                client.messasge('{} was allowed previusly'.sclient.name)
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
            query = "INSERT INTO vpnblockwaiting VALUES (NULL, '{0}')".format(ip)
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
        query = "SELECT * FROM vpnblockwaiting WHERE ip='{0}'".format(client.ip)
        result = self.console.storage.query(query)
        if result.rowcount >= 1:
            rmq = "DELETE FROM vpnblockwaiting WHERE ip='{0}'".format(client.ip)
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

    def zwamBroDb(self, ip):
        """
        Check if a ip is a vpn
        Return True if is vpn and False if not
        """
        self.debug("checking Zwambro DB")
        try:
            r = requests.get('https://zwambro.pw/antivpn/checkvpn?ip={}' .format(ip), headers={'Authorization': 'Token {}' .format(self.apiKey3.strip())}, timeout=2)
            if r.status_code == 200:
                finalRes = r.json()
                if finalRes["vpn"] == True:
                    self.debug('Zwambro db detect this ip ({}) a VPN/Proxy' .format(ip))
                    return True
        except Exception as e:
            self.debug('error: ' + str(e))
        return False

    def xdefConDb(self, ip):
        """
        Check if a ip is a vpn
        Return True if is vpn and False if not
        """
        self.debug("checking xdefcon DB")
        try:
            headers = {"User-Agent": "{}" .format(self.serverId)}
            r = requests.get('https://api.xdefcon.com/proxy/check/?ip={}&vpn=1' .format(ip), headers, timeout=2)
            if r.status_code == 200:
                finalRes = r.json()
                if finalRes["proxy"] == True:
                    self.debug('Xdefcon db detect this ip ({}) a VPN/Proxy' .format(ip))
                    return True
        except Exception as e:
            self.debug('error: ' + str(e))
        return False

    def proxyCheckDb(self, ip):
        """
        Check if a ip is a vpn
        Return True if is vpn and False if not
        """
        self.debug("checking proxycheck DB")
        try:
            r2 = requests.get('http://proxycheck.io/v2/{}?key={}&vpn=1' .format(ip, self.apiKey1.strip()), timeout=3)
            if r2.status_code == 200:
                finalRes2 = r2.json()
                if finalRes2[ip]["proxy"] == "yes":
                    self.debug('proxycheck db detect this ip ({}) a VPN/Proxy' .format(ip))
                    return True
        except Exception as e:
            self.debug('error: ' + str(e))
        return False

    def ipHubDb(self, ip):
        """
        Check if a ip is a vpn
        Return True if is vpn and False if not
        """
        self.debug("checking iphub DB")
        try:
            r3 = requests.get('http://v2.api.iphub.info/ip/{}'.format(ip), headers={'X-Key': self.apiKey2.strip()}, timeout=3)
            if r3.status_code == 200:
                finalRes3 = r3.json()
                if finalRes3["block"] == 1:
                    self.debug('Iphub db detect this ip ({}) a VPN/Proxy' .format(ip))
                    return True
        except Exception as e:
            self.debug('error: ' + str(e))
        return False

    def ipApiDb(self, ip):
        """
        Check if a ip is a vpn
        Return True if is vpn and False if not
        """
        self.debug("checking ipapi DB")
        try:
            r4 = requests.get('http://ip-api.com/json/{}?fields=status,mobile,proxy,hosting,query' .format(ip), timeout=2)
            if r4.status_code == 200:
                finalRes4 = r4.json()
                if finalRes4["proxy"] == True:
                    self.debug('IP info db detect this ip ({}) a VPN/Proxy' .format(ip))
                    return True
        except Exception as e:
            self.debug('error: ' + str(e))
        return False

    def zwamBroAddVpn(self, ip, info=None):
        self.debug("adding VPN to zwambro DB")
        try:
            headers = {'Content-type': 'application/json', 'Authorization': 'Token {}' .format(self.apiKey3.strip())}
            r = requests.post('https://zwambro.pw/antivpn/addvpn', data=json.dumps(info), headers=headers)
            if r.status_code == 201:
                self.debug('VPN IP added perfeclty')
                return True
        except Exception as e:
            self.debug('error: ' + str(e))
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
