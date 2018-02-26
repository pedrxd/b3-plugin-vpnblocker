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


__version__ = 2.0;
__author__ = 'pedrxd';

import b3
import b3.events
import b3.plugin

from IPy import IP
import requests

class VpnblockerPlugin(b3.plugin.Plugin):
    requiresConfigFile = False
    apiKey = 'PUTYOURTOKENHERE'

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
        if self.byPassProtection(client) :
            self.debug('Player {} ({}) bypassed VpnProtection'.format(client.name, client.ip))
            return;

        self.debug('Checking {} ip...'.format(client.name))
        if self.isVpn(client.ip):
            self.debug('Access denied {} ({})'.format(client.name, client.ip))
            client.kick('Vpn is not allowed on this server')

    def cmd_denyVpn(self,data,client,cmd=None):
        """
        <player/ip> - Deny a player or a ip to use vpn
        """
        if not data:
            client.message('Correct usage: !dv <player/ip>')
            return

        argv = self._adminPlugin.parseUserCmd(data)
        if self.validIP(argv[0]) :
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

    def cmd_allowVpn(self, data, client, cmd=None):
        """
        <player/ip> - Allow a player or a ip to use vpn
        """
        if not data:
            client.message('Correct usage: !av <player/ip>')
            return

        argv = self._adminPlugin.parseUserCmd(data)
        if self.validIP(argv[0]) :
            if self.addIpQueue(argv[0]):
                client.message('The ip has been added to the list, next player with that ip will be allowed')
            else:
                client.message('That ip is on the list.')
        else:
            sclient = self._adminPlugin.findClientPrompt(data, client)
            if not sclient:
                return
            if self.registerPlayer(sclient):
                client.messasge('{} was allowed previusly')
            else
                client.message('{} allowed to use vpn'.sclient.name)

    # ===========================================
    # Usefull functions for help on the main thread
    # ===========================================
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

    def isVpn(self, ip):
        """
        Check if a ip is a vpn
        Return True if is vpn and False if not
        """
        try:
            r = requests.get('http://v2.api.iphub.info/ip/{}'.format(ip), headers={'X-Key':self.apiKey}, timeout=1)
            if r.status_code == 200 :
                finalRes = r.json()
                if finalRes['block'] == 1 :
                    return True
        except:
            self.debug('Connection failure??')
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
