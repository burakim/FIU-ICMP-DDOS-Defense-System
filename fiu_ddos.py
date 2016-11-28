# Copyright 2016
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at:
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""
It is originated from l2_learning.py file which was written by James McCauley
Halim Burak Yesilyurt
Enes Erdin
Matthew Kress
Mian Zulqarnain
"""

from pox.core import core
import pox.openflow.libopenflow_01 as of
import pox.lib.packet as pkt
from pox.lib.util import dpid_to_str, str_to_dpid
from pox.lib.addresses import IPAddr,EthAddr,parse_cidr
from pox.lib.util import str_to_bool
from pox.lib.packet.ethernet import ethernet
from pox.lib.packet.arp import arp
from pox.lib.packet.icmp import icmp
import time

log = core.getLogger()
databank = dict()
maxAllowedPacketNumber = 5
checkingPeriod = 60 # unit is second.

class FIUPacket (object):
    def __init__(self, packet):
        self.packet = packet
        self.time = time.time()

class DDOSPreventer (object):
    def __init__ (self, connection):
        print "Deneme"
        connection.addListeners(self)

    def isAdded(self,sourceIpAddress):
        return databank.has_key(sourceIpAddress)

    def add2Databank(self,sourceIpAddress, packet):
        if ( self.isAdded (sourceIpAddress) is not True):
            databank[sourceIpAddress] = set()
        databank[sourceIpAddress].add(FIUPacket(packet))

    def maintainList(self):
        time2 = time.time() # max 60 sec
        toBeRemoved = set()
        for key, value in databank.iteritems():
            maxPermittedPacket = maxAllowedPacketNumber
            for item in value:
                if (time2 - item.time) > checkingPeriod:
                    toBeRemoved.add(item)
            for item1 in toBeRemoved:
                if(item1 in value):
                    value.remove(item1)

    def checkAttacker(self,src_ip):
        time2 = time.time() # max 60 sec
        maxPermittedPacket = maxAllowedPacketNumber
        if self.isAdded(src_ip) is True:
            value = databank[src_ip]
            if value is not None:
                for item in value:
                    if maxPermittedPacket <= 0:
                        return True
                    if (time2 - item.time) <= checkingPeriod:
                        #print "Packet time difference" + str(time2 - item.time)
                        maxPermittedPacket = maxPermittedPacket - 1
            else:
                print "src_ip set is null"
        return False


    def _handle_PacketIn(self, event):
        packet = event.parsed
        if packet.find("icmp"):
            if databank.has_key(packet.find("ipv4").dstip.toStr()) is False:
                print "New transmission requestor arrived. Welcome " + packet.find("ipv4").dstip.toStr()
            customizedPacket = FIUPacket(packet)
            self.add2Databank(packet.find("ipv4").dstip.toStr(),customizedPacket)
            self.maintainList()
            if (self.checkAttacker(packet.find("ipv4").dstip.toStr()) is not True):
                self.sendWithoutInterception(event)
            else:
                print "Attack is detected and blocked"
        else:
            self.sendWithoutInterception(event)


    def sendWithoutInterception(self,event):
        packet = event.parsed
        msg = of.ofp_packet_out()
        msg.actions.append(of.ofp_action_output(port = of.OFPP_FLOOD))
        msg.data = event.ofp
        msg.in_port = event.port
        event.connection.send(msg)

class DDOSDefenceSDN:
    def __init__(self):
        print "DDOS Defence has been started"
        core.openflow.addListeners(self)
    def _handle_ConnectionUp (self, event):
        print "Connection Alive"
        DDOSPreventer(event.connection)

def launch ():
    print "Pox controller initiated"
    core.registerNew(DDOSDefenceSDN)
    print "Pox controller has been just started."
