#!/usr/bin/python
#Copyright (C) 2012 Fakultet Elektrotehnike i Racunarstva
#
#This program is free software; you can redistribute it and/or
#modify it under the terms of the GNU General Public License
#as published by the Free Software Foundation; either version 2
#of the License, or (at your option) any later version.
#
#This program is distributed in the hope that it will be useful,
#but WITHOUT ANY WARRANTY; without even the implied warranty of
#MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#GNU General Public License for more details.
#
#You should have received a copy of the GNU General Public License
#along with this program; if not, write to the Free Software
#Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
#

from types import *
from pybgpdump import BGPDump
from dpkt import bgp
import socket
import struct
import sys
import time
import os.path
import os
import glob
import ipaddr
import math

################################################
################################################

#base Prefix class - it's not always used due to speed gain by using just tuples
class Prefix:		
	
	#constructor Prefix (prefix, int lenght)
	def __init__(self, prefix, lenght):			
		self.prefix = prefix
		self.lenght = lenght

	#returns string prefix
	def GetStringPrefix(self):				
		return socket.inet_ntoa(self.prefix)+"/"+str(self.lenght)

	#returns prefix
	def GetPrefix(self):					
		return self.prefix

	#returns integer prefix lenght
	def GetLenght(self):					
		return self.lenght

	#sets prerfix (prefix, int lenght)
	def SetPrefix(self, prefix, lenght):			
		self.prefix = prefix
		self.lenght = lenght

################################################

#class of AS PATH
class AsPath():				

	#list of instances of class As
	def __init__(self):	
		self.path = []				


	#prepending an AS to the path
	def Prepend(self, AS):				
		self.path = [AS] + self.path
	
	def Copy(self):
		as_temp = AsPath()
		
		for elem in self.path:
			as_temp.Postpend(elem)

		return as_temp

	#postpendign an AS to the path
	def Postpend(self, AS):				
		self.path = self.path + [AS]
		
	#returns originating AS number
	def GetAS0(self):				
		return self.path[len(self.path)-1]

	#returns integer originating AS number
	def GetIntAS0(self):				
		temp = self.GetAS0()
		return temp

	#removes aggregated AS nubmers in AS Path
	def RemoveAggregate(self):			

		i=0
		while i < len(self.path):
			if self.path[i] == '{':
				break
			
			i = i+1
		
		else:
			i = len(self.path)
		
		self.path[i:] = []

	#return string of complete AS Path
	def ReturnString(self):				

		temp = ''

		for elem in self.path:
			temp = temp + str(elem) + ' '

		temp = temp[:-1]
		return temp

	#removes double ASes in AS Path
	def RemoveDouble(self):				
		path_temp = []
		as_temp_list = []
		
		for elem in self.path:
			if elem not in as_temp_list:
				as_temp_list.append( elem )
				path_temp.append(elem)

		self.path = path_temp

#Finds changed links between this path (path in this instance of AsPath) 
#and of argument AS Path (newpath). Returns #dictionary of reputation 
#increment due to changed path. Dictionary is in form:

#key   = int AS num
#value = float Reputation increment

#example:

#oldpath		1 2 3 4 5
#newpath		7 8 3 4 5

#old links	1-2	2-3	3-4	4-5
#newlinks	7-8	8-3	3-4	4-5

#changes		1 one change	2 two changed	3 one change

#repinc		1: 0.25, 2: 0.5, 3: 0.25

	def FindLinksChanged(self, newpath):		
		i = 0
		j = 0
		l = 0
		r = 0
		preserved = 0
		repinctemp = {}
		counterrep = 0

		while i < (len(self.path)-1):

			l = int(self.path[i])
			r = int(self.path[i+1])
			j = 0
			preserved = 0

			while j < (len(newpath.path)-1):

				l2 = int(newpath.path[j])
				r2 = int(newpath.path[j+1])

				if l2 == l:
					if r2 == r:
						preserved = 1
						break
				j = j+1

			if preserved != 1:
				if (repinctemp.has_key(l))==False:
					repinctemp[l] = 1
					counterrep = counterrep+1
				else:
					repinctemp[l] = repinctemp[l]+1
					counterrep = counterrep+1

				if (repinctemp.has_key(r))==False:
					repinctemp[r] = 1
					counterrep = counterrep+1
				else:
					repinctemp[r] = repinctemp[r]+1
					counterrep = counterrep+1

			i = i+1

		for elem in repinctemp.keys():
			repinctemp[elem] = float(repinctemp[elem])/counterrep

		return repinctemp			

#makes As path in this instance from data from bgpdump (argument data)
#it's recommended to call methods RemoveDouble and RemoveAggregate after 
#calling method MakePath		

	def MakePath(self, data):		
		self.path = []

		for seg in data.segments:
			if seg.type == bgp.AS_SET:
				self.path.append('{')
				for elem in seg.path:
					self.path.append(int(elem))
				self.path.append('}')

			elif seg.type == bgp.AS_SEQUENCE:
				for elem in seg.path:
					self.path.append(int(elem))

			else:
				self.path.append('{')
				for elem in seg.path:
					self.path.append(int(elem))
				self.path.append('}')

################################################

class PrefixPath():

	def __init__(self, selectedAS, gama, delta, debug):

		#used for storing information about paths for different 
		#prefix-nexthop pairs
		self.prefpath = {}
		
		#used for counting number of prefixes passed through ASes
		self.prefnum = {}	
		
		#used for storing of reputation
		self.rep = {}		
		
		#used for storing reputation increment for current window of observation
		self.repinc = {}	

		#list for collecting reputation history for graph drawing
		self.selectedAS_rep_history = []

		self.selectedAS = selectedAS

		#used for calculating time when drawing graph
		self.time_start	= 0	 

		self.gama = gama
		self.delta = delta

		#Used for debuging (set in config.ini)
		self.debug = debug

#Writes reputations of ASes into output file. 
#This method is usualy called at the end of each window.
#Argument is output file name
#Format of output file is:
#
# Order num.: 1		AS: 1584	Reputation: 0.0003464
# Order num.: 2		AS: 8546	Reputation: 0.0005893
# Order num.: 3		AS: 12384	Reputation: 0.0042365
#   .
#   .
#   .
# Order num.: 25364	AS: 2584	Reputation: 0.9812358
#
#Lower order number means better reputation
#Lower reputation value means better reputation

	def FileWriteRep(self, filename):

		f1 = open(filename, 'w')

		cnt = 1
		reporder = 100000

		for key, value in sorted(self.rep.iteritems(), key=lambda (k,v): (v,k)):
			f1.write("Order num.: %s     \tAS %s:           \t Reputation: %s\n" 
					% (cnt, key, value) )

			if key==4761:
				reporder = cnt			

			cnt = cnt+1

		f1.close()


		pos = 100.0		

		try:
			pos=(100.0*reporder)/(cnt-1)

		except ZeroDivisionError:
			pass

#########################################
#					#
#					#
#	REPUTATION CALCULATION		#
#					#
#					#
#########################################

	def WinCalc(self, window_stop):
		
		for elem in self.repinc.keys():
			if elem in self.prefnum:
				self.repinc[elem] = (math.exp( float(-1)* self.delta / 
							(self.repinc[elem] / ( 1 + self.prefnum[elem]))))
			else:
				self.repinc[elem] = math.exp( (float(-1)* self.delta / 
											(self.repinc[elem])) )
		#multiply current reputation by gamma
		for elem in self.rep.keys():
			self.rep[elem] = (1-self.gama) * self.rep[elem]

		#if there was an increment in reputation, multiply it by
		#gamma and than add it to old reputation 
		for elem in self.repinc.keys():
			if elem in self.rep.keys():
				self.rep[elem] = self.rep[elem] + self.gama * self.repinc[elem]
			else:
				self.rep[elem] = self.gama * self.repinc[elem]
		
		#new window should start with zero values for reputation increment
		self.repinc = {}		

		#save values for graph (time[string], rep1, rep2,...)
		t = formatMinutes( (window_stop - self.time_start) )
		
		if len( self.selectedAS_rep_history ):
			if self.selectedAS_rep_history[-1][0] == t:
				return		
		
		tpl = (t,)
		
		for tmp_as in self.selectedAS:
			if tmp_as in self.rep.keys():
				tpl = tpl + ( self.rep[tmp_as]*100,)
			else:
				tpl = tpl + ( 0, )

		self.selectedAS_rep_history.append( tpl )
		
#Takes increment in reputation for every AS Path changed as argument 
#(repinctemp) and puts it in dictionary repinc
#Dictionary repinc stores cumulative rerputation increments 
#for current window of observation

	#repinctemp bringes reputation increments due to current path change
	def RepIncrement(self, repinctemp):	

		for elem in repinctemp.keys():
			if elem in self.repinc.keys():
				self.repinc[elem] = self.repinc[elem] + repinctemp[elem]
			else:
				self.repinc[elem] = repinctemp[elem]

#Counts occurances of different prefixes for ASes in RIB
#and puts the number in dictionary prefnum
#key: int AS num
#value:	number of occurances
		
	def PrefNumPut(self, path):

		for elem in path.path:
			if self.prefnum.has_key(elem):
				self.prefnum[elem] += 1 
			else:
				self.prefnum[elem] = 1
		
#Reads preparsed RIB file
#Takes filename

	def ReadRIB(self, in_time_start, filename):

		self.time_start = in_time_start

		#used for printing progress 
		current_ip = '0'

		f1 = open(filename, 'r')

		debug_counter = 0
		
		for line in f1:
			if self.debug:
				debug_counter += 1
				if debug_counter > 100000:
					return
			
			line = line[:-1]

			if line[0]=='P':
				line = line[8:]
				temp = line[:line.find('/')]
				
				#------------------ispis----------------
				temp_ip = temp.split('.')
				if temp_ip[0] != current_ip:
					Print.out( "%s.*.*.*" % temp_ip[0] )
					current_ip = temp_ip[0]
				
				try:
					pref=socket.inet_aton(temp)
				except:
					break

				temp = line[line.find('/')+1:]
				leng = int(temp)


			elif line[0]=='F':
				line = line[6:]

				#next-hop is left in pure string format due to simplicity
				source = line					
		
				
			elif line[0]=='A':
		
				line = line[9:]

				aspath = AsPath()

				pom = line.find('{')
				if pom!=-1:
					line = line[:pom-1]

				cols = line.split()
				
				for elem in cols:
					try:
						el = int(elem)
						aspath.Postpend(el)
					except:
						pass
				
				aspath.RemoveDouble()

				#tuple is used for speed gain
				temp_prefix = (pref, leng, source)	

#Puts key: (prefix, lenght, nexthop) | value: path   in dictionary prefpath

				if (self.prefpath.has_key(temp_prefix))==False:				
					self.prefpath[temp_prefix] = aspath	
					self.PrefNumPut(aspath)


				#RIBs shouldn't have double paths for same prefixes
				#in case they do, just use following code

#				else:
#					self.prefpath[temp_prefix] = aspath
#					print "\n\n!!!!!!      \tDOUBLE PATH IN RIB\t    !!!!!!\n\n"

#Parse updates announced
#Every update for new prefix-nexthop combination is put in dictionary prefpath
#Every reannounced prefix-nexthop combination changes puts new AS Path in value
#for this prefix-nexthop
#If the AS Path is changed, FindLinksChanged and RepIncrement methods 
#calculate and increment rerputation in dictionary #repinc

	def ParseUpdateAnnounced(self, data, source, path):

		for elem in data:
							
			if self.prefpath.has_key((elem.prefix, elem.len, source)):
				oldpath = self.prefpath.pop((elem.prefix, elem.len, source))
				self.prefpath[(elem.prefix, elem.len, source)] = path

				#print "\n-------------------"
				#print "Prefix: " + str(socket.inet_ntoa(elem.prefix)) + "/" 
					#+ str(elem.len) + "      \tNext Hop: " + str(source)
				#print "OLD AS-PATH: " + oldpath.ReturnString()
				#print "NEW AS-PATH: " + path.ReturnString()

				#founds increment for current change
				repinctemp = oldpath.FindLinksChanged(path)
				
				#increments reputation for current win.	
				self.RepIncrement(repinctemp)			
			else:
				self.prefpath[(elem.prefix, elem.len, source)] = path

				#print "\n-------------------"
				#print "FIRST OCCURENCE OF PREFIX FROM THIS PEER: "
				#print "Prefix: " + str(socket.inet_ntoa(elem.prefix)) + "/" + 
					#str(elem.len) + "      \tNext Hop: " + str(source)
				#print "AS-PATH: " + path.ReturnString()

#Parse updates withdrawn
#Every withdrawn update deletes affected routes from dictionary prefpath
#It rises reputation for all ases in withdrawn path

	def ParseUpdateWithdrawn(self, data, source):

		for elem in data:

			if self.prefpath.has_key((elem.prefix, elem.len, source)):

				oldpath = self.prefpath.pop((elem.prefix, elem.len, source))
				
				#if path is withdrawn - new path is empty - 
				#just used for calculation
				path = AsPath()		

				#print "\n-------------------"
				#print "WITHDRAWN Prefix: " + str(socket.inet_ntoa(elem.prefix))
					# + "/" + str(elem.len) + "      \tNext Hop: " + str(source)
				#print "WITHDRAWN AS-PATH: " + oldpath.ReturnString()

				repinctemp = oldpath.FindLinksChanged(path)
				self.RepIncrement(repinctemp)

################################################
################################################
################################################
################################################

class PrefixAS0Binding():

	def __init__(self, selectedAS, alpha, debug):

		self.prefas0 = {}
		self.asPrefRep = {}
		self.asRep = {}
		
		#list for collecting reputation history for graph drawing
		self.selectedAS_rep_history = []
		
		#list AS's that will be drawn in graph 
		self.selectedAS = selectedAS
		
		self.alpha = alpha
		
		#for graph time calculation, it is set to time_start
		self.time_start = 0   
		
		#Used for debuging (set in config.ini)
		self.debug = debug

#########################
	
	def ReadRIB(self, time, filename):

		self.time_start = time

		#this is used for printing progress
		current_ip = '0'

		f1 = open(filename, 'r')
		
		debug_count = 0
		
		for line in f1:
			if self.debug:
				debug_count += 1
				if debug_count > 100000:
					return
			
			line = line[:-1]

			if line[0]=='P':
				line = line[8:]
				temp = line[:line.find('/')]
				
				#------------------ispis----------------
				temp_ip = temp.split('.')
				if temp_ip[0] != current_ip:
					Print.out( "%s.*.*.*" % temp_ip[0] )
					current_ip = temp_ip[0]
				
				try:
					pref=socket.inet_aton(temp)
				except:
					break

				temp = line[line.find('/')+1:]
				leng = int(temp)
	

			elif line[0]=='F':
				line = line[6:]

				#next-hop is left in pure string format due to simplicity
				source = line	


			elif line[0]=='A':
		
				line = line[9:]

				aspath = AsPath()

				pom = line.find('{')
				if pom!=-1:
					line = line[:pom-1]

				cols = line.split()
				
				for elem in cols:
					try:
						el = int(elem)
						aspath.Postpend(el)
					except:
						pass
				
				aspath.RemoveDouble()

				as0 = aspath.GetIntAS0()

###########

				if (self.prefas0.has_key((pref, leng)))==False:
									
					temp_prefix = (pref, leng)

					temp_as_prefix = AsPrefix(as0)
					temp_as_prefix.SetTimeOfActivation(time)
					temp_as_prefix.InsertSource(source) 

					self.prefas0[temp_prefix] = [temp_as_prefix]

				else:
					foundAS=False

					for ases in self.prefas0[(pref, leng)]:
						
						if as0 == ases:
							
							foundAS = True

							ases.InsertSource(source)
							ases.SetTimeOfActivation(time)	

						else:

							ases.RemoveSource(source)
							ases.CheckAndDeactivate(time)  
	 
						
					if foundAS == False:
					
						temp_as_prefix = AsPrefix(as0)
						temp_as_prefix.SetTimeOfActivation(time)
						temp_as_prefix.InsertSource(source)
						
						self.prefas0[temp_prefix].append(temp_as_prefix)

#########################

#########################

	def ParseUpdateAnnounced(self, data, as0, source, time):

		for elem in data:	

			if (self.prefas0.has_key((elem.prefix, elem.len)))==False:
									
				temp_prefix = (elem.prefix, elem.len)

				temp_as_prefix = AsPrefix(as0)
				temp_as_prefix.SetTimeOfActivation(time)
				temp_as_prefix.InsertSource(source) 

				self.prefas0[temp_prefix] = [temp_as_prefix]	

			else:
				foundAS=False

				for ases in self.prefas0[(elem.prefix, elem.len)]:
						
					if as0 == ases:
							
						foundAS = True

						ases.InsertSource(source)
						ases.SetTimeOfActivation(time)	

					else:

						ases.RemoveSource(source)
						ases.CheckAndDeactivate(time)  
	 
						
				if foundAS == False:
					
					temp_as_prefix = AsPrefix(as0)
					temp_as_prefix.SetTimeOfActivation(time)
					temp_as_prefix.InsertSource(source)
						
					self.prefas0[(elem.prefix, elem.len)].append(temp_as_prefix)

					#print "Double AS0"

					#print "\n" + socket.inet_ntoa(elem.prefix) + 
						#"/" + str(elem.len)
					#for member in self.prefas0[(elem.prefix, elem.len)]:
						#print ""
						#print str(member.AS)
					#print "\n--------------------\n\n"

#########################

	def ParseUpdateWithdrawn(self, data, source, time):

		for elem in data:		
			if self.prefas0.has_key((elem.prefix, elem.len)):
				for ases in self.prefas0[(elem.prefix, elem.len)]:
					ases.RemoveSource(source)
					ases.CheckAndDeactivate(time)

#########################

	def FileWritePrefInf(self, filename):

		f1 = open(filename, 'w')

		for elem in self.prefas0.keys():

			f1.write("\n-----------------------------------\n")
			f1.write("Prefix:  " + socket.inet_ntoa(elem[0]) 
					+ "/" + str(elem[1]) + "\n")
		
			for el in self.prefas0[elem]:
				f1.write("\nSource AS:               " + str(el))
				f1.write("\nTime of Activation:      "+str(el.timeOfActivation))
				f1.write("\nTotal Active Time:       " + str(el.totalTime))
				f1.write("\nRepetition:              " + str(el.repetition))
				f1.write("\nUpdate from Router(s): ")
	
				for e in el.listOfRouters:
					f1.write("\n                             " + str(e))
					f1.write("\n")

				f1.write("\n")

		f1.close()

#########################

	def FileWriteRepInf(self, filename):

		f1 = open(filename, 'w')

		for elem in self.asPrefRep.keys():
	
			f1.write("\n-----------------------------------\n")
			f1.write("    AS-Num:    " + str(elem) + "\n\n")

			f1.write("    Number of Prefixes                " + 
					str(self.asPrefRep[elem].numberPref) + "\n")

			try:
				f1.write("    Total Active Percentage Time      " + 
						str(self.asPrefRep[elem].totalActiveSum/
							self.asPrefRep[elem].numberPref) + "\n")

			except ZeroDivisionError:
				f1.write("    Total Active Percentage Time     " + "0.0" + "\n")

			try:
				f1.write("    Average Active Percentage Time    " + 
						str( (self.asPrefRep[elem].totalActiveSumRep/
							self.asPrefRep[elem].numberPref) ) + "\n")

			except ZeroDivisionError:
				f1.write("    Average Active Percentage Time   " + "0.0" + "\n")

		f1.close()

#########################

	def FileWriteRep(self, filename):

		f1 = open(filename, 'w')

		cnt = 1

		for key,value in sorted(self.asRep.iteritems(), key=lambda (k,v):(v,k)):

			f1.write( "Order num.: %s     \tAS %s:           \tReputation: %s\n"
					 % (cnt, key, value) )
			cnt = cnt+1

			if key == self.selectedAS:
				self.selectedAS_rep_history[self.window_time] = value
				Print.out( str("selected as:", self.selectedAS,"   time:", 
					self.window_time, "  rep:", value) )


		f1.close()		

#########################

	def WinCalculation(self, window_stop, time_window):
		
		self.asPrefRep = {}

		for elem in self.prefas0.keys():
			for el in self.prefas0[elem]:
				if len(el.listOfRouters) != 0:		
					
					#deactivate currently active prefix-AS0 bindings
					#but make those prefixes active at the beggining 
					#of next window			
					el.DeactivateEndWin(window_stop)		
		
		for elem in self.prefas0.keys():

			for el in self.prefas0[elem]:
				temp_as0 = el
			
				if (self.asPrefRep.has_key(temp_as0))==False:
					tempAsPrefRep = AsPrefixRep()
					tempAsPrefRep.IncreaseSum(el.TimePercentage(time_window))
					tempAsPrefRep.IncreaseSumRep(
											el.TimePercentageRep(time_window))

					self.asPrefRep[temp_as0]=tempAsPrefRep

				else:
					tempAsPrefRep = self.asPrefRep[temp_as0]
					tempAsPrefRep.IncreaseSum(el.TimePercentage(time_window))
					tempAsPrefRep.IncreaseSumRep(
											el.TimePercentageRep(time_window))

					self.asPrefRep[temp_as0]=tempAsPrefRep

		for elem in self.prefas0.keys():
			for el in self.prefas0[elem]:
				#next window starts with measurement of time from 0
				el.totalTime = 0	

####

		for elemkey in self.asRep.keys():
			if elemkey in self.asPrefRep:
				self.asRep[elemkey] = (self.asRep[elemkey]*(1-self.alpha) + 
					(self.asPrefRep[elemkey].GetRep())*self.alpha)
			else:
				self.asRep[elemkey] = self.asRep[elemkey]*(1-self.alpha)
	

		for elemkey in self.asPrefRep.keys():
			if self.asRep.has_key(elemkey)==False:
				self.asRep[elemkey] =self.asPrefRep[elemkey].GetRep()*self.alpha

		#save data for the graph, (time[string], rep1, rep2,...)
		t = formatMinutes( (window_stop - self.time_start) )
		
		if len( self.selectedAS_rep_history ):
			if self.selectedAS_rep_history[-1][0] == t:
				return
		
		tpl = (t,)
		
		for tmp_as in self.selectedAS:
			if tmp_as in self.asRep.keys():
				tpl = tpl + ( self.asRep[tmp_as]*100,)
			else:
				tpl = tpl + ( 0, )

		self.selectedAS_rep_history.append( tpl )

#################################################
#						#
#################################################

"""
This class is used for storing and manipulating of data about ASes originating 
prefixes. Those ASes could either be real originator of prefixes or aggregator 
of prefixes. Instances of this class are put in list for EACH prefix. 
Usually, each prefix would have list of its originating ASes consisting of just 
one list element, thus representing only one originating AS. In some occasions 
that list can contain more instances of AsPrefix class meaning that particular 
prefix has or had more ASes originating it. It doesn't necesserly means it was 
originating by more then one AS at the same time. In case it was, it could 
either be intentionally (usually for aggregated prefixes) or it could be caused 
by unintentional or intentional error.

The list containing instances of AsPrefix class is put as value in dictionary 
while key is represented by a 2-elem tupple consisting of prefix and prefix 
lenght (prefix, lenght). Prefix is in standard prefix form (NOT STRING) and 
lenght of prefix is integer. Reason why keys of dictionary is not made of 
instances of Prefix class is easy hash searching.

Class AsPrefix has following attributes:

	AS				int AS number
	
	timeOfActivation	absolute time when prefix was activated; 
						for non-active prefixes it's 0
						
	totalTime		total time in seconds the prefix HAD been active
	
	listOfRouters	list containing ip address of host peering routers currently
					announcing this prefix
					
	repetition		counts the number this prefix HAS become active after 
					being inactive


Absolute time is time in seconds from the beggining of the world, or from 
00:00 1 Januray 1970 preciselly.

Because totalTime counts time the prefix HAD been active, it doesn't include 
time from last activation nor currently active prefixes. So, if the prefix was 
activated just once and not deactivated it can be 0. It is increased every time
prefix becomes inactive or at the end of the observation window. If the 
observation window finishes while the prefix is still being in active state, 
totalTime is increased by the time from last activation and timeOfActivation 
is set to the time of begining of next window. In that case the repetition 
counter is set to 1 to represent the first activation of the prefix in next 
window. The listOfRouters contains list of ip addresses of routers in string 
format because it's usually very small (it contains just a few peering routers). 
I rather use IPes of peering router instead of neighboring ASes because same AS
can have more peering routers and some peers can also be in our own AS. When the
listOfRouters is empty, the prefix is INACTIVE. When it's NOT empty, the prefix
is ACTIVE. When the last router announcing prefix is removed from the list, the 
prefix becomes inactive and totalTime is increased. When a router is added in 
empty list, the prefix becomes active, timeOfActivation is set and repetition 
counter is increased.

Constructor simply creates instance of class with all 0 or empty values other 
than AS number. It implies that all other values have to be set indipendently 
imidiatelly after the creation of instance by manually calling the appropriate 
methods with requested data.


	SetTimeOfActivation	sets time of activation and increases repetition counter
	
	Deactivate		increases totalTime and sets timeOfActivation to 0
	
	DeactivateEndWin	same as Deactivate but it sets timeOfActivation to the 
				time of begining of next window; it also sets repetition counter
				to 1 thus representing first activation of the prefix in 
				next window
				
	InsertSource		inserts new announcing router in list of routers 
						announcing the prefix
	RemoveSource		removes router formerlly announcing the prefix from 
						list of routers
	CheckAndDeactivate	checks if list of announcing routers is empty and the 
						prefix was active if so, it calls Deactivate to 
						set timers

"""

################################################

class AsPrefix(int):

	def __init__(self, AS):		#prima int broj AS-a
		self.AS = AS
		self.timeOfActivation = 0
		self.totalTime = 0
		self.listOfRouters = []
		self.repetition = 0

	def SetTimeOfActivation(self, time):
		if self.timeOfActivation==0:
			self.timeOfActivation = time
			self.repetition = self.repetition + 1

	def DeactivateEndWin(self, time):
		self.totalTime = self.totalTime + (time-self.timeOfActivation)	
		self.timeOfActivation = time
		self.repetition = 1

	def Deactivate(self, time):
		self.totalTime = self.totalTime + (time-self.timeOfActivation)	
		self.timeOfActivation = 0

	def InsertSource(self, routerid):
		if routerid in self.listOfRouters:
			pass
		else:
			self.listOfRouters.append(routerid)

	def RemoveSource(self, routerid):
		if routerid in self.listOfRouters:
			self.listOfRouters.remove(routerid)

	def CheckAndDeactivate(self, time):
		if len(self.listOfRouters)==0:
			if self.timeOfActivation != 0:
				self.Deactivate(time) 

	def TimePercentage(self, winTime):
		if self.totalTime != 0:
			return float(self.totalTime)/winTime
		else:
			return 0.0

	def TimePercentageRep(self, winTime):
		if self.totalTime != 0:
			return float(self.totalTime)/(winTime*self.repetition)
		else:
			return 0.0
	
	def CurrentTimePer(self, time, timeWinCur):
		if self.timeOfActivation!=0:

			return (self.totalTime + (time-self.timeOfActivation)) / timeWinCur
		else:
			return (self.totalTime) / timeWinCur

################################################

################################################

class AsPrefixRep():

	def __init__(self):
		self.numberPref = 0
		self.totalActiveSum = 0
		self.totalActiveSumRep = 0

	def IncreaseSum(self, inc):
		self.totalActiveSum = self.totalActiveSum + inc

		if inc != 0.0:
			self.numberPref += 1

	def IncreaseSumRep(self, inc):
		self.totalActiveSumRep = self.totalActiveSumRep + inc

	def GetRep (self):
		if self.numberPref != 0:
			return ((self.totalActiveSum + self.totalActiveSumRep) / 
				(2 * self.numberPref) )
		else:
			return 1

# ------------------------------------------------------------------------------
# ------------------------------------------------------------------------------
# ------------------------------------------------------------------------------
# ------------------------------------------------------------------------------
# ------------------------------------------------------------------------------
# ------------------------------------------------------------------------------
# ------------------------------------------------------------------------------
#for converting minutes to string for the graph

def formatMinutes( num ):
	num /= 60
	tmp_str = ""
	
	if min >= 60:
		if num / 60 < 10:
			tmp_str += "0"
					
		tmp_str += str ( int(num / 60) )
		tmp_str += ":"
		
		if num % 60 < 10:
			tmp_str += "0"
			
		tmp_str += str ( int(num % 60) )
	else:
		tmp_str += "00"
		tmp_str += ":"
		tmp_str += str ( int(num) )
	return tmp_str

#--------------------------------------------
#-------------------------------------------- 

class Print():
	"""
	Static class for controlling print outs to the console. It depends on
	verbose parameter.	
	"""
	
	level = 1
	
	@staticmethod
	def setVerboseLevel( num ):
		Print.level = num
	
	@staticmethod
	def out( string ):
		#for now its only 1 or 0, so we can put if
		if Print.level:
			print string
