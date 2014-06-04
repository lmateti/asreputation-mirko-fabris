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

from pybgpdump import BGPDump
import socket
import struct
import sys
import time
import os.path
import os
import glob
import core
import ipaddr
import shutil
from pychart import *
from core import Print

class Analyzer:

    def __init__(self, time_start, time_window, time_limit, preparsed_RIB,
                 selectedAS, text_output, graph_x, graph_y, 
		 updates_input, linksRep_output, prefInf_output, prefPerc_output,
		 prefRep_output, rib_output, debug):
        
	#Input UPDATE folder path
	self.updates_dir = updates_input
		
	#Output folder paths and filenames
	self.text_output_prefixSourceInformation = prefInf_output
	self.text_output_prefixPercentage = prefPerc_output
	self.text_output_prefixReputation = prefRep_output
	self.text_output_prefixRIB = rib_output
		
	self.text_output_linksReputation = linksRep_output
		
        #duration of window (in seconds)
        self.time_win = time_window
        self.time_start = time_start
        self.time_limit = time_limit
               
        self.preparsed_RIB = preparsed_RIB        

        self.selectedAS = selectedAS
        
        self.text_output = text_output
                
        self.size_x = graph_x
        self.size_y = graph_y

        #directory containing UPDATE dumps
        self.file_list = glob.glob( self.updates_dir + "/*.*")                         
        self.file_list.sort()
        
        #Debuging mode
        self.debug = debug
    
    #---------------------------------------------------------------------------
    #---------------------------------------------------------------------------
    #---------------------------------------------------------------------------
    def analyzeLinkBindings(self, gama, delta):    
        
        links = core.PrefixPath( self.selectedAS, gama, delta, self.debug )
        
        print "Parsing RIB..."
        links.ReadRIB(self.time_start, self.preparsed_RIB)
        print "Finished parsing RIB"

        
        #counter for UPDATE dumps   
        file_list_counter=0
        
        current_window = 1
        
        #time of termination of first window
        time_stop = self.time_start + self.time_win
        
        temp_time = 0
        
        #so we know the real time of the first update
        time_first_update = 0
        
        #dump list contains partially parsed UPDATE dumps
        self.dump_list=[]
        
        #fill up dump list
        for file_name in self.file_list:
            self.dump_list.append(BGPDump(file_name))    
        
        """
        Main iteration loop
            iterates through all dump files in designated directory. 
            It collects information about prefixes (origin of prefix - AS0; 
            time of last activation of prefix; total time of prefix active state 
            in current window; list of neighbouring routers sender of update 
            for this prefix - only routers currently announcing this prefix 
            are presented in the list thus empty list makes prefix currently 
            inactive setting it time of activation to 0; repetition - counting 
            number of times prefix have become activated after being inactive.
        """
        for d in self.dump_list:
            Print.out(str( "Parsing file " + self.file_list[file_list_counter]))
            file_list_counter += 1
        
            try:
                for mrth,bgph,bgpm in d:
                    #time of each update dump
                    temp_time = mrth.ts        
                    
                    #if this is the first file, remember timestamp
                    if file_list_counter == 1:
                        time_first_update = temp_time
                    
                    if (temp_time)>=(time_stop):
                            
                        links.WinCalc( time_stop )
                        if self.text_output:
                            links.FileWriteRep(self.text_output_linksReputation + 
                                               '_' + str(current_window))
                        
                        time_stop = time_stop + self.time_win
                        
                        
                        Print.out( str ("Finished computation of window " + 
                                str(current_window) + ".") )
                        current_window +=1
        
                    as_temp = core.AsPath()        #AS Path
        
                    for elem in bgpm.data.attributes:
                        if elem.type==2:
        
                            as_temp.MakePath(elem.data)
                            as_temp.RemoveAggregate()
                            as_temp.RemoveDouble()
        
                    #next hop address
                    temp_source =socket.inet_ntoa(struct.pack('>L',bgph.src_ip))        
        
                    if bgpm.data.withdrawn:
                        links.ParseUpdateWithdrawn(bgpm.data.withdrawn, 
                                                   temp_source)
                        
                    if bgpm.data.announced:
                        links.ParseUpdateAnnounced(bgpm.data.announced, 
                                                   temp_source,
                                                   as_temp)
        
        
            except AttributeError:
                #this is intentional, cause there is no exception handling
                #so write it out cause it might be relevant 
                print "AttributeError in parsing update dump"
                
        
            Print.out(str("Parsed file " + self.file_list[file_list_counter-1]))
        
        
            if self.time_limit:
                if temp_time >= time_first_update + self.time_limit:
                    Print.out( "Time limit hit." )
                    break
        
        calc = 1.0*(self.time_win - (time_stop-temp_time)) / self.time_win
        #theta = 0.25
        if calc > 0.25:
            links.WinCalc( time_stop )
            if self.text_output:
                links.FileWriteRep(self.text_output_linksReputation + '_' +str(current_window))
        
        print "Finished computation of last window."
        
        self.drawGraph( links.selectedAS_rep_history, 
                        links.selectedAS, 
                        "links" )
    



    ############################################################################
    ############################################################################
    ############################################################################
    ############################################################################
    def drawGraph(self, data, selectedAS, name):
        theme.get_options()
        theme.use_color = True
        theme.reinitialize()
        
        #we set scale factor to 2 so that letters are bigger and more clearer
        #thats why later we need to cut size in half later on
        theme.scale_factor = 2
        

        #find max value, so we can scale graph 
        max_value = 0
        size = len( selectedAS )
        for value in data:
            for i in xrange(1, size+1):
                if value[i] > max_value:
                    max_value = value[i]
        
        
        
        name_str = ""
        
        for a in selectedAS:
            name_str += str(a)
            name_str += "_"
             
        name_str += name + '_rep.png'
        
        canvas1 = canvas.init( fname=name_str, format="png" )
        
        chart_object.set_defaults( area.T, 
                                   size = (self.size_x/2, self.size_y/2), 
                                   y_range = (0, max_value),
                                   x_coord = category_coord.T(data, 0))
        
        chart_object.set_defaults(bar_plot.T, data = data)
        
        
        x_axis=axis.X(label="Time(hour:minute)", format="/a-30{}%s")
        y_axis=axis.Y(label="Reputation" )
        
        interval = 10
        
        if max_value < 91:
                            
            if max_value >= 10:
                interval = int( max_value / 10 )
                
            else: 
                interval = 0
                
        else:
            interval = 10
        

        ar = area.T(x_axis = x_axis,
                    y_axis = y_axis, 
                    y_grid_interval = interval
                    )
        

        count = 0
        max_count = len( selectedAS )
        print selectedAS
        for tmpAS in selectedAS:
            if count == 0:
                ar.add_plot(bar_plot.T(label=str(tmpAS),
                                       line_style=line_style.blue, 
                                       cluster=(count, max_count) ))
            else:
                ar.add_plot(bar_plot.T(label=str(tmpAS), 
                                       cluster=(count, max_count), 
                                       hcol=count+1 ))
            count+=1
    
        ar.draw(canvas1)
        
        canvas1.close()
    
        print "Finished generating graph: ", name_str


    #---------------------------------------------------------------------------
    #---------------------------------------------------------------------------
    #---------------------------------------------------------------------------
    def analyzePrefBindings(self, alpha):    
     
        bindings = core.PrefixAS0Binding( self.selectedAS, alpha, self.debug )        
        print "Parsing RIB..."
        bindings.ReadRIB(self.time_start, self.preparsed_RIB)
        print "Finished parsing RIB"
        
        
        if self.text_output:
            bindings.FileWritePrefInf(self.text_output_prefixRIB)
    
        #counter for UPDATE dumps   
        file_list_counter=0
        
        current_window = 1
        
        #time of termination of first window
        time_stop = self.time_start + self.time_win
        
        temp_time = 0
        
        #so we remember the real time of first update
        time_first_update = 0    
        
        #dump list contains partially parsed UPDATE dumps
        self.dump_list=[]
        
        #fill up dump list
        for file_name in self.file_list:
            self.dump_list.append(BGPDump(file_name))    
        
        """
        Main iteration loop
            iterates through all dump files in designated directory. It collects 
            information about prefixes (origin of prefix - AS0; time of last 
            activation of prefix; total time of prefix active state in current 
            window;list of neighbouring routers sender of update for this prefix 
            - only routers currently announcing this prefix are presented in the 
            list thus empty list makes prefix currently inactive setting it time 
            of activation to 0; repetition -counting number of times prefix have 
            become activated after being inactive.
        """
        
        for d in self.dump_list:
            Print.out(str("Parsing file " + self.file_list[file_list_counter]))
            file_list_counter += 1
        
            try:
                for mrth,bgph,bgpm in d:
                    #time of each update dump
                    temp_time = mrth.ts        
        
                    #if this is the first file, remember timestamp
                    if file_list_counter == 1:
                        time_first_update = temp_time
        
                    if (temp_time)>=(time_stop):
                        
                        bindings.WinCalculation(time_stop, self.time_win)
                        if self.text_output:
                            bindings.FileWritePrefInf( self.text_output_prefixSourceInformation 
													+ '_' + str(current_window))
                            bindings.FileWriteRepInf( self.text_output_prefixPercentage 
                                                    + '_' + str(current_window))
                            bindings.FileWriteRep( self.text_output_prefixReputation 
                                                   + '_' + str(current_window))
        
                        time_stop = time_stop + self.time_win
        
                        current_window +=1
                        Print.out(str( ("Finished computing of window " + 
                                    str(current_window-1) + ".")))
        
        
        
                    as_temp = []
        
                    for elem in bgpm.data.attributes:
                        if elem.type==2:
        
                            as_temp = core.AsPath()
                            as_temp.MakePath(elem.data)
                            as_temp.RemoveAggregate()
                            as_temp.RemoveDouble()
        
        
                    temp_source =socket.inet_ntoa(struct.pack('>L',bgph.src_ip))
        
                    if bgpm.data.withdrawn:
                        bindings.ParseUpdateWithdrawn( bgpm.data.withdrawn, 
                                                      temp_source, 
                                                      temp_time )
                        
                    if bgpm.data.announced:
                        temp_as0 = as_temp.GetIntAS0()
                        bindings.ParseUpdateAnnounced( bgpm.data.announced, 
                                                       temp_as0, 
                                                       temp_source, 
                                                       temp_time )
        
        
        
            except AttributeError:
                #see comment in the other function 
                print "AttributeError in parsing update dump"
        
        
            if self.time_limit:
                if temp_time >= time_first_update + self.time_limit:
                    Print.out( "Time limit hit." )
                    break
        
        #decreases window time by time left from last UPDATE to STOP time
        tmp_time_win = self.time_win - (time_stop-temp_time)
        
        #changes stop time to time of last UPDATE
        time_stop = temp_time                
        
        bindings.WinCalculation(time_stop, tmp_time_win)
        if self.text_output:
            bindings.FileWritePrefInf(self.text_output_prefixSourceInformation + '_' + str(current_window))
            bindings.FileWriteRepInf(self.text_output_prefixPercentage + '_' + str(current_window))
            bindings.FileWriteRep(self.text_output_prefixReputation + '_' + str(current_window))
        
        print "Finished computing of last window"
    
    
        self.drawGraph( bindings.selectedAS_rep_history, 
                        bindings.selectedAS, 
                        "pref" )
    

        
        
    

