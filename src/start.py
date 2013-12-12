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

import sys
sys.path.insert(0,'./lib')
import time
from analyzer import Analyzer
import ConfigParser
from core import Print
import cProfile
import pstats


#-----------------------------config file constants-----------------------------
CONFIG_FILENAME = 'config.ini'
SECTION_NAME = 'Variables'

TIME_WINDOW = 'time_window'
TIME_LIMIT = 'time_limit'
RIB = 'rib'
TEXT_OUTPUT = 'text_output'
ALPHA = 'alpha'
GAMA = 'gama'
DELTA = 'delta'
TIME_START = 'time_start'
SELECTED_AS = 'selected_as'
GRAPH_X = 'graph_x'
GRAPH_Y = 'graph_y'
ANALYSIS = 'analysis'
ANALYSIS_PREF = 'pref'
ANALYSIS_LINK = 'link'
VERBOSE = 'verbose'
PROFILING = 'profiling'


    
try:
    config = ConfigParser.ConfigParser()    
    config.read( CONFIG_FILENAME )
    
    #in minutes, so we need to convert it to seconds
    time_window = int( config.get( SECTION_NAME, TIME_WINDOW )) * 60    
    
    #limit of update files that is going to be parsed 
    time_limit = int( config.get( SECTION_NAME, TIME_LIMIT )) * 60
    
    #verbose console output or no 
    verbose = int( config.get( SECTION_NAME, VERBOSE ))
    if verbose != 0 and verbose != 1:
        raise Exception("Verbose option in config file wrong, must be 0 or 1!")
    Print.setVerboseLevel(verbose)
    
    #preparsed RIB table path
    preparsed_RIB = config.get( SECTION_NAME, RIB )
    
    #should there be text output
    text_output = int( config.get( SECTION_NAME, TEXT_OUTPUT ) ) 
            
    #parameters for calculations
    alpha = float( config.get(SECTION_NAME, ALPHA) ) 
    gama = float( config.get(SECTION_NAME, GAMA) )
    delta = float( config.get(SECTION_NAME, DELTA) )
    
    #start time for parsing
    time_string = config.get(SECTION_NAME, TIME_START)
    time_start= time.mktime(time.strptime( time_string, "%d %m %y %H %M"))
    
    #AS's selected to be drawn in the graph
    tmp_as_list = config.get(SECTION_NAME, SELECTED_AS).split(',')
    selectedAS = [] 
    for as_num in tmp_as_list:
        selectedAS.append( int(as_num ))
    
    #size of graph picture, in pixels
    size_x = int( config.get(SECTION_NAME,GRAPH_X) )
    size_y = int( config.get(SECTION_NAME,GRAPH_Y) )
    
    
    #type of analysis    
    analysis_str = config.get(SECTION_NAME, ANALYSIS).split(',')
    analysis_list = []
    for opt in analysis_str:
        opt = opt.strip()
        if opt != ANALYSIS_LINK and opt != ANALYSIS_PREF:
            raise Exception("Wrong analysis option: %s" % opt)
        else:
            analysis_list.append(opt)
    
    #profiling
    profiling = int( config.get(SECTION_NAME, PROFILING ) )
    
    
    print "config loaded ok"
except:
    print "Error loading configuration from config.ini:\n---", sys.exc_info()[1]
    exit() 
    
    
    
def run():
    analyzer = Analyzer( time_start, time_window, time_limit, preparsed_RIB, 
                         selectedAS, text_output, size_x, size_y )
    
    
    #so we can calculate total time this program used
    t = time.time()
    
    
    
    #####################################################################
    for opt in analysis_list:
        if opt == ANALYSIS_LINK:
            analyzer.analyzeLinkBindings( gama, delta )
        if opt == ANALYSIS_PREF:
            analyzer.analyzePrefBindings(alpha)
    #####################################################################

    
    print "Total time spent: %.2f  minutes" % ((time.time() - t)/60)


if profiling:
    cProfile.run('run()', 'profiling')
    p = pstats.Stats('profiling')
    p.sort_stats('time').print_stats(10)
else:
    run()
