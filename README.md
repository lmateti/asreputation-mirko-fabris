asreputation-luka-matetic
=========================

Changes of the AS reputation code written by Tomislav Dejdar and reworked Mirko Fabris done by Luka Matetic

Please follow these steps for a quick start with this program:

1. Download RIB and UPDATES data from a collector of choice.

2. To use the downloaded RIB, it must be parsed with zebra-dump-parser written in Pearl which
can be found in 3rdparty/RIB_Parser. This might take around four to six hours. 
The existing hardcoded name of an old RIB file in the program must be replaced with the name of a newly extracted RIB file. 
The hardcoded name is located at start of the zebra-dumb-parser.pl module. 
The newly extracted RIB file must also be put into the location of the module (3rdparty/RIB_Parser).

3. In "src" folder, there should be folders named "out", "out_links", "RIB" and "UP". 
If those folders don't exist, create new ones. Put the newly downloaded and extracted UPDATES data into the "UP" folder. 
Leave folders "out" and "out_links" empty. Program writes its output into these folders.

4. Zebra-dumb-parser will create a parsed RIB with an extension "parsed". 
The newly parsed RIB data must then be moved to "RIB" folder in src. 
In order to run the program, the path to the newly parsed RIB data must also be put into "config.ini". 
This can be done by replacing the existing RIB/NameOfOldRIB.parsed.

5. There must be at least one autonomous system selected by its autonomous system number if using the 
pref analysis type or at least two autonomous systems selected by their autonomous system number if using the 
link analysis type. In order to get good results, set time_start parameter to match the name of the RIB
and UPDATES data (notice that UPDATES data must also be taken at the same time).

6. In order to start the program, module start.py must be ran using a Python 2.7 interpreter. 