#usage: $python3 parse_annotations.py <dir with all the .scv listed below>

import sys

annotation_files = \
        ['00166cab6b88.csv', '0017882b9a25.csv', '44650d56ccd3.csv',
         '50c7bf005639.csv', '70ee50183443.csv', '74c63b29d71d.csv',
         'd073d5018308.csv', 'ec1a5979f489.csv', 'ec1a59832811.csv',
         'f4f5d88f0a3c.csv']

def parse_annotation (filename):
    f = open (filename, 'r')
    l = f.readlines ()
    f.close ()
    for ind, line in enumerate (l):
        l[ind] = l[ind].rstrip ()
        l[ind] = l[ind].split (',')
        l[ind][2] = l[ind][2].split ('|')
    return l

def parseAnnotationsFromDirectory (dir_name):
    if (dir_name[-1] != '/'):
        dir_name = dir_name + '/'
    l = list ()
    for filename in annotation_files:
        l.extend (parse_annotation (dir_name + filename))
    return l

l = parseAnnotationsFromDirectory (sys.argv[1])
#for line in l:
#    print (line)
