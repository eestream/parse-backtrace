import sys
import getopt
import re
import subprocess
import os.path


input_file = ''
symbol_directory = ''

opts, args = getopt.getopt(sys.argv[1:], "i:s:", ["input-file=", "symbol-directory="])

for opt, arg in opts:
    if opt in ("-i", "--input-file"):
        input_file = arg
    elif opt in ("-s", "--symbol-directory"):
        symbol_directory = arg


print ("")
print (input_file)
print (symbol_directory)
print ("")
print("**********Start Backtrace**************")


pattern="(.*\/(.*)\(((.*)\+(.*))?\)\s+\[.*\])\n"
f=open(input_file, "r")
for line in f:
    match = re.search(pattern, line)
    if(match):
        lib = match.group(2)
        func_name = match.group(4)
        offset = match.group(5)

        #print(func_name)
        if(func_name):
            if((os.path.exists(symbol_directory+"/"+lib))==False):
                    continue;

            nm_process = subprocess.Popen(['nm', symbol_directory+"/"+lib], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            grep_process = subprocess.Popen(["grep", func_name], stdin=nm_process.stdout, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            stdout, stderr = grep_process.communicate()
            #print(stdout)
            #print(stderr)

            func_match =  re.search("(.*)\s+\w\s"+func_name, stdout)
            func_addr = func_match.group(1)
            #print (func_addr)

            target_addr = hex(int(func_addr, 16) + int(offset, 16))
            #print(target_addr)
            addr2line_process = subprocess.Popen(['addr2line', '-Cfe', symbol_directory+"/"+lib, target_addr], stdout=subprocess.PIPE, stderr=subprocess.PIPE)

            stdout, stderr = addr2line_process.communicate()
           # print(stdout)
            match_stdout = re.search("(.*)\n.*", stdout)
            if(match_stdout):
                print('{:110} {}'.format(match.group(1), match_stdout.group(1)))

            match_stderr = re.search("(.*)\n.*", stderr)
            if(match_stderr):
                print('{:110} {}'.format(match.group(1), match_stderr.group(1))) # fixed width
                #print('{line:{width}} {func}'.format(width=len(match.group(1))+10, line=match.group(1), func=match_stderr.group(1))) #variable width


f.close()
