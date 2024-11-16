#---------------------------------------------------------------
# Using this Makefile
#
#   To compile your java source:
#
#   make
#
#   To clean up your directory
#
#   make clean
#
#---------------------------------------------------------------

all:
	mvn package

clean:
	mvn clean
	
