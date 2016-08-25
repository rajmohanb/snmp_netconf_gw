#*******************************************************************************
#                                                                              #
#                 Copyright (C) 2016, xxxxxxxxxxxxxxxxxxxxxxx                  #
#                  Rajmohan Banavi (rajmohan@mindbricks.com)                   #
#                            All Rights Reserved.                              #
#                                                                              #
#*******************************************************************************
#                                                                              #
# This document contains information that is confidential and proprietary to   #
# xxxxxxxxxxxxxxxxxxxxxxx. No part of this document may be reproduced in any   #
# form whatsoever without prior written approval from xxxxxxxxxxxxxxxxxxxxxxx. #
#                                                                              #
#******************************************************************************/

# Makefile for creating mindbricks ice server

ICE_LIB_DEST_PATH := $(shell pwd)/../lib

GATEWAY_APP := app
TARGET := all
SRC := app.c

# Include header file path
INCLUDE :=-I. -I../gateway/inc

GATEWAY_LIB := -lGateway
NET_SNMP_LIBS := -lnetsnmp

CFLAGS += -g -Wall -Wstrict-prototypes -c $(INCLUDE)
LDFLAGS += -L../gateway/src -L../net-snmp/libs

OBJ:=$(SRC:c=o)

.c.o :
	echo [CC] 	$< ...
	$(CC) $(CFLAGS) -o $*.o $<

$(TARGET) : clean $(GATEWAY_APP)

$(GATEWAY_APP) : $(OBJ)
	@echo "Creating app ... " $(TARGET) 
	$(CC) $(LDFLAGS) $(OBJ) -o $(GATEWAY_APP) $(GATEWAY_LIB) $(NET_SNMP_LIBS)

clean_obj:
	rm -rf $(OBJ)

clean:
	@echo "Removing all objects and binaries ... "
	rm -rf $(GATEWAY_APP) $(OBJ)

