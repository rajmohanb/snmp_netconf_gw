#*******************************************************************************
#                                                                              #
#                 Copyright (C) 2016, MindBricks Technologies                  #
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

# Makefile for creating ice full agent library

# Macros

# ice full agent library
LIB := libGateway.a

# ice agent source files
SRC = gateway.c 

# Include header files
INCLUDE := -I../inc -I../../net-snmp/inc

CFLAGS += -g -c -Wall -Wstrict-prototypes $(INCLUDE)

OBJS:=$(SRC:c=o)

#object Build Rules
.c.o :
	@echo "[CC] " $< ...
	@$(CC) $(CFLAGS) -o $*.o $<

archive:$(OBJS)
	@echo "Building library " $(LIB)
	@$(AR) $(ARFLAGS) $(LIB) $(OBJS) 
	#@mv $(LIB) $(ICE_LIB_DEST_PATH)

clean:
	@echo "Cleaning library" $(LIB)
	@rm -rf $(LIB) *.o $(ICE_LIB_DEST_PATH)/$(LIB)
