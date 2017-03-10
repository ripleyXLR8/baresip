#
# module.mk
#
# Copyright (C) 2017 Richard Perez
#

MOD		:= raspdoorbell
$(MOD)_SRCS	+= raspdoorbell.c
$(MOD)_LFLAGS += -lwiringPi

include mk/mod.mk
