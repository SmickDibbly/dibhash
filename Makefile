LIBNAME = dibhash
CC = gcc
AR = ar -rc
RM = rm -rf
CP = cp -v

CFLAGS = \
-Wall \
-Wextra \
-Wconversion \
-Wdouble-promotion \
-Wno-unused-parameter \
-Wno-unused-function \
-Wno-sign-conversion \
-std=c99 -pedantic \
-MMD \
-O3 \
$(SANITIZE_CFLAGS) \
$(GPROF_CFLAGS)
INCLUDES = -I $(DIBLIB_DIR)/h 
LDFLAGS = #-L$(DIBLIB_DIR)/a
LDLIBS =  #-lfoo

TARGET = lib$(LIBNAME).a
SRCS = $(LIBNAME).c
OBJS = $(SRCS:.c=.o)
DEPS = $(SRCS:.c=.d)

VERBOSE = #TRUE
ifeq ($(VERBOSE), TRUE)
	HIDE =
else
	HIDE = @
endif

BOLD = $(shell tput bold)
ORANGE = $(shell tput setaf 11)
SGR0 = $(shell tput sgr0)

$(TARGET) : $(LIBNAME).o
	$(HIDE)printf '$(BOLD)$(ORANGE)Creating archive$(SGR0) $@\n'
	$(HIDE)$(AR) $(TARGET) $(OBJS)

-include $(DEPS)

%.o: %.c
	$(HIDE)printf '$(BOLD)$(ORANGE)Building$(SGR0) $@\n'
	$(HIDE)$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@

.PHONY : clean install

clean :
	$(RM) $(TARGET) $(OBJS) $(DEPS)
	@echo Cleaning done!

include ../libcommon.mk

install :
	$(HIDE)printf '$(BOLD)$(ORANGE)Copying library$(SGR0)\n'
	$(HIDE)$(CP) $(TARGET) $(A_DEST)
	$(HIDE)printf '$(BOLD)$(ORANGE)Copying header$(SGR0)\n'
	$(HIDE)$(CP) $(LIBNAME).h $(H_DEST)
