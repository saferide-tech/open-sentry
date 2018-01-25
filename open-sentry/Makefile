TOP_DIR 	:= $(shell pwd)
BUILD_DIR 	:= $(TOP_DIR)/build
OBJDIR 		:= $(BUILD_DIR)/objs
BINDIR 		:= $(BUILD_DIR)/bin

TARGET 		:= open_sentry

VPATH 		:= src

SRCS 		:=  open_sentry.c \
				action.c \
				can.c \
				ip.c \

INCLUDES	+= -I./inc

OBJS		:= $(addprefix $(OBJDIR)/,$(SRCS:.c=.o))
DEPS		:= $(OBJS:.o=.d)

LIBS		:= -lsentry -lsysrepo -lpthread -lnl-3 -lnl-genl-3 -lnetfilter_log

CFLAGS 		+= -MMD -Wall

ifdef DEBUG
CFLAGS 		+= -g -O0
else
CFLAGS 		+= -O2
endif

all: $(TARGET)

$(TARGET): $(OBJDIR) $(OBJS)
	@echo "linking $(notdir $@)"
	@$(CC) $(LDFLAGS) $(OBJS) -o $(BINDIR)/$(TARGET) $(LIB_PATH) $(LIBS)

$(OBJDIR):
	@mkdir -p $(OBJDIR)
	@mkdir -p $(BINDIR)

$(OBJDIR)/%.o: %.c
	@echo "compiling $(notdir $<)"
	@$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@

clean:
	@rm -fr $(BUILD_DIR)

-include $(DEPS)

