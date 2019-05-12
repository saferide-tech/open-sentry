TOP_DIR 	:= $(shell pwd)
BUILD_DIR 	:= $(TOP_DIR)/build
OBJDIR 		:= $(BUILD_DIR)/objs
BINDIR 		:= $(BUILD_DIR)/bin
LIBDIR		:= $(BUILD_DIR)/lib

TARGET 		:= libsentry.so

VPATH 		:= 	src
SRCS 		:= 	sentry.c \
				action_rule.c \
				ip_rule.c \
				can_rule.c \
				file_rule.c \
				list.c

INCLUDES	+= -I./inc 

OBJS		:= $(addprefix $(OBJDIR)/,$(SRCS:.c=.o))
DEPS		:= $(OBJS:.o=.d)

CFLAGS 		+= -MMD -Wall -fPIC

ifdef DEBUG
CFLAGS 		+= -g -O0
else
CFLAGS 		+= -O2
endif


all: $(TARGET)

$(TARGET): $(OBJDIR) $(OBJS)
	@echo "linking $(notdir $@)"
	@rm -fr $(LIBDIR)/$@.0 $(LIBDIR)/$@
	@$(CC) $(LDFLAGS) -shared -Wl,-soname,$@.0 -o $(LIBDIR)/$@.0 $(OBJS)
	@cd $(LIBDIR) && ln -s $@.0 $@

$(OBJDIR):
	@mkdir -p $(OBJDIR)
	@mkdir -p $(BINDIR)
	@mkdir -p $(LIBDIR)

$(OBJDIR)/%.o: %.c
	@echo "compiling $(notdir $<)"
	@$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@

clean:
	@rm -fr $(BUILD_DIR)


test: $(TARGET)
	@echo "linking $(notdir $@)"
	@$(CC) $(INCLUDES) $(LDFLAGS) src/main.c -o $(BINDIR)/test -L$(LIBDIR) -lsentry $(LIBS)

-include $(DEPS)

