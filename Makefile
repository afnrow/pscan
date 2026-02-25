.PHONY: all clean module install uninstall

# Kernel module
obj-m += filter.o

# Userspace program
USER_PROGRAM := pscan
USER_SRCS := main.c scan.c global.c

PWD := $(shell pwd)
KDIR := /lib/modules/$(shell uname -r)/build

# Default target: build everything
all: maybe_module $(USER_PROGRAM)

# Build kernel module **only if headers exist**
maybe_module:
	if [ -d $(KDIR) ]; then \
		echo "Building kernel module..."; \
		$(MAKE) -C $(KDIR) M=$(PWD) modules; \
	else \
		echo "Kernel headers not found for $(shell uname -r). Skipping module build."; \
	fi

# Build userspace program
$(USER_PROGRAM): $(USER_SRCS)
	gcc -Wall -o $@ $(USER_SRCS)

# Install userspace program to /usr/bin
install: all
	@echo "Installing $(USER_PROGRAM) to /usr/bin..."
	sudo cp $(USER_PROGRAM) /usr/bin/
	sudo chmod +x /usr/bin/$(USER_PROGRAM)
	@echo "Installation complete."

# Uninstall userspace program
uninstall:
	@echo "Removing $(USER_PROGRAM) from /usr/bin..."
	sudo rm -f /usr/bin/$(USER_PROGRAM)
	@echo "Uninstallation complete."

# Clean both kernel and userspace builds
clean:
	if [ -d $(KDIR) ]; then \
		$(MAKE) -C $(KDIR) M=$(PWD) clean; \
	fi
	$(RM) $(USER_PROGRAM)
	@echo "Cleaned kernel module (if built) and userspace program."
