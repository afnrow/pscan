.PHONY: all clean module install uninstall

obj-m += filter.o

USER_PROGRAM := pscan
USER_SRCS := main.c scan.c global.c mod.c log.c

PWD := $(shell pwd)
KDIR := /lib/modules/$(shell uname -r)/build

all: maybe_module $(USER_PROGRAM)

maybe_module:
	if [ -d $(KDIR) ]; then \
		echo "Building kernel module..."; \
		$(MAKE) -C $(KDIR) M=$(PWD) modules; \
	else \
		echo "Kernel headers not found for $(shell uname -r). Skipping module build."; \
	fi

$(USER_PROGRAM): $(USER_SRCS)
	gcc -Wall -o $@ $(USER_SRCS)

install: all
	@echo "Installing $(USER_PROGRAM) to /usr/bin..."
	sudo cp $(USER_PROGRAM) /usr/bin/
	sudo chmod +x /usr/bin/$(USER_PROGRAM)
	@echo "Installation complete."

uninstall:
	@echo "Removing $(USER_PROGRAM) from /usr/bin..."
	sudo rm -f /usr/bin/$(USER_PROGRAM)
	@echo "Uninstallation complete."

clean:
	if [ -d $(KDIR) ]; then \
		$(MAKE) -C $(KDIR) M=$(PWD) clean; \
	fi
	$(RM) $(USER_PROGRAM)
	@echo "Cleaned kernel module and userspace program."
