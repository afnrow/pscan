savedcmd_/home/yahia/pscan/filter.mod := printf '%s\n'   filter.o | awk '!x[$$0]++ { print("/home/yahia/pscan/"$$0) }' > /home/yahia/pscan/filter.mod
