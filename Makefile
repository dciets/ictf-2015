.PHONY: all service bundle spawn
SERVICE=notecxx

all: bundle

service:
	$(MAKE) -C src
	cp src/$(SERVICE) service/ro/

bundle: service
	mkdir -p service/rw
	rm -f scripts/*.pyc
	rm -f ../$(SERVICE).tgz
	tar caf ../$(SERVICE).tgz *
	@echo "#### Double check ../$(SERVICE).tgz and submit it :) ####"

spawn: service
	( cd service/rw && (socat tcp-l:6666,reuseaddr,fork exec:"../ro/$(SERVICE)" 2> /tmp/log) )
