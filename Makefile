all:
	(cd src && $(MAKE) all)
	(cd test && $(MAKE) all)

clean:
	(cd test && $(MAKE) clean)
	(cd src && $(MAKE) clean)
