all: base64

base64:
	$(MAKE) -C base64

clean: clean_base64 clean_include
	rm -f *~ *.bak

clean_include:
	rm -f include/b64/*~

clean_base64:
	$(MAKE) -C base64 clean;
	
distclean: clean distclean_base64

distclean_base64:
	$(MAKE) -C base64 distclean;

