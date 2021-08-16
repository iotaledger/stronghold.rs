.PHONY: all clean
all clean: CoqMakefile
	$(MAKE) -f $< $@

CoqMakefile: _CoqProject
	coq_makefile -f $< -o $@
