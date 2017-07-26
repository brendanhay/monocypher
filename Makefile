VERSION  := 1.0.1
TMP_DIR  := tmp
URL := http://loup-vaillant.fr/projects/monocypher/monocypher-$(VERSION).tar.gz

all: cbits/monocypher.c cbits/monocypher.h

cbits/monocypher.c: cbits tmp/monocypher-$(VERSION)
	cp tmp/monocypher-$(VERSION)/src/monocypher.c $@

cbits/monocypher.h: cbits tmp/monocypher-$(VERSION)
	cp tmp/monocypher-$(VERSION)/src/monocypher.h $@

cbits:
	@mkdir -p $@

tmp/monocypher-$(VERSION): tmp
	@curl $(URL) | tar xzv -C tmp

tmp:
	@mkdir -p $@
