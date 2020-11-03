# Minimal makefile for Sphinx documentation
#

# You can set these variables from the command line.
SPHINXOPTS    =
SPHINXBUILD   = sphinx-build
SOURCEDIR     = .
BUILDDIR      = _build

VERSION_FILES = conf.py installation/basic.rst
VERSION      := $(shell perl -e 'require "../../lib/perl/OVH/Bastion.pm"; print $$OVH::Bastion::VERSION')

all: plugins default

default: Makefile
	@sed -i -e "s/__VERSION__/$(VERSION)/g" $(VERSION_FILES)
	@$(SPHINXBUILD) -M html "$(SOURCEDIR)" "$(BUILDDIR)" $(SPHINXOPTS) $(O)
	@rsync -a --delete _build/html/ ../../docs/
	@echo "HTML documentation copied to ../../docs/"

# Put it first so that "make" without argument is like "make help".
help:
	@$(SPHINXBUILD) -M help "$(SOURCEDIR)" "$(BUILDDIR)" $(SPHINXOPTS) $(O)

plugins:
	@bash build-plugins-help.sh

.PHONY: help Makefile plugins all

# Catch-all target: route all unknown targets to Sphinx using the new
# "make mode" option.  $(O) is meant as a shortcut for $(SPHINXOPTS).
%: Makefile
	@$(SPHINXBUILD) -M $@ "$(SOURCEDIR)" "$(BUILDDIR)" $(SPHINXOPTS) $(O)
