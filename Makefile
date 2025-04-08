# Makefile

PYTHON=python3

.PHONY: all server client test-crypto clean

all: help

help:
	@echo "📦 Commandes disponibles :"
	@echo "  make server        → Lance le serveur"
	@echo "  make client        → Lance le client"
	@echo "  make test-crypto   → Lance le test de chiffrement"
	@echo "  make clean         → Supprime les fichiers .pyc"

server:
	$(PYTHON) -m server.server

client:
	$(PYTHON) -m client.client

test-crypto:
	$(PYTHON) -m tests.test_crypto

clean:
	find . -name '*.pyc' -delete
	find . -name '__pycache__' -type d -exec rm -r {} +
