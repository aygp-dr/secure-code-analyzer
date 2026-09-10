.PHONY: run scan test lint fmt check clean help

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?\#\# .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?\#\# "}; {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}'

run: ## Run the scanner (usage: make run ARGS="--dir ./src --format json")
	bb run $(ARGS)

scan: ## Scan a directory (usage: make scan DIR=./src)
	bb run --dir $(or $(DIR),.) --format text

test: ## Run tests (JVM + babashka)
	bb test && bb test:bb

lint: ## Lint with clj-kondo
	bb lint

fmt: ## Check formatting (bb fmt:fix to repair)
	bb fmt

check: ## lint + fmt + test (what CI runs)
	bb check

clean: ## Clean caches
	rm -rf .cpcache target .clj-kondo/.cache
