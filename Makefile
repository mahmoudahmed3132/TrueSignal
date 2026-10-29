.PHONY: tag-sensors tag-release push-tags

# Tag every official sensor at the version in its manifest. CI refuses a tag
# whose version differs from the manifest, so bump the manifest first.
tag-sensors:
	@for f in $$(find Sensors/official -mindepth 2 -maxdepth 2 -name "*.json" 2>/dev/null | sort); do \
		id=$$(jq -r '.id // empty' "$$f"); \
		ver=$$(jq -r '.version // empty' "$$f"); \
		if [ -n "$$id" ] && [ -n "$$ver" ]; then \
			tag="sensor/$${id#ts-sensor-}/v$$ver"; \
			if git rev-parse -q --verify "refs/tags/$$tag" >/dev/null; then \
				echo "   = $$tag exists, skipping"; \
			else \
				git tag "$$tag" && echo "   + $$tag"; \
			fi; \
		fi; \
	done
	@echo "Push with: make push-tags (not git push --tags: see below)"

# Tag the Hub and Wizard at the versions compiled into them.
tag-release:
	@hub=$$(sed -nE 's/.*HubVersion[[:space:]]*=[[:space:]]*"([^"]+)".*/\1/p' Hub/internal/models/models.go); \
	wiz=$$(sed -nE 's/.*WizardVersion[[:space:]]*=[[:space:]]*"([^"]+)".*/\1/p' wizard/core/api/client.go); \
	if [ -z "$$hub" ] || [ -z "$$wiz" ]; then \
		echo "ERROR: could not parse HubVersion/WizardVersion from source" >&2; exit 1; \
	fi; \
	remote=$$(git ls-remote --tags origin | awk '{print $$2}'); \
	for t in "hub/v$$hub" "wizard/v$$wiz"; do \
		local=$$(git rev-parse -q --verify "refs/tags/$$t^{commit}" || true); \
		if printf '%s\n' "$$remote" | grep -qx "refs/tags/$$t"; then \
			echo "   = $$t already on origin (version unchanged), skipped"; \
		elif [ -n "$$local" ] && [ "$$local" = "$$(git rev-parse HEAD)" ]; then \
			echo "   = $$t already on HEAD, not yet pushed"; \
		elif [ -n "$$local" ]; then \
			echo "ERROR: local tag $$t points at $$local, not HEAD, and is not on origin. Delete it (git tag -d $$t) or bump the version." >&2; exit 1; \
		else \
			git tag "$$t" && echo "   + $$t" || exit 1; \
		fi; \
	done
	@echo "Push with: make push-tags (not git push --tags: see below)"

# Push the release tags on HEAD one per `git push`. GitHub creates no push
# event (so no publish workflow runs) for tags when one push carries more
# than three. Tags already on origin are skipped.
push-tags:
	@remote=$$(git ls-remote --tags origin | awk '{print $$2}'); \
	for t in $$(git tag --points-at HEAD | grep -E '^(hub|wizard|sensor)/'); do \
		if printf '%s\n' "$$remote" | grep -qx "refs/tags/$$t"; then \
			echo "   = $$t already on origin"; \
		else \
			git push -q origin "refs/tags/$$t" || { echo "   ! $$t push failed"; exit 1; }; \
			echo "   ^ $$t"; \
		fi; \
	done
