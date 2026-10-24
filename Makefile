.PHONY: tag-sensors tag-release

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
	@echo "Push with: git push origin --tags"

# Tag the Hub and Wizard at the versions compiled into them.
tag-release:
	@hub=$$(grep -oP 'HubVersion\s*=\s*"\K[^"]+' Hub/internal/models/models.go); \
	wiz=$$(grep -oP 'WizardVersion\s*=\s*"\K[^"]+' wizard/core/api/client.go); \
	git tag "hub/v$$hub" && echo "   + hub/v$$hub"; \
	git tag "wizard/v$$wiz" && echo "   + wizard/v$$wiz"
	@echo "Push with: git push origin --tags"
