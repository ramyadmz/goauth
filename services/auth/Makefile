.PHONY: docker-integration-test
docker-integration-test:
	@docker-compose -f integration/docker-compose.yml up --build --force-recreate --abort-on-container-exit
	@docker-compose -f integration/docker-compose.yml down --volumes
