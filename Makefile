CURRENT_DIR = $(shell pwd)

.DEFAULT_GOAL := docker-start

.SILENT:

docker-clean:
	docker compose down --rmi local

docker-start: docker-clean
	docker compose --env-file .env up --build

utests:
	cd $(CURRENT_DIR)/app &&\
	 	go test ./internals/transport/handlers/user &&\
		go test ./internals/services/user &&\
		go test ./pkg/session
