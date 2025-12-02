TAG ?= 12021525

.PHONY: build-docker-images
build-docker-images:
	cd file-server && docker build --platform linux/amd64 -t matewolf/file-server:$(TAG) -f .Dockerfile .
	cd mock-assistant && docker build --platform linux/amd64 -t matewolf/mock-assistant:$(TAG) -f .Dockerfile .

.PHONY: push-docker-images
push-docker-images:
	docker push matewolf/file-server:$(TAG)
	docker push matewolf/mock-assistant:$(TAG)

.PHONY: build-and-push-docker-images
build-and-push-docker-images: build-docker-images push-docker-images
.PHONY: build-and-push-latest

build-and-push-latest: build-docker-images push-docker-images
