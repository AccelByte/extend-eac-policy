# Copyright (c) 2025 AccelByte Inc. All Rights Reserved.
# This is licensed software from AccelByte Inc, for limitations
# and restrictions contact your company contract manager.

SHELL := /bin/bash

PROTOC_IMAGE := proto-builder

.PHONY: build proto_image proto

proto_image:
	docker build --target proto-builder -t $(PROTOC_IMAGE) .

proto: proto_image
	docker run --tty --rm --user $$(id -u):$$(id -g) \
		--volume $$(pwd):/build \
		--workdir /build \
		--entrypoint /bin/bash \
		$(PROTOC_IMAGE) \
			proto.sh

build: proto