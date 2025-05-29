# Makefile for root service manager

# Docker image and container variables
IMAGE_NAME := root-service-manager
IMAGE_TAG := latest

# Default target
.PHONY: help
help:
	@echo "Service Manager Makefile"
	@echo ""
	@echo "Docker Commands:"
	@echo "  make build              Build the Docker image"

# Build the Docker image
.PHONY: build
build:
	@echo "Building Docker image $(IMAGE_NAME):$(IMAGE_TAG)..."
	docker build -t $(IMAGE_NAME):$(IMAGE_TAG) .
	@echo "Build complete."

.PHONY: local
local:
	@echo "Building local service manager..."
	docker build -t local_root_service_manager .
	@echo "Local service manager built."
