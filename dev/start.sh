#!/bin/bash -ex

export COMPOSE_PROJECT_NAME=possumdev

docker-compose build

if [ ! -f data_key ]; then
	echo "Generating data key"
	docker-compose run --no-deps --rm --entrypoint possum possum data-key generate > data_key
fi

export POSSUM_DATA_KEY="$(cat data_key)"

docker-compose up -d
docker-compose exec possum possum db migrate
docker-compose exec possum possum account create cucumber || true
docker-compose exec possum bash
