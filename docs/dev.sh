#!/bin/bash -ex

(cd ..; docker build -t possum-web -f docs/Dockerfile .)

# /node_modules/.bin/aglio -i apidocs/src/api.md -o docs/apidocs/doc.html
docker run \
  --rm \
  -it \
  -v $PWD/..:/opt/conjur \
  -p 4000:4000 \
  --name possum-web \
  possum-web ${@-jekyll serve -H 0.0.0.0 --source docs}
