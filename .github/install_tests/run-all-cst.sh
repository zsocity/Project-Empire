#!/bin/bash
set -e

# The script is run like `./run-all-cst.sh debian12 debian11 debian10` to test multiple images
# or `./run-all-cst.sh debian12` to test a single image
# or `./run-all-cst.sh` to test all images

all_images=(debian12 debian11 debian10 ubuntu2004 ubuntu2204 kalirolling parrotrolling)

for image in "${@:-${all_images[@]}}"
do
  yaml=""
  # For debian trim the numbers off the end
  if [[ $image == debian* ]]; then
    yaml=debian
  fi
  # For ubuntu trim the numbers off the end
  if [[ $image == ubuntu* ]]; then
    yaml=ubuntu
  fi
  # For kali and parrot trim "rolling" off the end
  if [[ $image == kali* || $image == parrot* ]]; then
    yaml=${image%rolling}
  fi

  echo "Testing $image with $yaml.yaml"
  container-structure-test test -i docker.io/bcsecurity/empire-test-$image -c .github/install_tests/cst-config-install-base.yaml
  container-structure-test test -i docker.io/bcsecurity/empire-test-$image -c .github/install_tests/cst-config-$yaml.yaml
done
