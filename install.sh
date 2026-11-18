#!/bin/bash
set -eo pipefail

usageFunction()
{
  echo " "
  tput setaf 2;
  echo "Usage: $0 (-n) (-h)"
  echo -e "\t-n Non-interactive installation (Optional)"
  echo -e "\t-h Show usage"
  exit 1
}

# Root check must happen first
if [ "$EUID" -ne 0 ]; then
  tput setaf 1; echo "Error installing reNgine, Please run this script as root!"
  tput setaf 1; echo "Example: sudo ./install.sh"
  exit 1
fi

tput setaf 2;
cat web/art/reNgine.txt

# Ensure .env exists
if [ ! -f .env ]; then
  if [ -f .env.sample ]; then
    tput setaf 3; echo ".env file not found. Creating from .env.sample..."
    cp .env.sample .env
  else
    tput setaf 1; echo "Error: .env or .env.sample file not found. Please provide .env before installing."
    exit 1
  fi
fi

tput setaf 1; echo "Before running this script, please make sure Docker is running and you have made changes to .env file."
tput setaf 2; echo "Changing the postgres username & password from .env is highly recommended."

tput setaf 4;

isNonInteractive=false
while getopts nh opt; do
   case $opt in
      n) isNonInteractive=true ;;
      h) usageFunction ;;
      ?) usageFunction ;;
   esac
done

if [ "$isNonInteractive" = false ]; then
    read -p "Are you sure, you made changes to .env file (y/n)? " answer
    case ${answer:0:1} in
        y|Y|yes|YES|Yes )
          echo "Continiuing Installation!"
        ;;
        * )
          nano .env
        ;;
    esac
else
  echo "Non-interactive installation parameter set. Installation begins."
fi

echo " "
tput setaf 3;
echo "#########################################################################"
echo "Please note that, this installation script is only intended for Linux"
echo "For Mac and Windows, refer to the official guide https://rengine.wiki"
echo "#########################################################################"

echo " "
tput setaf 4;
echo "Installing reNgine and its dependencies"

echo " "
tput setaf 4;
echo "#########################################################################"
echo "Installing curl..."
echo "#########################################################################"
if [ -x "$(command -v curl)" ]; then
  tput setaf 2; echo "CURL already installed, skipping."
else
  apt-get update && apt-get install -y curl
  tput setaf 2; echo "CURL installed!!!"
fi

echo " "
tput setaf 4;
echo "#########################################################################"
echo "Installing Docker..."
echo "#########################################################################"
if [ -x "$(command -v docker)" ]; then
  tput setaf 2; echo "Docker already installed, skipping."
else
  curl -fsSL https://get.docker.com -o get-docker.sh && sh get-docker.sh
  tput setaf 2; echo "Docker installed!!!"
fi


echo " "
tput setaf 4;
echo "#########################################################################"
echo "Installing Docker Compose"
echo "#########################################################################"
if docker compose version >/dev/null 2>&1 || docker-compose version >/dev/null 2>&1; then
  tput setaf 2; echo "Docker Compose already installed, skipping."
else
  if [ -x "$(command -v apt-get)" ]; then
    apt-get update && apt-get install -y docker-compose-plugin || true
  fi
  if ! (docker compose version >/dev/null 2>&1 || docker-compose version >/dev/null 2>&1); then
    COMPOSE_VERSION="v2.29.7"
    curl -fsSL "https://github.com/docker/compose/releases/download/${COMPOSE_VERSION}/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
    chmod +x /usr/local/bin/docker-compose
    ln -sf /usr/local/bin/docker-compose /usr/bin/docker-compose
  fi
  tput setaf 2; echo "Docker Compose installed!!!"
fi


echo " "
tput setaf 4;
echo "#########################################################################"
echo "Installing make"
echo "#########################################################################"
if [ -x "$(command -v make)" ]; then
  tput setaf 2; echo "make already installed, skipping."
else
  apt-get install -y make
fi

echo " "
tput setaf 4;
echo "#########################################################################"
echo "Checking Docker status"
echo "#########################################################################"
if docker info >/dev/null 2>&1; then
  tput setaf 4;
  echo "Docker is running."
else
  tput setaf 1;
  echo "Docker is not running. Please run docker and try again."
  echo "You can run docker service using sudo systemctl start docker"
  exit 1
fi



echo " "
tput setaf 4;
echo "#########################################################################"
echo "Installing reNgine"
echo "#########################################################################"
make certs && make build && make up && tput setaf 2 && echo "reNgine is installed!!!" && failed=0 || failed=1

if [ "${failed}" -eq 0 ]; then
  sleep 5

  echo " "
  tput setaf 4;
  echo "#########################################################################"
  echo "Applying database migrations..."
  echo "#########################################################################"
  make migrate

  echo " "
  tput setaf 4;
  echo "#########################################################################"
  echo "Creating an account"
  echo "#########################################################################"
  make username isNonInteractive=$isNonInteractive

  tput setaf 2 && printf "\n%s\n" "Thank you for installing reNgine, happy recon!!"
else
  tput setaf 1 && printf "\n%s\n" "reNgine installation failed!!"
  exit 1
fi
