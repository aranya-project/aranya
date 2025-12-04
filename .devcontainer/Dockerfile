FROM rust:latest

RUN apt-get update && apt-get install -y \
    curl \
    git \
    gnupg2 \
    jq \
    sudo \
    zsh

WORKDIR /usr/src/myapp
COPY . .

CMD ["myapp"]
