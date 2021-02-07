# This is the docker file to build the manta project milestone 1
# it is quite slow -- on a 2021 MBP13, it took around 20 min to build

FROM ubuntu:18.04
FROM rust:1.49

# update apt
RUN apt update

# install necessary dependencies
RUN apt install -y cmake pkg-config libssl-dev git build-essential clang libclang-dev curl libz-dev

# copy the source code
RUN git clone https://github.com/Manta-Network/W3F-Milestone1-Demo.git

# setup rust runtime
RUN rustup toolchain install nightly-2020-10-05
RUN rustup target add wasm32-unknown-unknown --toolchain nightly-2020-10-05
RUN rustup default nightly-2020-10-05

# set workdir
WORKDIR /W3F-Milestone1-Demo

# # unzip sources
RUN tar -xf manta-node-0.1.0.tar.gz
RUN tar -xf manta-front-end-0.1.0.tar.gz

# install backend 
WORKDIR /W3F-Milestone1-Demo/manta-node-0.1.0
RUN cargo +nightly-2020-10-05 build --release
# backend test (slow)
# RUN cargo test --release


# install frontend
WORKDIR /W3F-Milestone1-Demo/ manta-front-end-0.1.0
RUN yarn install

