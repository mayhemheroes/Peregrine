FROM --platform=linux/amd64 ubuntu:22.04 as builder

RUN apt-get update
RUN DEBIAN_FRONTEND=noninteractive apt-get install -y build-essential meson
RUN DEBIAN_FRONTEND=noninteractive apt-get install -y clang

COPY . /repo
WORKDIR /repo/build
RUN meson .. 
RUN ninja 
RUN clang++ -c /repo/Peregrine/errors/errors.cpp -o errors.o
RUN ar rcs liberrors.a errors.o
RUN clang++ /repo/mayhem/fuzz_add_space.cpp -fsanitize=fuzzer,address -L /repo/build/ -lerrors -o /fuzz

FROM ubuntu:22.04 as package
COPY --from=builder /repo/build/peregrine.elf /
COPY --from=builder /fuzz /fuzz_add_space
