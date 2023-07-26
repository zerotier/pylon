FROM debian:bookworm-slim AS os-updated

RUN apt-get update -qq && apt-get install -y git make cmake clang

FROM os-updated AS build
COPY . /code
WORKDIR /code
RUN make release

FROM debian:bookworm-slim AS release
COPY --from=build /code/pylon /usr/local/bin
RUN apt-get clean
ENTRYPOINT [ "/usr/local/bin/pylon" ]
