FROM debian:bookworm-slim as build

COPY . /code
WORKDIR /code

RUN apt-get update -qq && apt-get install -y \
  build-essential git make pkg-config cmake libssl-dev

RUN make release

FROM debian:bookworm-slim
COPY --from=build /code/pylon /usr/local/bin
ENTRYPOINT [ "/usr/local/bin/pylon" ]
