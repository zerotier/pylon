FROM debian:bookworm-slim as build

RUN apt-get update -qq && apt-get install -y \
  build-essential git make pkg-config cmake libssl-dev

COPY ./ /code
WORKDIR /code

RUN make release

FROM debian:bookworm-slim
COPY --from=build /code/pylon /usr/local/bin
# EXPOSE 443
# EXPOSE 9993/udp
# ENV ZT_PYLON_SECRET_KEY=
# ENV ZT_PYLON_WHITELISTED_PORT=
ENTRYPOINT [ "/usr/local/bin/pylon" ]
CMD ["reflect"]
