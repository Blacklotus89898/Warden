# Static Go binary on distroless :nonroot (the Tulip image pattern). Warden
# only reads the cluster; it still gets no root and a read-only root fs.
FROM golang:1.25-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG VERSION=dev
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w -X main.version=${VERSION}" -o /out/warden .

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/warden /warden
EXPOSE 8080
VOLUME ["/data"]
USER nonroot:nonroot
ENTRYPOINT ["/warden"]
CMD ["-db", "/data/warden.db"]
