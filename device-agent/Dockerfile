FROM golang:1.22-alpine AS build
WORKDIR /app
COPY go.mod ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -o /device-agent

FROM gcr.io/distroless/base-debian12
COPY --from=build /device-agent /usr/local/bin/device-agent
EXPOSE 8080
USER 65532:65532
ENTRYPOINT ["/usr/local/bin/device-agent"]