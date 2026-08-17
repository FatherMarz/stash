FROM golang:1.25-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /stash .

FROM scratch
COPY --from=build /stash /stash
VOLUME /data
EXPOSE 8555
ENTRYPOINT ["/stash", "serve", "--addr", "0.0.0.0:8555", "--data", "/data"]
