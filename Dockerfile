FROM golang:1.21 AS builder

RUN apt-get update && apt-get install -y git

WORKDIR /app
# COPY go.mod go.sum ./
# RUN go mod download
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN chmod +x generate-sha.sh && ./generate-sha.sh
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o embargo .

# FROM registry.access.redhat.com/ubi8/ubi-micro
FROM gcr.io/distroless/static AS final

WORKDIR /app
USER nonroot:nonroot
COPY --from=builder --chown=nonroot:nonroot /app/embargo /app/embargo
# COPY --from=builder /app/embargo /app/embargo
COPY --from=builder /app/sha.txt /app/sha.txt

EXPOSE 8080
CMD ["/app/embargo"]
