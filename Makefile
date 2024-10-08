# Add command to start the server
start:
	@echo "Starting server..."
	@go run main.go

server-crt:
	@# Generate public key
	openssl ecparam -genkey -name prime256v1 -out server.key
	@# Create CSR
	openssl req -new -key server.key -out server.csr -subj "/C=JP/ST=Tokyo/L=Tokyo/O=MyOrganization/OU=MyUnit/CN=localhost"
	@# Signing the public key
	openssl req -x509 -sha256 -days 365 -key server.key -in server.csr -out server.crt

ed25519-crt:
	@# Generate public key
	openssl genpkey -algorithm Ed25519 -out server.key
	@# Signing the public key
	openssl req -new -x509 -key server.key -days 365 -out server.crt -subj "/C=JP/ST=Tokyo/L=Tokyo/O=MyOrganization/OU=MyUnit/CN=localhost"

handshake:
	openssl s_client -debug -connect localhost:443 -CAfile server.crt -tls1_3 -noservername -crlf -curves x25519:secp256r1 -sigalgs ECDSA+SHA256:ed25519 -msg -security_debug_verbose -trace -keylogfile keylog.txt

test:
	go test ./...
