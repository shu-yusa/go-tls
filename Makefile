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
