module github.com/laststate/protocol/tools/genvectors

go 1.22

require github.com/laststate/protocol/implementations/go v0.0.0

require (
	github.com/klauspost/compress v1.17.11 // indirect
	golang.org/x/crypto v0.31.0 // indirect
	golang.org/x/sys v0.28.0 // indirect
)

replace github.com/laststate/protocol/implementations/go => ../../implementations/go
