module github.com/XunleiBlockchain/tc-libs

go 1.13

replace (
	github.com/go-interpreter/wagon => github.com/xunleichain/wagon v0.5.3
	github.com/tjfoc/gmsm => github.com/bcscb8/gmsm v0.0.0-20191220070229-b97b35b41ab6
	go.mongodb.org/mongo-driver => github.com/xunleichain/mongo-go-driver v0.8.0
	gopkg.in/sourcemap.v1 => github.com/go-sourcemap/sourcemap v1.0.5
)

require (
	github.com/aristanetworks/goarista v0.0.0-20190712234253-ed1100a1c015
	github.com/bwesterb/go-ristretto v1.1.1
	github.com/cespare/cp v1.1.1
	github.com/davecgh/go-spew v1.1.1
	github.com/ethereum/go-ethereum v1.9.3
	github.com/go-stack/stack v1.8.0
	github.com/golang/protobuf v1.3.2
	github.com/kr/pretty v0.2.0 // indirect
	github.com/pborman/uuid v1.2.0
	github.com/pkg/errors v0.8.1
	github.com/rjeczalik/notify v0.9.2
	github.com/stretchr/testify v1.4.0
	github.com/tjfoc/gmsm v0.0.0-00010101000000-000000000000
	golang.org/x/crypto v0.0.0-20191206172530-e9b2fee46413
	golang.org/x/sys v0.0.0-20200223170610-d5e6a3e2c0ae
	gopkg.in/check.v1 v1.0.0-20190902080502-41f04d3bba15
	gopkg.in/fatih/set.v0 v0.1.0
)
