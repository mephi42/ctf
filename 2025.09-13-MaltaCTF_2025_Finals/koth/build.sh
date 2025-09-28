#!/bin/sh
set -e -u -x
protoc --go_out=. --go_opt=paths=source_relative,Mkoth.proto=mephi42/main koth.proto
go fmt
go build
