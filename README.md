keyman
======

Easy golang RSA key and certificate management.

API documentation available on [godoc](https://godoc.org/github.com/oxtoacart/keyman).

### Build Notes

On Windows, keyman uses a custom executable for importing certificates into the
system trust store.  This executable is built using Visual Studio from this
[solution](certimporter).

The resulting executable is packaged into go using
[go-bindata](https://github.com/jteeuwen/go-bindata) by running the below
command inside the [certimporter](certimporter) folder:

`bash
go-bindata -nomemcopy -nocompress -prefix Release -o ./certimporter.go -pkg certimporter Release
`
