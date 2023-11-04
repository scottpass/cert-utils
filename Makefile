SHELL := /bin/zsh
.PHONY: bundle_enclave_tests test_enclave

bundle_enclave_tests:
	mkdir -p bin
	rm -rf bin/enclave.test.app
	cp -a osx/enclave.test/enclave.test.app bin/enclave.test.app
	mkdir -p bin/enclave.test.app/Contents/MacOS
	go test -c -o bin/enclave.test.app/Contents/MacOS/enclave ./crypto/enclave
	codesign -s "Apple Development: Scott Wisniewski (GU628445FZ)" --deep --entitlements osx/enclave.test/entitlements.plist -o runtime bin/enclave.test.app

test_enclave: bundle_enclave_tests
	./bin/enclave.test.app/Contents/MacOS/enclave -test.v