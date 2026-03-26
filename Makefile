all: clean build install

build:
	RUSTFLAGS="-C target-cpu=native" cargo build --release

install:
	cp target/release/obfs /usr/local/bin/

clean:
	rm -f /usr/local/bin/obfs
