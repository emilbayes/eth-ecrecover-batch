build: contracts/batch-ecrecover.sol test/test.sol
	solc \
		--via-ir \
		--optimize \
		--optimize-runs 2000 \
		--ir-optimized \
		--abi \
		--storage-layout \
		--hashes \
		--bin \
		-o build --overwrite test/test.sol

clean: build
	rm -r build
