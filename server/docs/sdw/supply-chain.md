# SDW LMDB Supply-Chain Pin

Phase 1 uses the published `lmdb` npm package at exact version `3.4.2`. This is the npm package for the lmdb-js project; `lmdb-js` itself is not a published registry package name.

The package and platform prebuild artifacts are pinned in `server/package-lock.json` with integrity hashes:

- `lmdb@3.4.2`
- `@lmdb/lmdb-darwin-arm64@3.4.2`
- `@lmdb/lmdb-darwin-x64@3.4.2`
- `@lmdb/lmdb-linux-arm@3.4.2`
- `@lmdb/lmdb-linux-arm64@3.4.2`
- `@lmdb/lmdb-linux-x64@3.4.2`
- `@lmdb/lmdb-win32-arm64@3.4.2`
- `@lmdb/lmdb-win32-x64@3.4.2`

Install-time network behavior: `npm install` resolves the npm registry tarballs above and installs optional platform prebuild packages. There is no operation-time Castle Wall exception for LMDB; it is embedded and receives only ciphertext envelope bytes through `StorageBackend`.
