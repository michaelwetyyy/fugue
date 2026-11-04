# Third-party notices

The root MIT licence covers this project's code. It does not replace the separate licences or copyright notices for bundled third-party material.

## Bundled fonts

### Geist Mono

- Asset: `ui/src/assets/fonts/geist-mono-1.7.2.woff2`
- Licence: SIL OFL 1.1; full notice: [ui/src/assets/fonts/geist-mono-OFL.txt](ui/src/assets/fonts/geist-mono-OFL.txt)
- Upstream project: https://github.com/vercel/geist-font
- Bundled asset SHA-256: `fba8f577f38a2bbcbe818efa6348dd58f36303a10b8737c42fefad275be563ab`

### Space Mono

- Asset: `ui/src/assets/fonts/space-mono-400.woff2`
- Licence: SIL OFL 1.1; full notice: [ui/src/assets/fonts/space-mono-OFL.txt](ui/src/assets/fonts/space-mono-OFL.txt)
- Upstream project: https://github.com/googlefonts/spacemono
- Bundled asset SHA-256: `e0c8e616bda27642f4c3cebaecff6525d901e73afc8a227cbbb0f2af4810f300`

The hashes identify the files in this source release; they are not an independent upstream provenance certification. Both font notice files are retained unchanged. Redistributed font binaries must retain their applicable notices.

## Three.js and package dependencies

The UI locks Three.js 0.185.1. Its bundled [MIT notice](ui/src/assets/licenses/three-LICENSE.txt) is retained unchanged. The Tauri resource list includes that notice and both font notices for native bundles.

Other JavaScript and Rust dependencies are referenced through `ui/pnpm-lock.yaml` and `ui/src-tauri/Cargo.lock`; their source or installed dependency trees are not vendored in this publication. They retain their respective licences. A binary or static-asset distributor should include the notices required by the exact dependencies and assets it redistributes; this source publication contains no desktop binaries or installed dependency trees.
