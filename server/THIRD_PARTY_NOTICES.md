# Third-party notices

## SPDX License List data 3.28.0

Sanctuary's inert SPDX lookup table is generated from a deterministic minimal
projection containing only identifier/deprecated-status pairs and the list
version/release date. The repository and npm package do not redistribute the
full JSON summaries published by the SPDX `license-list-data` project. A normal
offline build verifies the committed fact-only projection and generated table.

- project: SPDX License List
- repository: `https://github.com/spdx/license-list-data`
- annotated release tag: `v3.28.0`
- tag object: `779ef2e5dff6d4af389c53de5e97116ab0bb52e8`
- source commit: `c4a7237ec8f4654e867546f9f409749300f1bf4c`
- release date declared by both summaries: `2026-02-20T00:00:00Z`
- license summary source:
  `https://raw.githubusercontent.com/spdx/license-list-data/v3.28.0/json/licenses.json`
- license summary raw SHA-256:
  `f728c534d8bd1044fc515a2ddb2292be99559021d830bfa3281be0bcd36302ee`
- license summary canonical-JSON SHA-256:
  `677f3480a6f3c26e7583e0ce41e9f486af91fcd3550de2eb6b8f4827e02589de`
- exception summary source:
  `https://raw.githubusercontent.com/spdx/license-list-data/v3.28.0/json/exceptions.json`
- exception summary raw SHA-256:
  `bd145bb558f44432fcd6f0d7e956ed0124dff72af7641a7cfcb1b557dc390a5b`
- exception summary canonical-JSON SHA-256:
  `ce36f1adeeaf719982fa9d2ca5134872904febfb09308b3d588456764ce16a12`
- release README source:
  `https://raw.githubusercontent.com/spdx/license-list-data/v3.28.0/README.md`
- release README raw SHA-256:
  `9d5e2eaa0daa05418074f90201d1e320fd3792018fe1a2ffdc3ebf69c9fffc44`
- committed fact-projection raw SHA-256:
  `a9517d7e516498a8adec3c07fa95cc6702c80c88e9d7381f1b667bfbf92c1c5e`
- generated identifier/deprecation table SHA-256:
  `57914b8e1024c570695c621267e3462691dc0829afe5ad773113cc9fa616d7c1`

The pinned `license-list-data` tag contains no repository-level LICENSE file.
Its README states that the data is generated from SPDX's `license-list-XML`
repository and directs consumers to the source and publisher repositories for
licensing information. The corresponding official SPDX License List page
carries this notice: “© 2018 SPDX Workgroup a Linux Foundation Project. All
Rights Reserved.” Sanctuary therefore does not assert a broader upstream
license grant and does not commit or publish the full summaries. Its minimal
projection retains only standardized identifiers, deprecation flags, version,
and release date needed for deterministic validation. SPDX and Software
Package Data Exchange are registered trademarks of The Linux Foundation.

The raw and canonical JSON hashes above are the integrity roots for an
externally supplied refresh. The tag-object and source-commit ids are reviewed
provenance attestations; they are not computed from and do not independently
authenticate the downloaded bytes.

The generator verifies exact raw and canonical source hashes, exact source
shape and release metadata, unique identifiers and reference numbers, canonical
SPDX URLs, 727 license rows (32 deprecated), 84 exception rows (one deprecated),
and the independently pinned generated-table digest.

## Sanctuary-authored profile grammar

`dist/intelligence/catalog-v3/spdx/spdx-expression-3.0.1.abnf` is
Sanctuary-authored Apache-2.0 material. It documents Sanctuary SPDX expression
profile v1, a deliberately narrower grammar that uses SPDX 3.0.1 vocabulary.

## Reproducible refresh

1. Review a new immutable SPDX `license-list-data` annotated release tag; pin
   both the tag-object id and its dereferenced source commit.
2. Download only `json/licenses.json`, `json/exceptions.json`, and the release
   README from that tag into a temporary directory outside the repository. Pin
   all three URLs and raw hashes here; pin the two summary raw/canonical hashes
   in the generator. Never commit the full summaries.
3. Verify the exact release version/date, source shapes, canonical hashes, 727
   license rows/32 deprecated, 84 exception rows/one deprecated, case-folded
   uniqueness, reference-number uniqueness, URL bindings, and deprecation
   status before changing the independent generated-table digest.
4. Run `node scripts/copy-catalog-v3-assets.mjs --write --refresh-source-dir
   /absolute/path/to/downloads`, review the exact minimal-projection and
   generated-table diffs, and pin the projection raw hash, table-content digest,
   and generated-source raw hash in the generator. If schemas or the ABNF changed, regenerate every
   raw/JCS/source-asset digest and independently repin the manifest raw hash.
5. Reconfirm the mechanically measured 61 module directories and 53 barrels in
   `src/README.md`, `CONTRIBUTING.md`, and the package gate.
6. Run the independent Python parity verifier, focused schema/package tests,
   typecheck, lint, build, and packed ESM/CJS consumer tests. The normal
   `npm test` path also re-derives the table in `pretest` without network access.

## Bundled console fonts (SIL Open Font License 1.1)

The web console embeds three typefaces as inline woff2 data in
`dist/` (the `CONSOLE_FONT_FACE_CSS` constant generated from
`assets/fonts/` by `scripts/build-design-fonts.mjs`). Each is a Latin subset
of the upstream variable font, cut with fonttools 4.55.3 `pyftsubset` (wght
axis kept, hinting dropped); the subsets keep the upstream copyright and
license name records. No Reserved Font Name is declared by any of the three
licenses. The full license text for each face is also committed beside its
font file in `assets/fonts/`.

- Manrope
  - copyright: Copyright 2018 The Manrope Project Authors (https://github.com/sharanda/manrope)
  - repository: `https://github.com/googlefonts/manrope`
  - pinned ref: commit `6f81ebecdf65e4463b798cc07b16a4f8d5216917` (upstream
    publishes no release tag; this is the commit Google Fonts records as the
    source of its Manrope release)
  - source: `fonts/variable/Manrope[wght].ttf`, SHA-256
    `d0639be45d0af36e798172419d7bd173c4bd4f29e2b76cbb69db1d11bf8b0a40`
  - subset: `assets/fonts/Manrope-wght.latin.woff2`, SHA-256
    `cd456782441247b5ea2648cbabea22a864dbf4bc179c2c136c643587114bc6bb`
- Space Grotesk
  - copyright: Copyright 2020 The Space Grotesk Project Authors (https://github.com/floriankarsten/space-grotesk)
  - repository: `https://github.com/floriankarsten/space-grotesk`
  - pinned ref: release tag `2.0.0`
  - source: `fonts/ttf/SpaceGrotesk[wght].ttf`, SHA-256
    `acad6de1fc93436f5c0f1f4137751ef04f1aea3063e7036535970ffcfbd79f72`
  - subset: `assets/fonts/SpaceGrotesk-wght.latin.woff2`, SHA-256
    `6ecbae53c7a459eeb68880f39264e8bbc4daa5ac2e462933578661f8cdad4c7f`
- Roboto Mono
  - copyright: Copyright 2015 The Roboto Mono Project Authors (https://github.com/googlefonts/robotomono)
  - repository: `https://github.com/googlefonts/RobotoMono`
  - pinned ref: release tag `v3.001`
  - source: `fonts/variable/RobotoMono[wght].ttf`, SHA-256
    `66a80e79d17e4c7cabd162e2916578a4cc08fd19eef6e2a643305eae9c567b2b`
  - subset: `assets/fonts/RobotoMono-wght.latin.woff2`, SHA-256
    `f8372c0e4704147a435cb078ca9af3e80ef90cdfe50f08673968a17ed6cda621`

To refresh a face: download only the pinned source font and its `OFL.txt` into
an empty temporary directory outside the repository, check the source hash,
re-run the `pyftsubset` command recorded in `scripts/build-design-fonts.mjs`,
copy the woff2 and license into `assets/fonts/`, update the pinned hashes here
and in the script, and run `node scripts/build-design-fonts.mjs`.

The license below applies to each of the three faces under the copyright line
given for it above.

```text

This Font Software is licensed under the SIL Open Font License, Version 1.1.
This license is copied below, and is also available with a FAQ at:
https://openfontlicense.org


-----------------------------------------------------------
SIL OPEN FONT LICENSE Version 1.1 - 26 February 2007
-----------------------------------------------------------

PREAMBLE
The goals of the Open Font License (OFL) are to stimulate worldwide
development of collaborative font projects, to support the font creation
efforts of academic and linguistic communities, and to provide a free and
open framework in which fonts may be shared and improved in partnership
with others.

The OFL allows the licensed fonts to be used, studied, modified and
redistributed freely as long as they are not sold by themselves. The
fonts, including any derivative works, can be bundled, embedded, 
redistributed and/or sold with any software provided that any reserved
names are not used by derivative works. The fonts and derivatives,
however, cannot be released under any other type of license. The
requirement for fonts to remain under this license does not apply
to any document created using the fonts or their derivatives.

DEFINITIONS
"Font Software" refers to the set of files released by the Copyright
Holder(s) under this license and clearly marked as such. This may
include source files, build scripts and documentation.

"Reserved Font Name" refers to any names specified as such after the
copyright statement(s).

"Original Version" refers to the collection of Font Software components as
distributed by the Copyright Holder(s).

"Modified Version" refers to any derivative made by adding to, deleting,
or substituting -- in part or in whole -- any of the components of the
Original Version, by changing formats or by porting the Font Software to a
new environment.

"Author" refers to any designer, engineer, programmer, technical
writer or other person who contributed to the Font Software.

PERMISSION & CONDITIONS
Permission is hereby granted, free of charge, to any person obtaining
a copy of the Font Software, to use, study, copy, merge, embed, modify,
redistribute, and sell modified and unmodified copies of the Font
Software, subject to the following conditions:

1) Neither the Font Software nor any of its individual components,
in Original or Modified Versions, may be sold by itself.

2) Original or Modified Versions of the Font Software may be bundled,
redistributed and/or sold with any software, provided that each copy
contains the above copyright notice and this license. These can be
included either as stand-alone text files, human-readable headers or
in the appropriate machine-readable metadata fields within text or
binary files as long as those fields can be easily viewed by the user.

3) No Modified Version of the Font Software may use the Reserved Font
Name(s) unless explicit written permission is granted by the corresponding
Copyright Holder. This restriction only applies to the primary font name as
presented to the users.

4) The name(s) of the Copyright Holder(s) or the Author(s) of the Font
Software shall not be used to promote, endorse or advertise any
Modified Version, except to acknowledge the contribution(s) of the
Copyright Holder(s) and the Author(s) or with their explicit written
permission.

5) The Font Software, modified or unmodified, in part or in whole,
must be distributed entirely under this license, and must not be
distributed under any other license. The requirement for fonts to
remain under this license does not apply to any document created
using the Font Software.

TERMINATION
This license becomes null and void if any of the above conditions are
not met.

DISCLAIMER
THE FONT SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO ANY WARRANTIES OF
MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT
OF COPYRIGHT, PATENT, TRADEMARK, OR OTHER RIGHT. IN NO EVENT SHALL THE
COPYRIGHT HOLDER BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
INCLUDING ANY GENERAL, SPECIAL, INDIRECT, INCIDENTAL, OR CONSEQUENTIAL
DAMAGES, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
FROM, OUT OF THE USE OR INABILITY TO USE THE FONT SOFTWARE OR FROM
OTHER DEALINGS IN THE FONT SOFTWARE.
```
