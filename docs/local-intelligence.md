# Local intelligence: the model-provisioning ceremony

> **Status:** the provisioning ceremony described here ships in this release.
> Sanctuary has code paths and tests for signed model-manifest binding and
> bounded local layer verification; production activation on a real host is
> pending host evidence, and this page will say so in plain terms once that
> evidence exists.

Local intelligence is Sanctuary's own cognition running on a local model
through Ollama: the concierge, the sentinel scorer, the gate advisor, the
privacy filter, and template suggestion can each be routed to a local model
instead of a hosted provider. The dashboard substrate selector and
`sanctuary intelligence diagnose` cover picking and inspecting that routing
and work with any model you have installed by hand.

## The provisioning ceremony

`sanctuary init --provision-local-intelligence` and
`sanctuary protect <harness> --provision-local-intelligence` enter the
disclosed setup ceremony. It requires an interactive terminal, prints its plan,
and asks for one confirmation before any change to the host.

Before any model pull, the ceremony verifies a Sanctuary-signed model manifest
that ships inside the release package. The manifest is checked against a key
pinned in the build (a dedicated model-catalog signing key, separate from the
release-signing key), through a byte cap and a strict parser, and against a
byte pin recorded when the package was built. A manifest that is missing,
oversized, malformed, signed by any other key, or altered inside the package
is refused with a named reason, an audit record is written, and no pull is
attempted.

Each check defends against one thing, and it is worth being exact. The byte pin
defends against an altered manifest file inside an otherwise intact package.
The signature defends against a manifest signed by any other key. Neither
defends against a package whose code has itself been rewritten; only the
package's own release provenance covers that.

The first manifest lists the default models for the three hardware
bands (8, 16, and 32 GiB of RAM) with their exact Ollama registry digests, so
the model that is pulled is the one that was signed.

## Bounds

- **No network discovery of newer manifests yet.** The ceremony only reads the
  manifest packaged with the installed release. An operator who has a newer
  Sanctuary-signed manifest can supply it by path with
  `--model-manifest <path>`; it is verified exactly the same way, and nothing
  is fetched.
- **Light assurance verifies the runtime-reported digest.** The check confirms
  that Ollama reports the signed manifest digest for each required model. It
  does not by itself prove that every model byte on disk was read.
- **Ollama is installed by the operator on every platform in this release.**
  Automatic runtime installation is not available yet; install Ollama, start
  it once, then run the ceremony. Pulling the tier model with `ollama pull`
  first is the reliable path on this release; the ceremony then verifies the
  present model against the signed manifest and arms.
- **Interactive only.** A headless run refuses before touching the host or the
  manifest.
- **ESM entry only.** The packaged manifest is located from the module's own
  file URL, which the CommonJS builds of the library do not carry; a CommonJS
  consumer gets a named refusal, and the `sanctuary` CLI is the provisioning
  path.
