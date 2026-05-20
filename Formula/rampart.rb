# Homebrew formula for rampart.
#
# Until a tap repo exists, install directly from this repo:
#
#   brew install --formula https://raw.githubusercontent.com/visigoth/rampart/main/Formula/rampart.rb
#
# Or clone the repo and `brew install --build-from-source ./Formula/rampart.rb`.
# Once a tap is set up (homebrew-visigoth or similar) move this file there
# unchanged and the `brew install visigoth/tap/rampart` shorthand will work.
#
# The formula builds from source so the bundled HCL library that ships
# in cmd/rampart/assets/ is materialized on disk under
# #{HOMEBREW_PREFIX}/share/rampart/, where the binary's relative-to-
# executable lookup (<exe-dir>/../share/rampart) finds it without any
# build-time path baked in.
class Rampart < Formula
  desc "Cross-platform sandbox wrapper for AI coding agents"
  homepage "https://github.com/visigoth/rampart"
  license "MIT"
  head "https://github.com/visigoth/rampart.git", branch: "main"

  # Pin the latest tagged release. `just release X.Y.Z` updates these
  # two lines automatically — or run `brew bump-formula-pr` if a tap is set up.
  url "https://github.com/visigoth/rampart/archive/refs/tags/v0.1.0.tar.gz"
  sha256 "0000000000000000000000000000000000000000000000000000000000000000"
  version "0.1.0"

  depends_on "go" => :build
  on_linux do
    depends_on "libseccomp"
  end

  def install
    # Build the binary. The plist linker hack only applies on macOS;
    # Linux skips it.
    ldflags = ["-s", "-w"]
    if OS.mac?
      plist_path = buildpath/"cmd/rampart/Info.plist"
      ldflags << "-linkmode" << "external"
      ldflags << "-extldflags=-Wl,-sectcreate,__TEXT,__info_plist,#{plist_path}"
    end

    system "go", "build",
           *std_go_args(ldflags: ldflags.join(" "), output: bin/"rampart"),
           "./cmd/rampart"

    # Bundled agent + module library. Goes to share/rampart/ so the
    # binary's relative lookup (<bin>/../share/rampart) finds it.
    library_root = share/"rampart"
    library_root.install Dir["cmd/rampart/assets/agents"]
    library_root.install Dir["cmd/rampart/assets/modules"]

    # Man page generated from the binary itself.
    mkdir_p man1
    system bin/"rampart", "docs", "man", "--output-dir", man1

    # Shell completions.
    generate_completions_from_executable(bin/"rampart", "completion")
  end

  def caveats
    <<~EOS
      The rampart binary discovers its bundled agent + module library at:
        #{share}/rampart/

      To shadow a bundled agent or module, drop a same-named file under:
        ~/.local/share/rampart/

      Rampart never writes to either directory; your overrides survive
      brew upgrade. The brew-managed copy is wiped and replaced on each
      upgrade.

      On macOS this formula's binary is ad-hoc signed. If you want stable
      Keychain ACLs across reinstalls (so the MITM CA private key isn't
      reprompted on every upgrade), build from source with the
      "Rampart Local Dev" identity in your Keychain — see the project's
      Justfile header for setup steps.
    EOS
  end

  test do
    assert_match "rampart", shell_output("#{bin}/rampart --help")
    # The bundled library should be visible to the running binary.
    assert_predicate share/"rampart/agents/coding.hcl", :exist?
  end
end
