class GardenCli < Formula
  desc "Development engine for Kubernetes"
  homepage "https://garden.io"
  url "{{{tarballUrl}}}"
  version "{{version}}"
  sha256 "{{sha256}}"

  def install
    libexec.install "garden", "fsevents.node", "static", "pty.node"
    bin.install_symlink libexec/"garden"
  end

  test do
    # just make sure the command works
    system bin/"garden", "--help"
  end
end
