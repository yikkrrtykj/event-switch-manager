# Windows Artifact delivery convention

User-facing GitHub Actions artifacts contain an already-extracted onedir payload.

- `windows-console-lab`: `EventSwitchManager-ConsoleLab/` contents directly,
  including GUI/CLI EXEs, `_internal`, instructions, Build Record, dependency
  manifest and checksum manifest. One download/extraction is enough to run the
  GUI EXE. It contains no nested build ZIP.
- `windows-console-lab-build-archive`: the engineering-only build ZIP and its
  Build Record/SHA manifest. It is not part of the user runtime artifact.
- `windows-console-lab-smoke-evidence`: CI smoke reports only.
- `windows-portable-runtime`: the `EventSwitchManager/` onedir contents and the
  Build Record; no nested ZIP.
- `windows-portable-build-archive`: engineering-only build ZIP.
- `windows-portable-smoke-evidence`: CI smoke reports and logs.

SHA meanings are distinct:

- **EXE SHA-256**: hash of the individual executable.
- **Build ZIP SHA-256**: hash of the engineering archive, not the downloaded
  user artifact.
- **Artifact digest / ID**: GitHub Actions artifact metadata; not the same as
  either EXE or build ZIP SHA.

The user runtime is verified by a CI job that downloads the uploaded artifact
once, checks that no `.zip` remains inside it, runs the GUI/CLI smoke, and checks
the package checksum manifest.
