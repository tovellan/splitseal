# Similarity plugin API

Similarity plugins are optional Python distributions registered under the
`splitseal.similarity` entry-point group. An entry point must load a zero-argument class
instance with `name`, `version`, and `analyze` attributes.

```python
from collections.abc import Iterable, Mapping, Sequence
from typing import Any

from splitseal.canonical import Record
from splitseal.plugins import SimilarityFinding


class ExamplePlugin:
    name = "example"
    version = "1.0.0"

    def analyze(
        self,
        splits: Mapping[str, Sequence[Record]],
        settings: Mapping[str, Any],
    ) -> Iterable[SimilarityFinding]:
        threshold = float(settings["threshold"])
        # Compare records using a method appropriate for the dataset.
        return []
```

Register it in the plugin package:

```toml
[project.entry-points."splitseal.similarity"]
example = "example_plugin:ExamplePlugin"
```

Configure it with an explicit operating point:

```toml
[[similarity]]
plugin = "example"

[similarity.settings]
threshold = 0.91
```

The example value is synthetic and is not a recommendation. SplitSeal deliberately has
no default threshold. The plugin owns the meaning and validation of its settings.

Any returned finding blocks the freeze. Public attestations report only `pass` or
`not_run`; plugin names, versions, scores, settings, record indexes, and split names stay
inside local execution or the encrypted private manifest.

The declared plugin `name` must be a non-empty string equal to the configured entry-point
name, and `version` must be a non-empty string. Entry-point discovery, loading, identity,
and interface failures return `SS060`. Failures from a custom loader, identity or
interface validation, analysis iteration, or version evidence return `SS061`. No release
artifacts are written after either failure.

Plugins are trusted code with direct access to private records. Process isolation,
network restriction, deterministic execution, and dependency review are the operator's
responsibility.
