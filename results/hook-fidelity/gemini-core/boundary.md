## Hook runner files across every non-nightly release in the range

232 releases hashed (0 failed to download). A line is a run of consecutive releases whose hookRunner.js, hookAggregator.js and hookEventHandler.js are byte-identical (first 16 hex digits of sha256, `hookRunner/hookAggregator/hookEventHandler`). The files are compared, not executed: a different file is not shown to behave differently, and an identical file is not shown to behave identically if something it calls changed.

- `0.24.0-preview.0` .. `0.24.5` (10 releases): 82f824e0/1f7198ed/bfce659e
- `0.25.0-preview.0` .. `0.26.0-preview.4` (13 releases): 82f824e0/1f7198ed/b4b54ef2
- `0.26.0-preview.5` .. `0.26.0` (2 releases): 82f824e0/bbed4596/b4b54ef2
- `0.27.0-preview.0` .. `0.27.4` (14 releases): f3a735f2/bbed4596/c33068f0
- `0.28.0-preview.0` .. `0.28.2` (12 releases): f3a735f2/bbed4596/b35d99c9
- `0.29.0-preview.0` .. `0.29.7` (14 releases): 6641c3d4/555bc248/b35d99c9
- `0.30.0-preview.0` .. `0.30.1` (9 releases): ff9a8e7c/555bc248/b35d99c9
- `0.31.0-preview.0` .. `0.32.1` (8 releases): e07014c9/c3047a35/f131aebe
- `0.33.0-preview.0` .. `0.33.2` (19 releases): be2ab510/c3047a35/f131aebe
- `0.34.0-preview.0` .. `0.34.0` (6 releases): 709732e9/c38c3016/ce840d1f
- `0.35.0-preview.0` .. `0.35.3` (10 releases): 709732e9/c38c3016/c95de295
- `0.36.0-preview.0` .. `0.37.2` (15 releases): 709732e9/68fe4b9f/aca58757
- `0.38.0-preview.0` .. `0.38.2` (4 releases): b9da1098/68fe4b9f/ed0e74c2
- `0.39.0-preview.0` .. `0.42.0` (24 releases): 764e6ec7/68fe4b9f/ed0e74c2
- `0.43.0-preview.0` .. `0.67.0-preview.0` (72 releases): 764e6ec7/68fe4b9f/edf7f6c7

Mentions of `forcedDecision` in the shell tool's source (0 means its `shouldConfirmExecute` takes no forced decision, so a hook `ask` on a shell call is dropped there):

- `0.35.3` .. `0.37.2` (16 releases): 0
- `0.38.0-preview.0` .. `0.39.1` (9 releases): 2
- `0.40.0-preview.0` .. `0.40.1` (8 releases): 3
