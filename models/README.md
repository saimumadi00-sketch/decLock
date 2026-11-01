# Face models

Gatekeeper refuses to load any of these files unless its SHA-256 matches the value pinned in
`gatekeeper/faces.py` (`MODEL_HASHES`).

| File | What it does | Source | Licence |
|---|---|---|---|
| `scrfd_500m.onnx` | SCRFD-500M face detector with 5 landmarks | `det_500m.onnx` from InsightFace [`buffalo_s.zip` (v0.7 release)](https://github.com/deepinsight/insightface/releases/tag/v0.7) | InsightFace pretrained models: **non-commercial research use only** |
| `arcface_mbf.onnx` | ArcFace (MobileFaceNet, WebFace600K) 512-d identity embedding | `w600k_mbf.onnx` from the same `buffalo_s.zip` | as above |
| `minifasnet_v2.onnx` | MiniFASNetV2 anti-spoofing, 2.7x face crop | converted from `2.7_80x80_MiniFASNetV2.pth`, [minivision-ai/Silent-Face-Anti-Spoofing](https://github.com/minivision-ai/Silent-Face-Anti-Spoofing) | Apache-2.0 |
| `minifasnet_v1se.onnx` | MiniFASNetV1SE anti-spoofing, 4.0x face crop | converted from `4_0_0_80x80_MiniFASNetV1SE.pth`, same repository | Apache-2.0 |

SHA-256 of the files as shipped:

```
5e4447f50245bbd7966bd6c0fa52938c61474a04ec7def48753668a9d8b4ea3a  scrfd_500m.onnx
9cc6e4a75f0e2bf0b1aed94578f144d15175f357bdc05e815e5c4a02b319eb4f  arcface_mbf.onnx
37fd1f3a1c4d06fe65a67db4f1ff009c22c1a3690dcb8c54e2c7a706ca7f736c  minifasnet_v2.onnx
834506239fdb8492b1364a603390b18891e954a7a57f512d1fa95de1bb32b7e1  minifasnet_v1se.onnx
```

The two InsightFace files are byte-for-byte the release files (renamed). The MiniFASNet files were
converted with [`tools/convert_minifasnet.py`](../tools/convert_minifasnet.py), which defines the
network itself, loads only the weights (`weights_only=True`), and checks the ONNX output against
PyTorch. A re-export with another PyTorch version can produce different bytes; if so, update
`MODEL_HASHES` to the new values the script prints.

Because of the InsightFace licence, this face pipeline suits a university project or personal use,
not a commercial product.
