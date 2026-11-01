"""One-off converter: Minivision's MiniFASNet anti-spoofing weights (PyTorch) -> ONNX for Gatekeeper.

Gatekeeper runs models with onnxruntime only; PyTorch is needed just for this conversion.

The network is defined here (a re-implementation of the published MiniFASNet layout), so no code
from elsewhere runs: only the two weight files are needed, from
https://github.com/minivision-ai/Silent-Face-Anti-Spoofing (Apache-2.0),
resources/anti_spoof_models/. load_state_dict(strict=True) proves the layout matches the weights.

    python tools/convert_minifasnet.py <folder with the two .pth files> models/

Writes models/minifasnet_v2.onnx (2.7x crop) and models/minifasnet_v1se.onnx (4.0x crop), checks that
each ONNX file gives the same answer as PyTorch, and prints the SHA-256 values for faces.MODEL_HASHES.
"""

import hashlib
import sys
from collections import OrderedDict
from pathlib import Path

import numpy as np
import torch
from torch import nn

# Channel widths per layer of the two published variants ("1.8M" = V1/V1SE, "1.8M_" = V2).
KEEP = {
    "1.8M": [32, 32, 103, 103, 64, 13, 13, 64, 26, 26, 64, 13, 13, 64, 52, 52, 64, 231, 231, 128,
             154, 154, 128, 52, 52, 128, 26, 26, 128, 52, 52, 128, 26, 26, 128, 26, 26, 128, 308, 308,
             128, 26, 26, 128, 26, 26, 128, 512, 512],
    "1.8M_": [32, 32, 103, 103, 64, 13, 13, 64, 13, 13, 64, 13, 13, 64, 13, 13, 64, 231, 231, 128,
              231, 231, 128, 52, 52, 128, 26, 26, 128, 77, 77, 128, 26, 26, 128, 26, 26, 128, 308, 308,
              128, 26, 26, 128, 26, 26, 128, 512, 512],
}


class ConvBlock(nn.Module):  # conv -> batch norm -> PReLU
    def __init__(self, cin, cout, kernel=(1, 1), stride=(1, 1), padding=(0, 0), groups=1):
        super().__init__()
        self.conv = nn.Conv2d(cin, cout, kernel, stride, padding, groups=groups, bias=False)
        self.bn = nn.BatchNorm2d(cout)
        self.prelu = nn.PReLU(cout)

    def forward(self, x):
        return self.prelu(self.bn(self.conv(x)))


class LinearBlock(nn.Module):  # conv -> batch norm (no activation)
    def __init__(self, cin, cout, kernel=(1, 1), stride=(1, 1), padding=(0, 0), groups=1):
        super().__init__()
        self.conv = nn.Conv2d(cin, cout, kernel, stride, padding, groups=groups, bias=False)
        self.bn = nn.BatchNorm2d(cout)

    def forward(self, x):
        return self.bn(self.conv(x))


class SEModule(nn.Module):  # squeeze-and-excitation: re-weight channels by their average activity
    def __init__(self, channels, reduction):
        super().__init__()
        self.avg_pool = nn.AdaptiveAvgPool2d(1)
        self.fc1 = nn.Conv2d(channels, channels // reduction, 1, bias=False)
        self.bn1 = nn.BatchNorm2d(channels // reduction)
        self.relu = nn.ReLU(inplace=True)
        self.fc2 = nn.Conv2d(channels // reduction, channels, 1, bias=False)
        self.bn2 = nn.BatchNorm2d(channels)
        self.sigmoid = nn.Sigmoid()

    def forward(self, x):
        w = self.sigmoid(self.bn2(self.fc2(self.relu(self.bn1(self.fc1(self.avg_pool(x)))))))
        return x * w


class DepthWise(nn.Module):  # 1x1 expand -> depthwise 3x3 -> 1x1 project, optional residual (+ SE)
    def __init__(self, c1, c2, c3, residual=False, stride=(2, 2), se_reduct=None):
        super().__init__()
        self.conv = ConvBlock(c1[0], c1[1])
        self.conv_dw = ConvBlock(c2[0], c2[1], kernel=(3, 3), stride=stride, padding=(1, 1), groups=c2[0])
        self.project = LinearBlock(c3[0], c3[1])
        self.residual = residual
        if se_reduct:
            self.se_module = SEModule(c3[1], se_reduct)

    def forward(self, x):
        out = self.project(self.conv_dw(self.conv(x)))
        if not self.residual:
            return out
        if hasattr(self, "se_module"):
            out = self.se_module(out)
        return x + out


class Residual(nn.Module):  # a stack of residual DepthWise blocks; SE variants put SE on the last one
    def __init__(self, keep, starts, se):
        super().__init__()
        blocks = []
        for n, i in enumerate(starts):
            last = se and n == len(starts) - 1
            blocks.append(DepthWise((keep[i], keep[i + 1]), (keep[i + 1], keep[i + 2]), (keep[i + 2], keep[i + 3]),
                                    residual=True, stride=(1, 1), se_reduct=4 if last else None))
        self.model = nn.Sequential(*blocks)

    def forward(self, x):
        return self.model(x)


class MiniFASNet(nn.Module):
    def __init__(self, keep, se: bool, embedding_size=128, conv6_kernel=(5, 5), num_classes=3):
        super().__init__()
        k = keep
        self.conv1 = ConvBlock(3, k[0], kernel=(3, 3), stride=(2, 2), padding=(1, 1))
        self.conv2_dw = ConvBlock(k[0], k[1], kernel=(3, 3), padding=(1, 1), groups=k[1])
        self.conv_23 = DepthWise((k[1], k[2]), (k[2], k[3]), (k[3], k[4]))
        self.conv_3 = Residual(k, [4, 7, 10, 13], se)
        self.conv_34 = DepthWise((k[16], k[17]), (k[17], k[18]), (k[18], k[19]))
        self.conv_4 = Residual(k, [19, 22, 25, 28, 31, 34], se)
        self.conv_45 = DepthWise((k[37], k[38]), (k[38], k[39]), (k[39], k[40]))
        self.conv_5 = Residual(k, [40, 43], se)
        self.conv_6_sep = ConvBlock(k[46], k[47])
        self.conv_6_dw = LinearBlock(k[47], k[48], kernel=conv6_kernel, groups=k[48])
        self.linear = nn.Linear(512, embedding_size, bias=False)
        self.bn = nn.BatchNorm1d(embedding_size)
        self.prob = nn.Linear(embedding_size, num_classes, bias=False)

    def forward(self, x):
        for layer in (self.conv1, self.conv2_dw, self.conv_23, self.conv_3, self.conv_34, self.conv_4,
                      self.conv_45, self.conv_5, self.conv_6_sep, self.conv_6_dw):
            x = layer(x)
        x = self.bn(self.linear(x.flatten(1)))  # (dropout is a no-op at inference, so it is left out)
        return torch.softmax(self.prob(x), dim=1)  # probabilities, baked into the ONNX graph


MODELS = {  # output file -> (weights file, channel layout, has SE blocks)
    "minifasnet_v2.onnx": ("2.7_80x80_MiniFASNetV2.pth", "1.8M_", False),
    "minifasnet_v1se.onnx": ("4_0_0_80x80_MiniFASNetV1SE.pth", "1.8M", True),
}


def main(weights_dir: Path, out_dir: Path) -> None:
    import onnxruntime as ort
    out_dir.mkdir(parents=True, exist_ok=True)
    sample = torch.rand(1, 3, 80, 80) * 255  # the models take raw 0-255 BGR pixels
    for out_name, (weights, keep, se) in MODELS.items():
        net = MiniFASNet(KEEP[keep], se)
        # weights_only=True: accept tensors only, so a tampered .pth cannot run code while loading.
        state = torch.load(weights_dir / weights, map_location="cpu", weights_only=True)
        state = OrderedDict((k[7:] if k.startswith("module.") else k, v) for k, v in state.items())
        net.load_state_dict(state, strict=True)  # fails if the layout above doesn't match the weights
        net.eval()
        target = out_dir / out_name
        torch.onnx.export(net, sample, str(target), input_names=["input"], output_names=["probs"],
                          opset_version=13, dynamo=False)
        with torch.no_grad():
            expected = net(sample).numpy()
        got = ort.InferenceSession(str(target), providers=["CPUExecutionProvider"]).run(
            None, {"input": sample.numpy()})[0]
        assert np.allclose(expected, got, atol=1e-4), (out_name, expected, got)
        print(out_name, hashlib.sha256(target.read_bytes()).hexdigest())


if __name__ == "__main__":
    main(Path(sys.argv[1]), Path(sys.argv[2]))
