# PyInstaller spec: one shared analysis, two executables.
#   gatekeeper.exe  - console build for the CLI (init, add, usb, face, ...)
#   gatekeeperw.exe - windowed build for the background guard (no console window)
a = Analysis(
    ["gatekeeper_main.py"],
    datas=[("models", "models")],
    # Large packages that other libraries import optionally. Gatekeeper never uses them, but
    # PyInstaller bundles them if they happen to be installed in the build environment.
    excludes=[
        "pytest", "unittest", "pydoc",
        "torch", "torchvision", "torchaudio", "transformers", "datasets", "huggingface_hub",
        "tensorflow", "jax", "sklearn", "scipy", "sympy", "onnx",
        "pandas", "polars", "pyarrow", "matplotlib", "IPython",
        "openai", "aiohttp", "pydantic", "jinja2", "fsspec", "dill",
    ],
)
pyz = PYZ(a.pure)
cli = EXE(pyz, a.scripts, [], exclude_binaries=True, name="gatekeeper", console=True)
gui = EXE(pyz, a.scripts, [], exclude_binaries=True, name="gatekeeperw", console=False)
coll = COLLECT(cli, gui, a.binaries, a.datas, name="gatekeeper")
