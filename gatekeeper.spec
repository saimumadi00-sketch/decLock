# PyInstaller spec: one shared analysis, two executables.
#   gatekeeper.exe  - console build for the CLI (init, add, usb, face, ...)
#   gatekeeperw.exe - windowed build for the background guard (no console window)
a = Analysis(
    ["gatekeeper_main.py"],
    datas=[("models", "models")],
    excludes=["pytest", "unittest", "pydoc"],
)
pyz = PYZ(a.pure)
cli = EXE(pyz, a.scripts, [], exclude_binaries=True, name="gatekeeper", console=True)
gui = EXE(pyz, a.scripts, [], exclude_binaries=True, name="gatekeeperw", console=False)
coll = COLLECT(cli, gui, a.binaries, a.datas, name="gatekeeper")
