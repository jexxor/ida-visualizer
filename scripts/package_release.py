"""Bundle the IDA plugin and one platform's native renderer."""

from argparse import ArgumentParser
from pathlib import Path
from zipfile import ZIP_DEFLATED, ZipFile


ROOT = Path(__file__).resolve().parents[1]
LIBRARIES = {
    "linux-x86_64": "libvisualizer.so",
    "windows-x86_64": "visualizer.dll",
}
FILES = ("visualizer.py", "visualizer_core.py", "README.md", "LICENSE")
PACKAGES = ("visualizer_engine", "visualizer_ui")


def main():
    parser = ArgumentParser(description=__doc__)
    parser.add_argument("--native", type=Path, required=True)
    parser.add_argument("--platform", choices=LIBRARIES, required=True)
    parser.add_argument("--version", required=True)
    args = parser.parse_args()

    native = args.native.resolve()
    expected_name = LIBRARIES[args.platform]
    if not native.is_file() or native.name != expected_name:
        parser.error(f"expected a built {expected_name}: {native}")

    output_dir = ROOT / "dist"
    output_dir.mkdir(exist_ok=True)
    archive = output_dir / f"ida-visualizer-{args.version}-{args.platform}.zip"
    with ZipFile(archive, "w", ZIP_DEFLATED) as bundle:
        for name in FILES:
            bundle.write(ROOT / name, name)
        for package in PACKAGES:
            for source in sorted((ROOT / package).glob("*.py")):
                bundle.write(source, source.relative_to(ROOT))
        bundle.write(native, expected_name)
    print(archive)


if __name__ == "__main__":
    main()
