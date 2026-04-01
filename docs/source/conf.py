import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))
# If you do not use src-layout, use:
# sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

project = "fwtool"
copyright = "2025, Mohammad Mohsen"
author = "Mohammad Mohsen"
release = "1.0.0"

extensions = [
    "sphinx.ext.autodoc",
    "sphinx.ext.napoleon",
    "sphinx.ext.viewcode",
    "myst_parser",
    "sphinx_autodoc_typehints",
]

templates_path = ["_templates"]
exclude_patterns = []

html_theme = "alabaster"
