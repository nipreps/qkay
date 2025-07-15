import importlib
import sys
from pathlib import Path

# Ensure qkay.qkay can import qkay.index via the short name 'index'
sys.modules['index'] = importlib.import_module('qkay.index')
from qkay.qkay import Dataset


def test_validate_dataset_positive(tmp_path):
    html = tmp_path / "sub-01" / "report.html"
    html.parent.mkdir(parents=True)
    html.write_text("<html></html>")
    ds = Dataset(name="ds", path_dataset=str(tmp_path))
    assert ds.validate_dataset()


def test_validate_dataset_no_html(tmp_path):
    ds = Dataset(name="ds", path_dataset=str(tmp_path))
    assert not ds.validate_dataset()


def test_validate_dataset_missing_path(tmp_path):
    ds = Dataset(name="ds", path_dataset=str(tmp_path / "missing"))
    assert not ds.validate_dataset()

