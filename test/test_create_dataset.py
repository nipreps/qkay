import sys
import glob
import json
import os
from importlib.machinery import SourceFileLoader


def test_dataset_creation_without_description(tmp_path):
    dataset_dir = tmp_path / "ds1"
    dataset_dir.mkdir()
    (dataset_dir / "sub-001.html").write_text("<html></html>")

    sys.path.append('qkay')
    mod = SourceFileLoader('qkay_module', 'qkay/qkay.py').load_module()
    Dataset = mod.Dataset

    dataset_path = str(dataset_dir)
    desc_files = glob.glob(os.path.join(dataset_path, '**', 'dataset_description.json'), recursive=True)
    if desc_files:
        with open(desc_files[0]) as f:
            data_description = json.load(f)
        dataset_name = data_description.get('Name', dataset_dir.name)
        if dataset_name == 'MRIQC - MRI Quality Control':
            dataset_name = dataset_dir.name
    else:
        dataset_name = dataset_dir.name

    dataset = Dataset(name=dataset_name, path_dataset=dataset_path)
    assert dataset.validate_dataset() is True
    assert dataset.name == dataset_dir.name
