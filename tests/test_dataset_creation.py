import importlib
import sys
import os
import json
import glob
from pathlib import Path

sys.modules['index'] = importlib.import_module('qkay.index')
from qkay.qkay import app, Dataset


class DummyQuery:
    def first(self):
        return None

def patch_dataset(monkeypatch, saved):
    monkeypatch.setattr(Dataset, '_get_collection', lambda *a, **k: None)
    monkeypatch.setattr(Dataset, 'objects', lambda *a, **kw: DummyQuery())
    monkeypatch.setattr(Dataset, 'save', lambda self: saved.update({'name': self.name, 'path': self.path_dataset}))


def test_create_dataset_with_description(monkeypatch, tmp_path):
    ds_name = 'dsdesc'
    root = Path('/datasets') / ds_name
    root.mkdir(parents=True, exist_ok=True)
    (root / 'report.html').write_text('<html></html>')
    (root / 'dataset_description.json').write_text(json.dumps({'Name': 'Fancy'}))

    saved = {}
    patch_dataset(monkeypatch, saved)

    client = app.test_client()
    with app.app_context():
        res = client.post('/create_dataset', data={'datasets[]': [ds_name]})

    assert res.status_code == 302
    assert saved['name'] == 'Fancy'
    assert saved['path'] == str(root)

    # cleanup
    os.remove(root / 'report.html')
    os.remove(root / 'dataset_description.json')
    os.rmdir(root)


def test_create_dataset_without_description(monkeypatch, tmp_path):
    ds_name = 'dsnodec'
    root = Path('/datasets') / ds_name
    root.mkdir(parents=True, exist_ok=True)
    (root / 'report.html').write_text('<html></html>')

    saved = {}
    patch_dataset(monkeypatch, saved)

    # Patch glob.glob to mimic missing dataset_description.json
    monkeypatch.setattr(glob, 'glob', lambda *a, **kw: [''])

    client = app.test_client()
    with app.app_context():
        res = client.post('/create_dataset', data={'datasets[]': [ds_name]})

    assert res.status_code == 302
    assert saved['name'] == ds_name
    assert saved['path'] == str(root)

    # cleanup
    os.remove(root / 'report.html')
    os.rmdir(root)

