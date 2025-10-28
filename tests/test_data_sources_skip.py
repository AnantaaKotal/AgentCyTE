import csv
import tempfile
from pathlib import Path

from webapp.app_backend import _validate_and_normalize_data_source_csv


def _write_csv(path: Path, header, rows):
    with path.open('w', encoding='utf-8', newline='') as f:
        w = csv.writer(f)
        w.writerow(header)
        for r in rows:
            w.writerow(r)


def test_skip_invalid_rows():
    header = ["Name", "Path", "Type", "Startup", "Vector"]
    valid_row = ["n1", "/tmp/a", "artifact", "yes", "local"]
    bad_type = ["n2", "/tmp/b", "wrongtype", "yes", "local"]
    missing_name = ["", "/tmp/c", "artifact", "yes", "local"]
    with tempfile.TemporaryDirectory() as td:
        p = Path(td) / "ds.csv"
        _write_csv(p, header, [valid_row, bad_type, missing_name, valid_row])
        ok, note, norm_rows, skipped = _validate_and_normalize_data_source_csv(str(p), skip_invalid=True)
        assert ok is True
        # Expect 2 valid rows retained (header + two valid rows)
        assert len(norm_rows) == 1 + 2
        # Two rows skipped
        assert len(skipped) == 2
        assert all(isinstance(i, int) for i in skipped)
        assert 'skipped' in note.lower()


    def test_bom_header_handled():
        # Simulate a file with UTF-8 BOM before Name
        header = ["\ufeffName", "Path", "Type", "Startup", "Vector"]
        rows = [
            ["n1", "/tmp/a", "artifact", "yes", "local"],
        ]
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "bom.csv"
            _write_csv(p, header, rows)
            ok, note, norm_rows, skipped = _validate_and_normalize_data_source_csv(str(p), skip_invalid=True)
            assert ok
            assert skipped == []
            assert norm_rows[0][0] == 'Name'
