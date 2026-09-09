from pathlib import Path
import shutil

def test_case_create():
    from aiof.core.case import Case

    # Clean up existing
    case_dir = Path("cases") / "20260909112051"
    if case_dir.exists():
        shutil.rmtree(case_dir)

    case = Case.create(name="Test-Case", examiner="Test User")
    assert case is not None
    assert (case.path / "case.json").exists()
    assert (case.path / "evidence").exists()
    assert (case.path / "artifacts").exists()
    assert (case.path / "reports").exists()
