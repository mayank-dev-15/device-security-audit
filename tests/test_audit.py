import pytest, sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

def test_import():
    from device_security_audit import run_audit
    assert callable(run_audit)

def test_run_audit():
    from device_security_audit import run_audit
    result = run_audit()
    assert isinstance(result, dict)

def test_check_firewall():
    from device_security_audit import check_firewall
    result = check_firewall()
    assert isinstance(result, dict)

def test_check_open_ports():
    from device_security_audit import check_open_ports
    result = check_open_ports()
    assert isinstance(result, list)
