import pytest
import requests
from unittest.mock import patch
from project import check_password_strength, check_pwned_api, format_for_csv


def test_strong_password():
    
    score, feedback = check_password_strength("StrongP@ssw0rd123")
    assert score == 5
    assert not feedback

def test_weak_password_short():
    
    score, feedback = check_password_strength("short")
    assert "Should be at least 12 characters long." in feedback

def test_weak_password_no_upper():
    
    score, feedback = check_password_strength("nouppercase@123")
    assert "Missing an uppercase letter." in feedback

def test_weak_password_no_symbol_or_number():
    
    score, feedback = check_password_strength("PasswordWithoutThem")
    assert "Missing a number." in feedback
    assert "Missing a special character." in feedback


@patch('requests.get')
def test_pwned_password(mock_get):
    
    mock_get.return_value.text = "1E4C9B93F3F0682250B6CF8331B7EE68FD8:3680000"
    mock_get.return_value.raise_for_status.return_value = None
    
    count = check_pwned_api("password")
    assert count > 0

@patch('requests.get')
def test_not_pwned_password(mock_get):
    
    mock_get.return_value.text = "0018A45C4D1DEF81644B54AB7F969B88D65:3" # A different hash
    mock_get.return_value.raise_for_status.return_value = None

    count = check_pwned_api("aVerySecurePasswordNotInTheList123!@#")
    assert count == 0


def test_format_for_csv_normal():

    data = {
        "Google": {"username": "test@gmail.com", "password": "pass1"},
        "GitHub": {"username": "tester", "password": "pass2"}
    }
    expected = [
        ["service", "username", "password"],
        ["Google", "test@gmail.com", "pass1"],
        ["GitHub", "tester", "pass2"]
    ]
    assert format_for_csv(data) == expected

def test_format_for_csv_empty():
    
    data = {}
    expected = [["service", "username", "password"]]
    assert format_for_csv(data) == expected
    
def test_format_for_csv_invalid_input():
    
    with pytest.raises(TypeError):
        format_for_csv(["not", "a", "dictionary"])

