import unittest
from mock import Mock, patch
from piiscanner import PIIScanner


class TestUnformatedCpf(unittest.TestCase):
    @patch.object(PIIScanner, "createIssue")
    def test_treatResponse(self, mock_createIssue):
        mock_regexLookaheadCheckbox = Mock()
        mock_regexLookaheadCheckbox.isSelected.return_value = False
        mock_regexJwtCheckbox = Mock()
        mock_regexJwtCheckbox.isSelected.return_value = False
        mock_regexBase64Checkbox = Mock()
        mock_regexBase64Checkbox.isSelected.return_value = False
        mock_createIssue.return_value = None

        scanner = PIIScanner(
            mock_regexLookaheadCheckbox, mock_regexJwtCheckbox, mock_regexBase64Checkbox
        )
        scanner.treatResponse(body="12345678909")

        mock_createIssue.assert_called_once()


class TestFormatedCpf(unittest.TestCase):
    @patch.object(PIIScanner, "createIssue")
    def test_treatResponse(self, mock_createIssue):
        mock_regexLookaheadCheckbox = Mock()
        mock_regexLookaheadCheckbox.isSelected.return_value = False
        mock_regexJwtCheckbox = Mock()
        mock_regexJwtCheckbox.isSelected.return_value = False
        mock_regexBase64Checkbox = Mock()
        mock_regexBase64Checkbox.isSelected.return_value = False
        mock_createIssue.return_value = None

        scanner = PIIScanner(
            mock_regexLookaheadCheckbox, mock_regexJwtCheckbox, mock_regexBase64Checkbox
        )
        scanner.treatResponse(body="123.456.789-09")

        mock_createIssue.assert_called_once()


class TestMalformedCpf(unittest.TestCase):
    @patch.object(PIIScanner, "createIssue")
    def test_treatResponse(self, mock_createIssue):
        mock_regexLookaheadCheckbox = Mock()
        mock_regexLookaheadCheckbox.isSelected.return_value = False
        mock_regexJwtCheckbox = Mock()
        mock_regexJwtCheckbox.isSelected.return_value = False
        mock_regexBase64Checkbox = Mock()
        mock_regexBase64Checkbox.isSelected.return_value = False
        mock_createIssue.return_value = None

        scanner = PIIScanner(
            mock_regexLookaheadCheckbox, mock_regexJwtCheckbox, mock_regexBase64Checkbox
        )
        scanner.treatResponse(body="12.3456.789-09")

        mock_createIssue.assert_not_called()


class TestLookaheadCpf(unittest.TestCase):
    @patch.object(PIIScanner, "createIssue")
    def test_treatResponse(self, mock_createIssue):
        mock_regexLookaheadCheckbox = Mock()
        mock_regexLookaheadCheckbox.isSelected.return_value = True
        mock_regexJwtCheckbox = Mock()
        mock_regexJwtCheckbox.isSelected.return_value = False
        mock_regexBase64Checkbox = Mock()
        mock_regexBase64Checkbox.isSelected.return_value = False
        mock_createIssue.return_value = None

        scanner = PIIScanner(
            mock_regexLookaheadCheckbox, mock_regexJwtCheckbox, mock_regexBase64Checkbox
        )
        scanner.treatResponse(body="00000000000123.456.789-09")

        mock_createIssue.assert_called_once()


class TestJwtCpf(unittest.TestCase):
    @patch.object(PIIScanner, "createIssue")
    def test_treatResponse(self, mock_createIssue):
        mock_regexLookaheadCheckbox = Mock()
        mock_regexLookaheadCheckbox.isSelected.return_value = False
        mock_regexJwtCheckbox = Mock()
        mock_regexJwtCheckbox.isSelected.return_value = True
        mock_regexBase64Checkbox = Mock()
        mock_regexBase64Checkbox.isSelected.return_value = False
        mock_createIssue.return_value = None

        scanner = PIIScanner(
            mock_regexLookaheadCheckbox, mock_regexJwtCheckbox, mock_regexBase64Checkbox
        )
        scanner.treatResponse(
            body="eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJPbmxpbmUgSldUIEJ1aWxkZXIiLCJpYXQiOjE3MTYzNDQyNjQsImV4cCI6MTc0Nzg4MDI2NCwiYXVkIjoid3d3LmV4YW1wbGUuY29tIiwic3ViIjoianJvY2tldEBleGFtcGxlLmNvbSIsIkdpdmVuTmFtZSI6IkpvaG5ueSIsIlN1cm5hbWUiOiJSb2NrZXQiLCJFbWFpbCI6Impyb2NrZXRAZXhhbXBsZS5jb20iLCJSb2xlIjpbIk1hbmFnZXIiLCJQcm9qZWN0IEFkbWluaXN0cmF0b3IiXSwiQ1BGIjoiMTIzLjQ1Ni43ODktMDkifQ.HqZt_Oa3bjdHkoBCPshaBitF6a6WaXFWn2JevRbVSy8"
        )

        mock_createIssue.assert_called_once()


class TestBase64Cpf(unittest.TestCase):
    @patch.object(PIIScanner, "createIssue")
    def test_treatResponse(self, mock_createIssue):
        mock_regexLookaheadCheckbox = Mock()
        mock_regexLookaheadCheckbox.isSelected.return_value = False
        mock_regexJwtCheckbox = Mock()
        mock_regexJwtCheckbox.isSelected.return_value = False
        mock_regexBase64Checkbox = Mock()
        mock_regexBase64Checkbox.isSelected.return_value = True
        mock_createIssue.return_value = None

        scanner = PIIScanner(
            mock_regexLookaheadCheckbox, mock_regexJwtCheckbox, mock_regexBase64Checkbox
        )
        scanner.treatResponse(body="MTIzLjQ1Ni43ODktMDkK")

        mock_createIssue.assert_called_once()


if __name__ == "__main__":
    unittest.main()
