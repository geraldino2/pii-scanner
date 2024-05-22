import re


class CPFScanner:
    def __init__(self, regexLookaheadCheckbox):
        # type: (JCheckBox) -> None
        """Defines metadata"""
        self.type = "CPF"
        self._regexLookaheadCheckbox = regexLookaheadCheckbox

    def isValidCpf(self, cpfCandidate):
        # type: (str) -> boolean
        """Check if the CPF candidate is actually a valid CPF"""
        cpf = "".join(filter(str.isdigit, cpfCandidate))
        cpf = [int(char) for char in cpf]

        if len(cpf) != 11 or len({char for char in cpf}) == 1:
            return False

        for i in range(9, 11):
            value = sum((cpf[num] * ((i + 1) - num) for num in range(0, i)))
            digit = ((value * 10) % 11) % 10
            if digit != cpf[i]:
                return False
        return True

    def find(self, text):
        # type: (str) -> Set[str]
        """
        Find CPF candidates using an aggressive regexp that allows
        overlapping and inconsistent separators, validates them and returns
        a list of matches
        """
        regexp = r"(\d{3}\.\d{3}\.\d{3}-\d{2})|(\d{11})"
        if self._regexLookaheadCheckbox.isSelected():
            regexp = r"(?=({0}))".format(regexp)
        cpfRegex = re.compile(regexp)

        matches = set()

        for regexMatch in cpfRegex.findall(text):
            for cpfCandidate in regexMatch:
                if self.isValidCpf(cpfCandidate):
                    matches.add(cpfCandidate)

        return matches
