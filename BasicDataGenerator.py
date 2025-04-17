from faker import Faker
import re
import random

import SpecialDataGenerator


def LoadDataTypes(path):
    dane = {}

    with open(path, 'r', encoding='utf-8') as file:
        for line in file:
            line = line.strip()
            if not line:
                continue
            parts = line.split(':', 2)
            if len(parts) == 3:
                table, column, value = parts
                dane[(table, column)] = value
            else:
                print(f"⚠️ Błąd formatu: {line}")

    return dane

def detectPattern(text):
    patterns = [
        r'\([^()]*\)',       # () nawiasy okrągłe
        r'\[[^\[\]]*\]',     # [] nawiasy kwadratowe
        r'"[^"]*"'           # "" cudzysłów
    ]

    matches = []
    for pattern in patterns:
        matches += re.findall(pattern, text)

    return matches

def ClearSpecialValues():
    SpecialDataGenerator.ClearData()

def genNumber(text):
    lower, upper = text.split("-")
    return str(random.randint(int(lower), int(upper)))

def randomWord(text):
    words = text.split("/")
    return random.choice(words)

def randomText(size, faker):
    if int(size) < 5:
        return "new"
    return faker.text(int(size))

def GenerateData(text):
    if text.startswith('*'):
        parts = text[1:].split(':')
        if parts[0] == "PESEL":
            return SpecialDataGenerator.PeselGenerator(parts[1])
        elif parts[0] == "VIN":
            return SpecialDataGenerator.VIN(parts[1])
    faker = Faker()
    matches = detectPattern(text)
    newText = []
    for match in matches:
        if match.startswith('('):
            newText.append(genNumber(match[1:-1]))
            pass
        elif match.startswith('['):
            newText.append(randomWord(match[1:-1]))
            pass
        elif match.startswith('"'):
            newText.append(randomText(match[1:-1], faker))
            pass
    for x in range(len(newText)):
        text = text.replace(matches[x], newText[x], 1)
    return text

print(GenerateData("*PESEL:BirthDay"))