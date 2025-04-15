import string

from faker import Faker
import re
import random

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

print(GenerateData("<VIN>"))