from faker import Faker
import string
import re
import random


PESEL = dict()
VIN = dict()
faker = Faker()

# Regiony produkcji według pierwszej litery VIN
regions = {
    '1': 'Ameryka Północna',
    '2': 'Kanada',
    '3': 'Meksyk',
    'J': 'Japonia',
    'K': 'Korea Południowa',
    'S': 'Wielka Brytania',
    'W': 'Niemcy',
    'Z': 'Włochy'
}

# Przykładowi producenci i ich kody (litera 2)
producers = {
    'H': 'Honda',
    'T': 'Toyota',
    'V': 'Volkswagen',
    'B': 'BMW',
    'F': 'Ford',
    'M': 'Mazda'
}

# Typy pojazdów i napędów (VDS, pozycje 4–8)
vehicle_types = {
    'CM826': {'type': 'sedan', 'engine': '2.4L benzyna'},
    'JF835': {'type': 'SUV', 'engine': '2.0L diesel'},
    'XR710': {'type': 'kombi', 'engine': '1.6L benzyna'},
    'AB912': {'type': 'coupe', 'engine': '3.0L V6'},
}

# Rok modelowy na podstawie kodu w pozycji 10 VIN
year_codes = {
    'Y': 2000, '1': 2001, '2': 2002, '3': 2003, '4': 2004,
    '5': 2005, '6': 2006, '7': 2007, '8': 2008, '9': 2009,
    'A': 2010, 'B': 2011, 'C': 2012, 'D': 2013, 'E': 2014,
    'F': 2015, 'G': 2016, 'H': 2017, 'J': 2018, 'K': 2019,
    'L': 2020, 'M': 2021, 'N': 2022, 'P': 2023, 'R': 2024,
    'S': 2025
}

def ClearData():
    PESEL.clear()
    VIN.clear()


def PeselGenerator(data):
    types = {"PESEL", "BirthDay", "Gender", "FirstName", "LastName"}
    if data not in types:
        return "wrong type of data"

    if data in PESEL.keys():
        return PESEL[data]

    birth_date = faker.date_of_birth(minimum_age=0, maximum_age=100)
    gender = random.choice(['M', 'F'])  # M = mężczyzna, F = kobieta

    year = birth_date.year
    month = birth_date.month
    day = birth_date.day

    # Zakoduj miesiąc z uwzględnieniem wieku (zgodnie z systemem PESEL)
    if 1800 <= year <= 1899:
        month += 80
    elif 1900 <= year <= 1999:
        month += 0
    elif 2000 <= year <= 2099:
        month += 20
    elif 2100 <= year <= 2199:
        month += 40
    elif 2200 <= year <= 2299:
        month += 60

    # Pierwsze 6 cyfr PESEL-a
    pesel = f"{year % 100:02d}{month:02d}{day:02d}"

    # Kolejne 4 cyfry (losowe, ostatnia zależna od płci)
    serial = random.randint(0, 999)
    gender_digit = random.choice(range(0, 10, 2)) if gender == 'F' else random.choice(range(1, 10, 2))

    pesel += f"{serial:03d}{gender_digit}"

    # Oblicz cyfrę kontrolną
    weights = [1, 3, 7, 9, 1, 3, 7, 9, 1, 3]
    checksum = sum(int(pesel[i]) * weights[i] for i in range(10))
    control_digit = (10 - (checksum % 10)) % 10

    pesel += str(control_digit)

    PESEL["PESEL"] = pesel
    PESEL["BirthDay"] = birth_date
    if gender == "M":
        PESEL["Gender"] = "Male"
        PESEL["FirstName"] = faker.first_name_male()
        PESEL["LastName"] = faker.last_name_male()
    else:
        PESEL["Gender"] = "Female"
        PESEL["FirstName"] = faker.first_name_female()
        PESEL["LastName"] = faker.last_name_female()

    return PESEL[data]

def VinGenerator(data):
    types = {"Vin", "Region", "Producer", "VehicleType", "Engine", "ModelYear", "SerialNumber"}
    if data not in types:
        return "wrong type of data"

    if data in VIN.keys():
        return VIN[data]

    # WMI
    region_code = random.choice(list(regions.keys()))
    producer_code = random.choice(list(producers.keys()))
    wmi = region_code + producer_code + random.choice(string.ascii_uppercase)

    # VDS
    vds_code, vds_info = random.choice(list(vehicle_types.items()))
    check_digit = random.choice(string.digits + 'X')  # 9. znak, uproszczony (X = 10)

    # VIS
    year_code = random.choice(list(year_codes.keys()))
    factory_code = random.choice(string.ascii_uppercase.replace('I', '').replace('O', '').replace('Q', ''))
    serial_number = ''.join(random.choices(string.digits, k=6))

    VIN["Vin"] = wmi + vds_code + check_digit + year_code + factory_code + serial_number
    VIN["Region"] = regions[region_code]
    VIN["Producer"] = producers[producer_code]
    VIN["VehicleType"] = vds_info['type']
    VIN["Engine"] = vds_info['engine']
    VIN["ModelYear"] = year_codes[year_code]
    VIN["SerialNumber"] = serial_number
    return VIN[data]
