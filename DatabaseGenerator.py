from sqlalchemy import create_engine, MetaData, Table
from sqlalchemy.orm import sessionmaker
from faker import Faker
import random

import BasicDataGenerator

DATABASE_URL = "postgresql://postgres:password@localhost:5432/Przychodnia"

engine = create_engine(DATABASE_URL)
metadata = MetaData()
metadata.reflect(bind=engine)

faker = Faker()
specialData = dict()

def generate_fake_value(column, table):
    name = column.name.lower()
    coltype = str(column.type).lower()


    if (table, name) in specialData:
        value = BasicDataGenerator.GenerateData(specialData[table, name])
        return value

    if "int" in coltype:
        return random.randint(1, 100)
    elif "char" in coltype or "text" in coltype:
        if "email" in name:
            return faker.email()
        elif "name" in name:
            return faker.name()
        elif "address" in name:
            return faker.address()
        else:
            return faker.word()
    elif "date" in coltype:
        return faker.date()
    elif "bool" in coltype:
        return random.choice([True, False])
    elif "numeric" in coltype or "float" in coltype or "double" in coltype:
        return round(random.uniform(1.0, 1000.0), 2)
    else:
        return None  # brak wartości do generowania

def generuj_dane_dla_tabel(engine, metadata, liczba_wierszy=5):
    Session = sessionmaker(bind=engine)
    session = Session()

    for table_name, table in metadata.tables.items():
        print(f"🧪 Generowanie danych dla tabeli: {table_name}")
        for _ in range(liczba_wierszy):
            values = {}
            BasicDataGenerator.ClearSpecialValues()
            for column in table.columns:
                if column.autoincrement or column.primary_key:
                    continue  # pomijamy ID/PK
                values[column.name] = generate_fake_value(column, table_name)

            ins = table.insert().values(**values)
            session.execute(ins)

    session.commit()
    session.close()

specialData = BasicDataGenerator.LoadDataTypes("plik.txt")
generuj_dane_dla_tabel(engine, metadata, liczba_wierszy=5)