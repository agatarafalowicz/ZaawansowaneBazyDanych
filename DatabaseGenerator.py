from sqlalchemy import create_engine, MetaData
from sqlalchemy.orm import sessionmaker
from collections import defaultdict, deque
from faker import Faker
import random

import BasicDataGenerator
import TableOrder

# Konfiguracja połączenia
DATABASE_URL = "postgresql://postgres:password@localhost:5432/sklep"

# Inicjalizacja
engine = create_engine(DATABASE_URL)
metadata = MetaData()
metadata.reflect(bind=engine)
faker = Faker()
specialData = dict()

#Zbiór istniejących wartości PK dla szybkiego dostępu
existing_primary_keys = defaultdict(list)


#Generowanie wartości dla kolumn
def generate_fake_value(column, table_name):
    name = column.name.lower()
    coltype = str(column.type).lower()

    # Jeśli kolumna to FK
    for fk in column.foreign_keys:
        referred_table = fk.column.table.name
        if existing_primary_keys[referred_table]:
            return random.choice(existing_primary_keys[referred_table])
        else:
            raise ValueError(f"No available foreign key values for {table_name}.{column.name}")

    if (table_name, name) in specialData:
        value = BasicDataGenerator.GenerateData(specialData[table_name, name])
        return value

    # Typowe generowanie danych
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
        return None

# 🧪 Generowanie danych do tabel
def generuj_dane_dla_tabel(engine, metadata, liczba_wierszy=5):
    Session = sessionmaker(bind=engine)
    session = Session()

    graph = TableOrder.build_dependency_graph(metadata)
    sorted_tables = TableOrder.topological_sort(graph)

    print("Kolejność generowania tabel:")
    for t in sorted_tables:
        print(f" - {t}")

    for table_name in sorted_tables:
        table = metadata.tables[table_name]
        print(f"\nGenerowanie danych dla tabeli: {table_name}")

        pk_column = [col for col in table.columns if col.primary_key]
        if not pk_column:
            print(f"Tabela {table_name} nie ma klucza głównego!")
            continue

        for _ in range(liczba_wierszy):
            values = {}
            try:
                for column in table.columns:
                    if column.autoincrement or column.primary_key:
                        continue

                    if (table_name, column.name) in specialData:
                        values[column.name] = BasicDataGenerator.GenerateData(specialData[table_name, column.name])
                    else:
                        values[column.name] = generate_fake_value(column, table_name)

                ins = table.insert().values(**values)
                result = session.execute(ins)

                # Po wstawieniu zapamiętaj wartość nowego PK
                inserted_pk = result.inserted_primary_key[0]
                existing_primary_keys[table_name].append(inserted_pk)

            except ValueError as e:
                print(f"Pomijam wiersz: {e}")
                continue

    session.commit()
    session.close()


if __name__ == "__main__":
    specialData = BasicDataGenerator.LoadDataTypes("plik.txt")
    generuj_dane_dla_tabel(engine, metadata, liczba_wierszy=5)