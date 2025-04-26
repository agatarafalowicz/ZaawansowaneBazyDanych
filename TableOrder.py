from collections import defaultdict, deque

def build_dependency_graph(metadata):
    graph = defaultdict(set)  # tabela -> zbiór tabel od których zależy (FK)
    all_tables = set(metadata.tables.keys())

    for table_name, table in metadata.tables.items():
        for column in table.columns:
            for fk in column.foreign_keys:
                referred_table = fk.column.table.name
                graph[table_name].add(referred_table)

    # Upewnij się, że wszystkie tabele są w grafie (nawet jeśli nie mają zależności)
    for table in all_tables:
        graph.setdefault(table, set())

    return graph


def topological_sort(graph):
    # Inicjalizacja stopnia wejścia dla każdej tabeli
    in_degree = {table: 0 for table in graph}

    # Odwrócony graf zależności
    reverse_graph = defaultdict(set)

    for table in graph:
        reverse_graph[table] = set()

    # Budowanie grafu
    for table, deps in graph.items():
        for dep in deps:
            in_degree[table] += 1  # Zwiększamy stopień wejścia dla tabeli 'dep'
            reverse_graph[dep].add(table)  # Tabela 'table' zależy od 'dep'

    # Kolejka tabel, które nie mają zależności (in_degree == 0)
    queue = deque([table for table in in_degree if in_degree[table] == 0])

    sorted_tables = []

    while queue:
        table = queue.popleft()
        sorted_tables.append(table)

        # Aktualizacja stopni wejścia zależnych tabel
        for dependent in reverse_graph[table]:
            in_degree[dependent] -= 1
            if in_degree[dependent] == 0:
                queue.append(dependent)

    # Jeśli liczba posortowanych tabel różni się od liczby tabel w grafie, wykryto cykl
    if len(sorted_tables) != len(graph):
        raise Exception("🛑 Cyclic dependency detected between tables!")

    return sorted_tables
