import secrets
import string
import time
import re
import tkinter as tk
import uuid
from collections import defaultdict
from tkinter import ttk, messagebox, simpledialog, filedialog
import psycopg2
from psycopg2 import sql
from faker import Faker
import random
import BasicDataGenerator
import SpecialDataGenerator
from datetime import datetime



class UniversalDataGenerator:
    def __init__(self, root):
        self.root = root
        self.root.title("Generator Danych")
        self.root.geometry("1200x800")

        self.conn = None
        self.cursor = None
        self.faker = Faker('pl_PL')
        self.tables = {}
        self.generation_rules = {}
        self.column_lengths_cache = {}
        self.special_data = self.load_special_data("plik.txt")
        self.current_config_widget = None
        self.primary_keys = defaultdict(list)
        self.foreign_keys = {}
        self.table_dependencies = defaultdict(list)
        self.generated_ids = defaultdict(list)
        self.auto_increment = defaultdict(dict)
        self.setup_ui()
        self.load_last_config()
        self.generated_values_cache = defaultdict(set)
        self.retry_limit = 500
        self.initialize_pk_cache()
        self.special_generators = {
            'PESEL': lambda param: SpecialDataGenerator.PeselGenerator(param),
            'VIN': SpecialDataGenerator.VinGenerator
        }
        current_seed = int(time.time() * 1000)
        random.seed(current_seed)
        Faker.seed(current_seed)



    def load_special_data(self, path):
        try:
            raw_data = BasicDataGenerator.LoadDataTypes(path)
            special_data = {}
            for (table, column), value in raw_data.items():
                key = (table.lower(), column.lower())
                special_data[key] = value
            return special_data
        except Exception as e:
            messagebox.showerror("Błąd", f"Błąd ładowania specjalnych danych: {str(e)}")
            return {}

    def initialize_pk_cache(self):
        if self.conn:
            try:
                self.cursor.execute("""
                    SELECT table_name, column_name 
                    FROM information_schema.key_column_usage 
                    WHERE constraint_name LIKE '%pkey'
                """)
                for table, column in self.cursor.fetchall():
                    self._load_existing_values(table, column)

                self.cursor.execute("""
                    SELECT table_name, column_name 
                    FROM information_schema.key_column_usage 
                    WHERE constraint_name IN (
                        SELECT constraint_name 
                        FROM information_schema.table_constraints 
                        WHERE constraint_type = 'UNIQUE'
                    )
                """)
                for table, column in self.cursor.fetchall():
                    self._load_existing_values(table, column)

            except Exception as e:
                self.log(f"Błąd inicjalizacji cache: {str(e)}")

    def _load_existing_values(self, table, column):
        try:
            self.cursor.execute(
                sql.SQL("SELECT {} FROM {}").format(
                    sql.Identifier(column),
                    sql.Identifier(table)
                )
            )
            existing = {str(r[0]) for r in self.cursor.fetchall()}
            self.generated_values_cache[(table, column)] = existing
            self.log(f"Zainicjowano cache dla {table}.{column}: {len(existing)} rekordów")
        except Exception as e:
            self.log(f"Błąd ładowania wartości dla {table}.{column}: {str(e)}")

    def setup_ui(self):
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill=tk.BOTH, expand=True)

        self.setup_connection_tab()
        self.setup_tables_tab()
        self.setup_generation_tab()
        self.setup_patterns_tab()

    def setup_connection_tab(self):
        tab = ttk.Frame(self.notebook)
        self.notebook.add(tab, text="Połączenie")

        frame = ttk.LabelFrame(tab, text="Parametry połączenia")
        frame.pack(fill=tk.X, padx=10, pady=5)

        ttk.Label(frame, text="Host:").grid(row=0, column=0, sticky=tk.W)
        self.host_entry = ttk.Entry(frame)
        self.host_entry.grid(row=0, column=1, sticky=tk.EW)
        self.host_entry.insert(0, "localhost")

        ttk.Label(frame, text="Port:").grid(row=0, column=2, sticky=tk.W)
        self.port_entry = ttk.Entry(frame, width=10)
        self.port_entry.grid(row=0, column=3)
        self.port_entry.insert(0, "5432")

        ttk.Label(frame, text="Baza danych:").grid(row=1, column=0, sticky=tk.W)
        self.db_entry = ttk.Entry(frame)
        self.db_entry.grid(row=1, column=1, sticky=tk.EW)

        ttk.Label(frame, text="Użytkownik:").grid(row=1, column=2, sticky=tk.W)
        self.user_entry = ttk.Entry(frame)
        self.user_entry.grid(row=1, column=3)

        ttk.Label(frame, text="Hasło:").grid(row=2, column=0, sticky=tk.W)
        self.password_entry = ttk.Entry(frame, show="*")
        self.password_entry.grid(row=2, column=1, sticky=tk.EW)

        ttk.Button(frame, text="Połącz", command=self.connect_to_db).grid(row=2, column=3, sticky=tk.E)

    def setup_tables_tab(self):
        tab = ttk.Frame(self.notebook)
        self.notebook.add(tab, text="Tabele")

        self.tree = ttk.Treeview(tab, columns=("type", "length", "nullable"), selectmode="extended")
        self.tree.heading("#0", text="Tabela/Kolumna")
        self.tree.heading("type", text="Typ")
        self.tree.heading("length", text="Długość")
        self.tree.heading("nullable", text="Nullable")
        self.tree.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)

        btn_frame = ttk.Frame(tab)
        btn_frame.pack(fill=tk.X, padx=10, pady=5)

        ttk.Button(btn_frame, text="Odśwież", command=self.load_tables).pack(side=tk.LEFT)
        ttk.Button(btn_frame, text="Konfiguruj", command=self.configure_table).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="Zapisz konfig", command=self.save_configuration).pack(side=tk.LEFT)
        ttk.Button(btn_frame, text="Wczytaj konfig", command=self.load_configuration).pack(side=tk.LEFT, padx=5)

    def setup_generation_tab(self):
        tab = ttk.Frame(self.notebook)
        self.notebook.add(tab, text="Generacja")

        main_frame = ttk.Frame(tab)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)


        left_frame = ttk.Frame(main_frame)
        left_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=5)

        ttk.Label(left_frame, text="Wybierz tabele do generowania:").pack(anchor=tk.W)

        self.tables_tree = ttk.Treeview(left_frame, columns=("count"), show="tree headings", selectmode="extended")
        self.tables_tree.heading("#0", text="Tabela")
        self.tables_tree.heading("count", text="Ilość rekordów")
        self.tables_tree.column("count", width=100, anchor=tk.CENTER)
        self.tables_tree.pack(fill=tk.BOTH, expand=True)

        scrollbar = ttk.Scrollbar(left_frame, orient="vertical", command=self.tables_tree.yview)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.tables_tree.configure(yscrollcommand=scrollbar.set)

        right_frame = ttk.Frame(main_frame)
        right_frame.pack(side=tk.RIGHT, fill=tk.Y, padx=5)

        ttk.Label(right_frame, text="Parametry:").pack()

        self.global_count_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(right_frame, text="Globalna ilość rekordów",
                        variable=self.global_count_var).pack(anchor=tk.W)

        self.records_entry = ttk.Entry(right_frame, width=10)
        self.records_entry.pack(pady=5)
        self.records_entry.insert(0, "100")

        ttk.Label(right_frame, text="Rozmiar partii:").pack()
        self.batch_entry = ttk.Entry(right_frame, width=10)
        self.batch_entry.pack(pady=5)
        self.batch_entry.insert(0, "10")

        btn_frame = ttk.Frame(right_frame)
        btn_frame.pack(pady=10)

        ttk.Button(btn_frame, text="Zaznacz wszystkie",
                   command=self.select_all_tables).pack(side=tk.LEFT, padx=2)
        ttk.Button(btn_frame, text="Odznacz wszystkie",
                   command=self.deselect_all_tables).pack(side=tk.LEFT, padx=2)

        ttk.Button(right_frame, text="Generuj dane",
                   command=self.generate_data).pack(pady=10)

        self.tables_tree.bind("<Double-1>", self.on_table_double_click)

        self.log_text = tk.Text(tab, height=10, state=tk.DISABLED)
        self.log_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)

        ttk.Button(tab, text="Wyczyść log",
                   command=self.clear_log).pack(side=tk.RIGHT, padx=10, pady=5)

    def on_table_double_click(self, event):
        """Obsługa edycji ilości rekordów przez podwójne kliknięcie"""
        region = self.tables_tree.identify("region", event.x, event.y)
        if region == "cell":
            column = self.tables_tree.identify_column(event.x)
            if column == "#1":
                item = self.tables_tree.identify_row(event.y)
                x, y, width, height = self.tables_tree.bbox(item, column)

                entry = ttk.Entry(self.tables_tree)
                entry.place(x=x, y=y, width=width, height=height)
                entry.insert(0, self.tables_tree.item(item, "values")[0])
                entry.select_range(0, tk.END)
                entry.focus_set()

                def save_edit():
                    self.tables_tree.set(item, column, entry.get())
                    entry.destroy()

                entry.bind("<FocusOut>", lambda e: save_edit())
                entry.bind("<Return>", lambda e: save_edit())

    def toggle_global_count(self):
        state = 'normal' if not self.global_count_var.get() else 'disabled'
        for child in self.tables_tree.get_children():
            entry = self.tables_tree.set(child, 'count')
            if isinstance(entry, ttk.Entry):
                entry.configure(state=state)

    def select_all_tables(self):
        for table in self.tables:
            self.tables_tree.selection_add(table)

    def deselect_all_tables(self):
        self.tables_tree.selection_remove(self.tables_tree.selection())

    def update_tables_list(self):
        """Aktualizuje listę dostępnych tabel"""
        self.tables_tree.delete(*self.tables_tree.get_children())
        for table in sorted(self.tables.keys()):
            self.tables_tree.insert("", "end", iid=table, text=table, values=("100",))

    def setup_patterns_tab(self):
        tab = ttk.Frame(self.notebook)
        self.notebook.add(tab, text="Własne wartości i wzorce")

        frame = ttk.LabelFrame(tab, text="Definicje wzorców i własnych wartości")
        frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)

        self.patterns_tree = ttk.Treeview(frame, columns=("definition"), selectmode="browse")
        self.patterns_tree.heading("#0", text="Symbol")
        self.patterns_tree.heading("definition", text="Definicja")
        self.patterns_tree.pack(fill=tk.BOTH, expand=True)

        self.pattern_definitions = {
            '(liczba-liczba)': 'Generator liczb z zakresu',
            '[wartość/wartość]': 'Wybór losowej wartości z listy',
            '"liczba"': 'Losowy tekst o długości podanej liczby',
            'N': 'Wzorzec dla cyfry (0-9)',
            'D': 'Wzorzec dla wielkiej litery (A-Z)',
            'M': 'Wzorzec dla małej litery (a-z)'
        }

        for symbol, definition in self.pattern_definitions.items():
            self.patterns_tree.insert("", "end", text=symbol, values=(definition,))

        btn_frame = ttk.Frame(tab)
        btn_frame.pack(fill=tk.X, padx=10, pady=5)

        ttk.Button(btn_frame, text="Dodaj wzór", command=self.add_pattern).pack(side=tk.LEFT)
        ttk.Button(btn_frame, text="Usuń wzór", command=self.remove_pattern).pack(side=tk.LEFT, padx=5)

    def connect_to_db(self):
        try:
            if self.conn:
                self.conn.close()

            self.conn = psycopg2.connect(
                host=self.host_entry.get(),
                port=self.port_entry.get(),
                dbname=self.db_entry.get(),
                user=self.user_entry.get(),
                password=self.password_entry.get()
            )
            self.cursor = self.conn.cursor()
            self.load_tables()
            self.load_table_metadata()
            self._cache_column_lengths()
            self.notebook.select(1)
            self.log("Połączono z bazą danych")
        except Exception as e:
            messagebox.showerror("Błąd połączenia", str(e))


    def load_table_metadata(self):
        """Ładuje metadane o kluczach głównych, obcych i zależnościach"""
        try:
            self.cursor.execute("""
                SELECT kcu.table_name, kcu.column_name
                FROM information_schema.key_column_usage AS kcu
                JOIN information_schema.table_constraints AS tc
                    ON kcu.constraint_name = tc.constraint_name
                WHERE tc.constraint_type = 'PRIMARY KEY'
                    AND tc.table_schema = 'public'
            """)
            for table, column in self.cursor.fetchall():
                self.primary_keys[table].append(column)

            self.cursor.execute("""
                SELECT
                    tc.table_name AS child_table,
                    kcu.column_name AS child_column,
                    ccu.table_name AS parent_table,
                    ccu.column_name AS parent_column
                FROM information_schema.table_constraints AS tc
                JOIN information_schema.key_column_usage AS kcu
                    ON tc.constraint_name = kcu.constraint_name
                JOIN information_schema.constraint_column_usage AS ccu
                    ON tc.constraint_name = ccu.constraint_name
                WHERE tc.constraint_type = 'FOREIGN KEY'
                    AND tc.table_schema = 'public'
            """)
            for child_table, child_col, parent_table, parent_col in self.cursor.fetchall():
                self.foreign_keys[(child_table, child_col)] = (parent_table, parent_col)
                self.table_dependencies[parent_table].append(child_table)

            self.cursor.execute("""
                        SELECT table_name, column_name 
                        FROM information_schema.columns 
                        WHERE column_default LIKE 'nextval(%'
                    """)
            for table, column in self.cursor.fetchall():
                if table not in self.auto_increment:
                    self.auto_increment[table] = {}
                self.auto_increment[table][column] = True

            self.parse_check_constraints()

        except Exception as e:
            messagebox.showerror("Błąd metadanych", str(e))

    def parse_check_constraints(self):
        """Parsuje wszystkie ograniczenia CHECK z bazy danych"""
        self.check_constraints = defaultdict(dict)
        try:
            self.cursor.execute("""
                SELECT
                    conrelid::regclass::text AS table_name,
                    a.attname AS column_name,
                    pg_get_expr(c.conbin, c.conrelid) AS check_expr
                FROM
                    pg_constraint c
                JOIN pg_attribute a
                    ON a.attnum = ANY(c.conkey)
                    AND a.attrelid = c.conrelid
                WHERE
                    c.contype = 'c'
                    AND conrelid::regclass::text IN (
                        SELECT table_name 
                        FROM information_schema.tables 
                        WHERE table_schema = 'public'
                    )
            """)

            for table, column, expr in self.cursor.fetchall():
                table = table.lower()
                column = column.lower()
                parsed = self._parse_check_clause(column, expr)
                if parsed:
                    self.check_constraints[(table, column)] = parsed

            self.log(f"Zapisane ograniczenia: {dict(self.check_constraints)}")

        except Exception as e:
            self.log(f"Błąd parsowania ograniczeń CHECK: {str(e)}")

    def _parse_check_clause(self, column, expr):
        expr = expr.strip()
        any_array_match = re.search(
            rf"{re.escape(column)}::text\s*=\s*ANY\s*\(\s*\(ARRAY\[(.*?)\]\s*(::[^\)]*)?\)",
            expr, re.IGNORECASE
        )
        if any_array_match:
            raw_values = any_array_match.group(1)
            values = re.findall(r"'([^']*)'(?:\s*::[a-zA-Z\s]+)?", raw_values)
            return {'type': 'IN', 'values': values}

        in_match = re.search(
            rf"{re.escape(column)}\s+IN\s*\(([\d,\s]+)\)", expr, re.IGNORECASE
        )
        if in_match:
            values = list(map(int, in_match.group(1).split(',')))
            return {'type': 'IN', 'values': values}

        conditions = re.findall(
            rf"{re.escape(column)}\s*(<=|>=|=|<|>)\s*(\d+)", expr
        )
        if conditions and len(conditions) >= 2:
            result = {}
            for op, val in conditions:
                val = int(val)
                if op == '>=':
                    result['min'] = max(result.get('min', val), val)
                elif op == '>':
                    result['min'] = max(result.get('min', val + 1), val + 1)
                elif op == '<=':
                    result['max'] = min(result.get('max', val), val)
                elif op == '<':
                    result['max'] = min(result.get('max', val - 1), val - 1)
                elif op == '=':
                    result['min'] = result['max'] = val
            return {'type': 'BETWEEN', **result}

        simple = re.search(
            rf"{re.escape(column)}\s*(<=|>=|=|<|>)\s*(\d+)", expr
        )
        if simple:
            operator, value = simple.groups()
            return {
                'type': 'COMPARISON',
                'operator': operator,
                'value': int(value)
            }

        return {
            'type': 'COMPLEX',
            'expression': expr
        }

    def topological_sort(self, tables):
        """Sortuje tabele według zależności"""
        visited = {}
        result = []

        def visit(table):
            if table in visited:
                return
            visited[table] = True
            for dependent in self.table_dependencies.get(table, []):
                if dependent in tables:
                    visit(dependent)
            result.append(table)

        for table in tables:
            visit(table)
        return reversed(result)

    def load_tables(self):
        if not self.conn:
            return

        try:
            self.tree.delete(*self.tree.get_children())
            self.tables = {}

            self.cursor.execute("""
                SELECT table_name, column_name, data_type, 
                       character_maximum_length, is_nullable
                FROM information_schema.columns
                WHERE table_schema = 'public'
                ORDER BY table_name, ordinal_position
            """)

            current_table = None
            for table, column, dtype, max_len, nullable in self.cursor.fetchall():
                if table not in self.tables:
                    self.tables[table] = []
                    current_table = self.tree.insert("", "end", text=table, values=("Tabela", "", ""))

                self.tables[table].append({
                    'name': column,
                    'type': dtype,
                    'max_length': max_len,
                    'nullable': nullable == 'YES'
                })
                self.tree.insert(current_table, "end", text=column, values=(dtype, max_len, nullable))

            self.update_tables_list()
            self.log("Załadowano strukturę tabel")
        except Exception as e:
            messagebox.showerror("Błąd", str(e))

    def _cache_column_lengths(self):
        try:
            self.cursor.execute("""
                SELECT table_name, column_name, character_maximum_length 
                FROM information_schema.columns 
                WHERE table_schema = 'public' 
                AND data_type IN ('character varying', 'char', 'text')
            """)
            for table, column, length in self.cursor.fetchall():
                if table not in self.column_lengths_cache:
                    self.column_lengths_cache[table] = {}
                self.column_lengths_cache[table][column] = length
        except Exception as e:
            self.log(f"Błąd buforowania: {str(e)}")

    def configure_table(self):
        selected = self.tree.selection()
        if not selected:
            return

        item = self.tree.item(selected[0])
        parent = self.tree.parent(selected[0])

        if parent == "":
            self.configure_whole_table(item['text'])
        else:
            self.configure_column(self.tree.item(parent)['text'], item['text'])

    def configure_whole_table(self, table):
        top = tk.Toplevel(self.root)
        top.title(f"Konfiguracja tabeli {table}")

        tree = ttk.Treeview(top, columns=("config"), selectmode="browse")
        tree.pack(fill=tk.BOTH, expand=True)
        tree.heading("#0", text="Kolumna")
        tree.heading("config", text="Konfiguracja")

        for col in self.tables[table]:
            config = self.generation_rules.get(table, {}).get(col['name'], "Domyślny")
            tree.insert("", "end", text=col['name'], values=(config,))

        ttk.Button(top, text="Zamknij", command=top.destroy).pack(pady=5)

    def configure_column(self, table, column):
        top = tk.Toplevel(self.root)
        top.title(f"Konfiguracja {table}.{column}")

        current_config = self.generation_rules.get(table, {}).get(column, {})
        config_type = current_config.get('type', 'default')

        var = tk.StringVar(value=config_type)
        col_info = next(c for c in self.tables[table] if c['name'] == column)

        main_frame = ttk.Frame(top)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)

        radio_frame = ttk.Frame(main_frame)
        radio_frame.pack(fill=tk.X, pady=5)

        ttk.Radiobutton(radio_frame, text="Domyślny", variable=var, value="default").pack(anchor=tk.W)
        ttk.Radiobutton(radio_frame, text="Własne wartości", variable=var, value="custom").pack(anchor=tk.W)
        ttk.Radiobutton(radio_frame, text="Wzór", variable=var, value="pattern").pack(anchor=tk.W)

        input_frame = ttk.Frame(main_frame)
        input_frame.pack(fill=tk.BOTH, expand=True)

        self.current_config_widget = None
        self.custom_entry = ttk.Entry(input_frame)
        self.pattern_entry = ttk.Entry(input_frame)
        self.function_text = tk.Text(input_frame, height=4)

        if current_config:
            if config_type == 'custom':
                self.custom_entry.insert(0, ";".join(current_config.get('values', [])))
            elif config_type == 'pattern':
                self.pattern_entry.insert(0, current_config.get('pattern', ''))
            elif config_type == 'function':
                self.function_text.insert("1.0", current_config.get('function', ''))

        def update_state():
            if self.current_config_widget:
                self.current_config_widget.pack_forget()

            state = var.get()
            if state == "custom":
                self.custom_entry.pack(fill=tk.X, expand=True)
                self.current_config_widget = self.custom_entry
            elif state == "pattern":
                self.pattern_entry.pack(fill=tk.X, expand=True)
                self.current_config_widget = self.pattern_entry
            elif state == "function":
                self.function_text.pack(fill=tk.BOTH, expand=True)
                self.current_config_widget = self.function_text

        var.trace_add("write", lambda *args: update_state())
        update_state()

        ttk.Button(main_frame, text="Zapisz", command=lambda: self.save_column_config(
            top, table, column, var.get(),
            self.custom_entry.get(),
            self.pattern_entry.get(),
            self.function_text.get("1.0", tk.END)
        )).pack(pady=5)

    def save_column_config(self, window, table, column, config_type, custom_values, pattern,  function):
        config = {}
        try:
            if config_type == "custom":
                values = [v.strip() for v in custom_values.split(";") if v.strip()]
                if not values:
                    raise ValueError("Podaj wartości według konfiguracji")
                config = {'type': 'custom', 'values': values}
            elif config_type == "pattern":
                if not pattern:
                    raise ValueError("Podaj wzór")
                config = {'type': 'pattern', 'pattern': pattern}
            elif config_type == "function":
                if not function.strip():
                    raise ValueError("Podaj kod funkcji")
                config = {'type': 'function', 'function': function.strip()}

            if table not in self.generation_rules:
                self.generation_rules[table] = {}
            self.generation_rules[table][column] = config
            window.destroy()
            self.log(f"Zapisano konfigurację dla {table}.{column}")
        except Exception as e:
            messagebox.showerror("Błąd", str(e))

    def generate_data(self):
        if not self.conn:
            messagebox.showerror("Błąd", "Najpierw połącz z bazą!")
            return

        try:
            selected_tables = self.tables_tree.selection()
            if not selected_tables:
                messagebox.showwarning("Brak wyboru", "Wybierz przynajmniej jedną tabelę!")
                return

            generation_config = {}
            for table in selected_tables:
                if self.global_count_var.get():
                    count = int(self.records_entry.get())
                else:
                    count = int(self.tables_tree.item(table, "values")[0])
                generation_config[table] = count

            all_tables = self.get_all_dependent_tables(generation_config.keys())
            sorted_tables = self.topological_sort(all_tables)

            for table in sorted_tables:
                count = generation_config.get(table, 100)
                batch_size = int(self.batch_entry.get())

                if table in self.generation_rules:
                    self.log(f"Generowanie {count} rekordów dla {table} (skonfigurowana)")
                    self.generate_table_data(table, count, batch_size)
                else:
                    self.log(f"Generowanie {count} rekordów dla {table} (domyślna)")
                    self.generate_default_table_data(table, count, batch_size)

            messagebox.showinfo("Sukces", "Dane wygenerowane!")
        except Exception as e:
            messagebox.showerror("Błąd", str(e))
            self.log(f"Błąd generowania: {str(e)}")

    def generate_pesel(self):
        return str(SpecialDataGenerator.PeselGenerator('PESEL'))



    def pk_exists(self, table, pk_column, value):
        """Sprawdza istnienie wartości PK w cache'u i bazie danych"""
        if str(value) in self.generated_values_cache.get((table, pk_column), set()):
            return True

        try:
            self.cursor.execute(
                sql.SQL("SELECT EXISTS (SELECT 1 FROM {} WHERE {} = %s)").format(
                    sql.Identifier(table),
                    sql.Identifier(pk_column)
                ),
                (value,)
            )
            return self.cursor.fetchone()[0]
        except Exception as e:
            self.log(f"Błąd sprawdzania PK: {str(e)}")
            return False

    def handle_integrity_error(self, error, table, columns, batch):
        """Obsługuje błędy integralności i próbuje regenerować dane"""
        error_msg = str(error)
        self.log(f"BŁĄD INTEGRALNOŚCI: {error_msg}")
        if "null value in column" in error_msg:
            col_name = re.search(r'column "(.*?)"', error_msg).group(1)
            self.log(f"Próbuję poprawić NULL w kolumnie {col_name}...")
            self.regenerate_null_values(table, col_name, batch, columns)
            self.generate_table_data(table, len(batch), len(batch))

        elif "duplicate key value" in error_msg:
            match = re.search(r'Key \((.*?)\)=\((.*?)\)', error_msg)
            if match:
                pk_col = match.group(1)
                pk_value = match.group(2)
                self.log(f"Duplikat klucza głównego {pk_col}={pk_value}")
                self.generated_values_cache[(table, pk_col)].discard(pk_value)
                self.generate_table_data(table, 1, 1)

        elif "foreign key constraint" in error_msg:
            match = re.search(r'Key \((.*?)\)=\((.*?)\)', error_msg)
            if match:
                fk_col = match.group(1)
                fk_value = match.group(2)
                parent_table = [v[0] for k, v in self.foreign_keys.items() if k == (table, fk_col)][0]
                self.log(f"Brak wartości {fk_value} w tabeli {parent_table}.{fk_col}")
                self.ensure_minimum_records(parent_table)
                self.generate_table_data(table, len(batch), len(batch))

        else:
            self.log(f"Nierozpoznany błąd integralności: {error_msg}")
            raise

    def regenerate_null_values(self, table, column, batch, columns):
        """Regeneruje wartości NULL w istniejącym batchu"""
        col_index = columns.index(column)
        for record in batch:
            if record[col_index] is None:
                try:
                    new_value = self.generate_value(table, column)
                    record[col_index] = new_value
                    self.log(f"Wygenerowano nową wartość dla {table}.{column}: {new_value}")
                except Exception as e:
                    record[col_index] = self.generate_default_value(table, column)
                    self.log(f"Wykorzystano wartość domyślną dla {table}.{column}: {record[col_index]}")

    def handle_primary_key_error(self, table, columns, batch):
        pk_column = self.primary_keys[table][0]
        self.log(f"Wykryto duplikat klucza głównego w {table}.{pk_column}, próba regeneracji...")

        pk_index = columns.index(pk_column)
        for record in batch:
            existing_id = record[pk_index]
            self.generated_values_cache[(table, pk_column)].discard(existing_id)

        new_batch = []
        for record in batch:
            try:
                new_record = list(record)
                new_record[pk_index] = self.generate_value(table, pk_column)
                new_batch.append(new_record)
            except ValueError as e:
                self.log(str(e))

        if new_batch:
            try:
                self.cursor.executemany(
                    sql.SQL("INSERT INTO {} ({}) VALUES ({})").format(
                        sql.Identifier(table),
                        sql.SQL(', ').join(map(sql.Identifier, columns)),
                        sql.SQL(', ').join([sql.Placeholder()] * len(columns))
                    ),
                    new_batch
                )
                self.conn.commit()
                self.log(f"Pomyślnie dodano {len(new_batch)} rekordów po regeneracji PK")
            except psycopg2.Error as e:
                self.conn.rollback()
                self.log(f"Błąd przy ponownym wstawianiu: {str(e)}")


    def generate_default_table_data(self, table, count, batch_size):
        """Generuje dane dla tabeli bez specjalnej konfiguracji"""
        try:
            columns = []
            returning = None

            if table in self.primary_keys:
                pk = self.primary_keys[table][0]
                if self.auto_increment.get(table, {}).get(pk, False):
                    columns = [col['name'] for col in self.tables[table] if col['name'] != pk]
                    returning = pk
                else:
                    columns = [col['name'] for col in self.tables[table]]
            else:
                columns = [col['name'] for col in self.tables[table]]

            query = sql.SQL("INSERT INTO {} ({}) VALUES ({})").format(
                sql.Identifier(table),
                sql.SQL(', ').join(map(sql.Identifier, columns)),
                sql.SQL(', ').join([sql.Placeholder()] * len(columns))
            )

            if returning:
                query += sql.SQL(" RETURNING {}").format(sql.Identifier(returning))

            for i in range(0, count, batch_size):
                current_batch = min(batch_size, count - i)
                batch = []
                for _ in range(current_batch):
                    row = [self.generate_value(table, col) for col in columns]
                    batch.append(row)

                try:
                    if returning:
                        ids = []
                        for record in batch:
                            self.cursor.execute(query, record)
                            ids.append(self.cursor.fetchone()[0])
                        self.generated_ids[table].extend(ids)
                    else:
                        self.cursor.executemany(query, batch)

                    self.conn.commit()
                    self.log(f"Dodano {len(batch)} rekordów do {table}")
                except Exception as e:
                    self.conn.rollback()
                    self.log(f"Błąd: {str(e)}")
                    raise

        except Exception as e:
            self.log(f"Krytyczny błąd generowania {table}: {str(e)}")
            raise

    def get_all_dependent_tables(self, selected_tables):
        """Zwraca wszystkie tabele zależne wymagane dla wybranych tabel"""
        all_tables = set(selected_tables)
        for table in selected_tables:
            dependencies = self.get_parent_tables(table)
            all_tables.update(dependencies)
        return list(all_tables)

    def get_parent_tables(self, table):
        """Zwraca wszystkie tabele nadrzędne dla danej tabeli"""
        parents = set()
        for (child_table, _), (parent_table, _) in self.foreign_keys.items():
            if child_table == table:
                parents.add(parent_table)
                parents.update(self.get_parent_tables(parent_table))
        return parents

    def ensure_minimum_records(self, table):
        """Gwarantuje minimum 100 rekordów w tabelach nadrzędnych"""
        if self.get_record_count(table) < 100:
            self.log(f"Automatyczne generowanie 100 rekordów dla {table}")
            self.generate_table_data(table, 100, 10)

    def generate_table_data(self, table, count, batch_size):
        """Generuje dane dla tabeli z uwzględnieniem wszystkich ograniczeń i walidacji"""
        try:
            columns = []
            returning = None
            pk_column = self.primary_keys.get(table, [None])[0]

            if pk_column and self.auto_increment.get(table, {}).get(pk_column, False):
                columns = [col['name'] for col in self.tables[table] if col['name'] != pk_column]
                returning = pk_column
            else:
                columns = [col['name'] for col in self.tables[table]]

            query = sql.SQL("INSERT INTO {} ({}) VALUES ({})").format(
                sql.Identifier(table),
                sql.SQL(', ').join(map(sql.Identifier, columns)),
                sql.SQL(', ').join([sql.Placeholder()] * len(columns))
            )

            if returning:
                query += sql.SQL(" RETURNING {}").format(sql.Identifier(returning))

            total_generated = 0
            retry_attempts = 3

            def validate_row(table, columns, row):
                for i, (col, value) in enumerate(zip(columns, row)):
                    col_info = next(c for c in self.tables[table] if c['name'] == col)

                    check = self.check_constraints.get((table.lower(), col.lower()))
                    if not check:
                        continue

                    ctype = check['type']

                    if col_info['type'] in ['integer', 'bigint']:
                        if not isinstance(value, int):
                            return False

                        if ctype == 'BETWEEN':
                            if not (check.get('min', float('-inf')) <= value <= check.get('max', float('inf'))):
                                return False
                        elif ctype == 'IN':
                            if value not in check['values']:
                                return False
                        elif ctype == 'COMPARISON':
                            op = check['operator']
                            cval = check['value']
                            if op == '>=' and not (value >= cval):
                                return False
                            elif op == '>' and not (value > cval):
                                return False
                            elif op == '<=' and not (value <= cval):
                                return False
                            elif op == '<' and not (value < cval):
                                return False
                            elif op == '=' and not (value == cval):
                                return False

                    elif col_info['type'] in ['character varying', 'text', 'varchar']:
                        if ctype == 'IN':
                            if str(value) not in check['values']:
                                return False


                return True

            while total_generated < count:
                batch = []
                attempts = 0
                while len(batch) < min(batch_size, count - total_generated) and attempts < retry_attempts:
                    try:
                        row = [self.generate_value(table, col) for col in columns]
                        if validate_row(table, columns, row):
                            batch.append(row)
                        else:
                            self.log("Odrzucono nieprawidłowy wiersz, generuję ponownie")
                            attempts += 1
                    except ValueError as e:
                        self.log(f"Błąd generowania: {str(e)}")
                        attempts += 1

                if not batch:
                    self.log(f"Nie udało się wygenerować prawidłowych danych dla {table}")
                    break

                try:
                    if returning:
                        new_ids = []
                        for record in batch:
                            self.cursor.execute(query, record)
                            new_id = self.cursor.fetchone()[0]
                            new_ids.append(new_id)
                            self.generated_values_cache[(table, returning)].add(str(new_id))
                        self.generated_ids[table].extend(new_ids)
                    else:
                        self.cursor.executemany(query, batch)

                    self.conn.commit()
                    success_count = len(batch)
                    total_generated += success_count
                    self.log(f"Dodano {success_count} rekordów do {table} (łącznie: {total_generated}/{count})")

                except psycopg2.IntegrityError as e:
                    self.conn.rollback()
                    self.handle_integrity_error(e, table, columns, batch)

                    for record in batch:
                        try:
                            if returning:
                                self.cursor.execute(query, record)
                                new_id = self.cursor.fetchone()[0]
                                self.generated_ids[table].append(new_id)
                            else:
                                self.cursor.execute(query, record)
                            self.conn.commit()
                        except Exception as single_error:
                            self.conn.rollback()
                            self.log(f"Błąd przy ponownym wstawianiu pojedynczego rekordu: {str(single_error)}")

                except Exception as e:
                    self.conn.rollback()
                    self.log(f"Krytyczny błąd: {str(e)}")
                    break

            if pk_column:
                try:
                    self.cursor.execute(
                        sql.SQL("SELECT {} FROM {} ORDER BY {} DESC LIMIT {}").format(
                            sql.Identifier(pk_column),
                            sql.Identifier(table),
                            sql.Identifier(pk_column),
                            sql.Literal(total_generated)
                        )
                    )
                    new_values = {str(r[0]) for r in self.cursor.fetchall()}
                    self.generated_values_cache[(table, pk_column)].update(new_values)
                except Exception as e:
                    self.log(f"Błąd aktualizacji cache: {str(e)}")

            return total_generated

        except Exception as main_error:
            self.log(f"Krytyczny błąd w generate_table_data: {str(main_error)}")
            raise

    def get_record_count(self, table):
        """Zwraca liczbę istniejących rekordów w tabeli"""
        try:
            self.cursor.execute(f"SELECT COUNT(*) FROM {table}")
            return self.cursor.fetchone()[0]
        except Exception as e:
            self.log(f"Błąd sprawdzania danych w {table}: {str(e)}")
            return 0

    def generate_value(self, table, column):
        """Generuje wartość dla kolumny z uwzględnieniem wszystkich reguł i zależności"""
        local_seed = secrets.randbits(64)
        local_random = random.Random(local_seed)
        Faker.seed(local_seed)

        try:
            key = (table.lower(), column.lower())
            if key in self.special_data:
                try:
                    parts = self.special_data[key].split(':')
                    if len(parts) >= 2 and parts[0].startswith("*"):
                        generator_type = parts[0][1:]
                        param = parts[1]
                        if generator_type == 'PESEL':
                            for attempt in range(self.retry_limit):
                                pesel = SpecialDataGenerator.PeselGenerator(param)
                                cache_key = (table, column)

                                in_cache = pesel in self.generated_values_cache.get(cache_key, set())
                                in_db = self.check_pesel_in_db(pesel)

                                if not in_cache and not in_db:
                                    self.generated_values_cache[cache_key].add(pesel)
                                    BasicDataGenerator.ClearSpecialValues()
                                    return pesel

                                else:
                                    BasicDataGenerator.ClearSpecialValues()
                                    new_seed = secrets.randbits(64)
                                    local_random.seed(new_seed)
                                    Faker.seed(new_seed)

                            raise ValueError(
                                f"Nie udało się wygenerować unikalnego PESEL po {self.retry_limit} próbach")



                except Exception as e:
                    self.log(f"Błąd specjalnego generatora {table}.{column}: {str(e)}")
                    raise

            for (child_table, child_col), (parent_table, parent_col) in self.foreign_keys.items():
                if child_table == table and child_col == column:
                    try:
                        parent_ids = self.get_existing_ids(parent_table, parent_col)
                        if not parent_ids:
                            self.ensure_minimum_records(parent_table)
                            parent_ids = self.get_existing_ids(parent_table, parent_col)
                        return local_random.choice(parent_ids)
                    except Exception as e:
                        self.log(f"Błąd klucza obcego {table}.{column}: {str(e)}")
                        raise

            if table in self.generation_rules and column in self.generation_rules[table]:
                rule = self.generation_rules[table][column]
                if rule['type'] == "custom":
                    selected_value = local_random.choice(rule['values'])
                    return self.process_custom(selected_value)
                elif rule['type'] == "pattern":
                    return self.generate_from_pattern(rule['pattern'])
                elif rule['type'] == "function":
                    try:
                        return eval(rule['function'], {
                            'fake': self.faker,
                            'random': local_random,
                            'secrets': secrets
                        })
                    except Exception as e:
                        self.log(f"Błąd funkcji: {str(e)}")
                        raise ValueError("Nieprawidłowa funkcja generująca")

            return self.generate_default_value(table, column)

        except Exception as e:
            self.log(f"Krytyczny błąd generowania {table}.{column}: {str(e)}")
            raise

    def check_pesel_in_db(self, pesel):
        try:
            self.cursor.execute("""
                SELECT table_name
                FROM information_schema.columns
                WHERE column_name = 'pesel'
                  AND table_schema = 'public'
            """)
            tables = self.cursor.fetchall()

            for (table_name,) in tables:
                query = f"SELECT EXISTS(SELECT 1 FROM {table_name} WHERE pesel = %s)"
                self.cursor.execute(query, (pesel,))
                if self.cursor.fetchone()[0]:
                    return True

            return False
        except Exception as e:
            self.log(f"Błąd sprawdzania PESEL: {str(e)}")
            return True

    def generate_default_pk_value(self, table, column):
        """Generuje domyślną wartość PK na podstawie typu"""
        col_info = next(c for c in self.tables[table] if c['name'] == column)

        if col_info['type'] in ['integer', 'bigint']:
            return random.randint(1, 2147483647)
        elif col_info['type'] in ['varchar', 'text']:
            return str(uuid.uuid4())
        else:
            raise ValueError(f"Nieobsługiwany typ PK: {col_info['type']}")

    def get_existing_ids(self, table, column):
        """Pobiera istniejące ID z bazy danych"""
        try:
            self.cursor.execute(f"SELECT {column} FROM {table}")
            return [row[0] for row in self.cursor.fetchall()]
        except Exception as e:
            self.log(f"Błąd pobierania ID z {table}.{column}: {str(e)}")
            return []

    def generate_from_pattern(self, pattern):
        result = []
        letters_lower = string.ascii_lowercase
        letters_upper = string.ascii_uppercase
        for char in pattern:
            if char == 'N':
                result.append(str(random.randint(0, 9)))
            elif char == 'M':
                result.append(random.choice(letters_upper))
            elif char == 'D':
                result.append(random.choice(letters_upper))
            else:
                result.append(char)
        return ''.join(result)

    def generate_default_value(self, table, column):
        """Generuje wartość uwzględniającą ograniczenia CHECK"""
        col_info = next(c for c in self.tables[table] if c['name'] == column)
        key = (table.lower(), column.lower())
        check = self.check_constraints.get(key)

        if check:
            try:
                if check['type'] == 'IN' and check.get('values'):
                    return random.choice(check['values'])

                elif check['type'] == 'BETWEEN':
                    return random.randint(check['min'], check['max'])

                elif check['type'] == 'COMPARISON':
                    operator = check['operator']
                    constraint_value = check['value']

                    if col_info['type'] in ['integer', 'bigint']:
                        min_val = 1
                        max_val = 2147483647

                        if operator == '>=':
                            min_val = constraint_value
                        elif operator == '>':
                            min_val = constraint_value + 1
                        elif operator == '<=':
                            max_val = constraint_value
                        elif operator == '<':
                            max_val = constraint_value - 1
                        elif operator == '=':
                            min_val = max_val = constraint_value

                        return random.randint(min_val, max_val)

                    elif 'date' in col_info['type'].lower():
                        current_year = datetime.now().year
                        if check['type'] in ['>=', '>']:
                            return random.randint(
                                max(constraint_value, 1888),
                                current_year
                            )
                        return random.randint(1888, current_year)

                elif check['type'] == 'COMPLEX':
                    expr = check.get('expression', '')
                    match = re.search(r"ARRAY\[(.*?)\]", expr)
                    if match:
                        raw_values = match.group(1).strip()
                        if re.search(r"'[^']*'", raw_values):
                            values = re.findall(r"'([^']*)'(?:\s*::[a-z\s]+)?", raw_values)
                        else:
                            values = [float(v.strip()) if '.' in v else int(v.strip()) for v in raw_values.split(',')]

                        if values:
                            return random.choice(values)



            except Exception as e:
                self.log(f"Błąd generowania dla {table}.{column}: {str(e)}")
                self.log(f"Szczegóły ograniczenia: {check}")

        if col_info['type'] in ['integer', 'bigint']:
            return random.randint(1, 2147483647)

        elif col_info['type'] in ['character varying', 'text']:
            max_len = col_info['max_length'] or 50
            return self.faker.text(max_nb_chars=max_len)[:max_len].replace("'", "")

        elif col_info['type'] == 'date':
            return self.faker.date_between(start_date='-30y', end_date='today')

        elif col_info['type'] == 'boolean':
            return random.choice([True, False])

        elif col_info['type'] in ['numeric', 'real']:
            return round(random.uniform(1.0, 1000.0), 2)

        elif col_info['type'] == 'timestamp without time zone':
            return self.faker.date_time_this_decade()

        elif col_info['type'] == 'time without time zone':
            return self.faker.time()

        return self.faker.word()[:50]

    def save_configuration(self):
        file_path = filedialog.asksaveasfilename(defaultextension=".txt")
        if not file_path:
            return

        with open(file_path, "w") as f:
            for table in self.generation_rules:
                for col, rule in self.generation_rules[table].items():
                    if rule['type'] == "custom":
                        line = f"{table}@{col}@{'|'.join(rule['values'])}\n"
                        f.write(line)
                    elif rule['type'] == "pattern":
                        line = f"{table}@{col}@PATTERN@{rule['pattern']}\n"
                        f.write(line)
                    elif rule['type'] == "function":
                        line = f"{table}@{col}@FUNCTION@{rule['function']}\n"
                        f.write(line)

    def load_configuration(self):
        file_path = filedialog.askopenfilename()
        if not file_path:
            return

        self.generation_rules = {}
        with open(file_path, "r") as f:
            for line in f:
                parts = line.strip().split("@")
                if len(parts) < 3:
                    continue

                table = parts[0]
                col = parts[1]
                rule_type = parts[2]

                if table not in self.generation_rules:
                    self.generation_rules[table] = {}

                if rule_type == "custom":
                    self.generation_rules[table][col] = {
                        'type': 'custom',
                        'values': parts[3].split("|")
                    }
                elif rule_type == "PATTERN":
                    self.generation_rules[table][col] = {
                        'type': 'pattern',
                        'pattern': parts[3]
                    }
                elif rule_type == "FUNCTION":
                    self.generation_rules[table][col] = {
                        'type': 'function',
                        'function': parts[3]
                    }

    def log(self, message):
        self.log_text.config(state=tk.NORMAL)
        self.log_text.insert(tk.END, f"[{datetime.now().strftime('%H:%M:%S')}] {message}\n")
        self.log_text.config(state=tk.DISABLED)
        self.log_text.see(tk.END)

    def clear_log(self):
        self.log_text.config(state=tk.NORMAL)
        self.log_text.delete(1.0, tk.END)
        self.log_text.config(state=tk.DISABLED)

    def load_last_config(self):
        try:
            with open("last_config.txt", "r") as f:
                lines = f.readlines()
                self.host_entry.delete(0, tk.END)
                self.host_entry.insert(0, lines[0].strip())
                self.port_entry.delete(0, tk.END)
                self.port_entry.insert(0, lines[1].strip())
                self.db_entry.delete(0, tk.END)
                self.db_entry.insert(0, lines[2].strip())
                self.user_entry.delete(0, tk.END)
                self.user_entry.insert(0, lines[3].strip())
                self.password_entry.delete(0, tk.END)
                self.password_entry.insert(0, lines[4].strip())
        except:
            pass

    def on_closing(self):
        with open("last_config.txt", "w") as f:
            f.write(f"{self.host_entry.get()}\n")
            f.write(f"{self.port_entry.get()}\n")
            f.write(f"{self.db_entry.get()}\n")
            f.write(f"{self.user_entry.get()}\n")
            f.write(f"{self.password_entry.get()}\n")
        if self.conn:
            self.conn.close()
        self.root.destroy()

    def add_pattern(self):
        symbol = simpledialog.askstring("Nowy wzór", "Podaj symbol wzoru (1 znak):")
        definition = simpledialog.askstring("Definicja", "Podaj opis wzoru:")
        if symbol and definition and len(symbol) == 1:
            self.pattern_definitions[symbol] = definition
            self.patterns_tree.insert("", "end", text=symbol, values=(definition,))

    def remove_pattern(self):
        selected = self.patterns_tree.selection()
        if selected:
            item = self.patterns_tree.item(selected[0])
            symbol = item['text']
            del self.pattern_definitions[symbol]
            self.patterns_tree.delete(selected[0])

    def detect_custom(self, text):
        """Wykrywa wzorce w tekście: (x-y), [a/b/c], "n"""
        patterns = [
            r'\([^()]*\)',
            r'\[[^\[\]]*\]',
            r'"[^"]*"'
        ]
        matches = []
        for pattern in patterns:
            matches += re.findall(pattern, text)
        return matches

    def process_custom(self, text):
        """Przetwarza tekst zastępując wykryte wzorce wygenerowanymi wartościami"""
        matches = self.detect_custom(text)
        replacements = []
        local_random = random.Random(secrets.randbits(64))

        for match in matches:
            if match.startswith('(') and match.endswith(')'):
                content = match[1:-1]
                if '-' in content:
                    lower, upper = map(int, content.split('-'))
                    replacements.append(str(local_random.randint(lower, upper)))
                else:
                    replacements.append(content)

            elif match.startswith('[') and match.endswith(']'):
                options = match[1:-1].split('/')
                replacements.append(local_random.choice(options))

            elif match.startswith('"') and match.endswith('"'):
                length = int(match[1:-1])
                replacements.append(self.faker.text(max_nb_chars=length).replace('\n', ' ')[:length])

            else:
                replacements.append(match)

        processed_text = text
        for match, replacement in zip(matches, replacements):
            processed_text = processed_text.replace(match, replacement, 1)

        return processed_text


if __name__ == "__main__":
    root = tk.Tk()
    app = UniversalDataGenerator(root)
    root.protocol("WM_DELETE_WINDOW", app.on_closing)
    root.mainloop()