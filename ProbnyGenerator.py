import tkinter as tk
from tkinter import ttk, messagebox, simpledialog
import psycopg2
from psycopg2 import sql
from faker import Faker
import random
from datetime import datetime, timedelta
import re


class UniversalDataGenerator:
    def __init__(self, root):
        self.root = root
        self.root.title("Uniwersalny Generator Danych Medycznych")
        self.root.geometry("1200x800")

        self.conn = None
        self.cursor = None
        self.faker = Faker('pl_PL')
        self.tables = {}
        self.generation_rules = {}
        self.custom_values = {}
        self.constraints = {}
        self.column_lengths_cache = {}
        self.pacjenci_ids = []
        self.lekarze_ids = []
        self.wizyty_ids = []

        self.setup_ui()
        self.load_last_config()

    def setup_ui(self):
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill=tk.BOTH, expand=True)

        self.setup_connection_tab()
        self.setup_tables_tab()
        self.setup_generation_tab()
        self.setup_patterns_tab()
        self.setup_medical_tab()

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

        connect_btn = ttk.Button(frame, text="Połącz", command=self.connect_to_db)
        connect_btn.grid(row=2, column=3, sticky=tk.E)

    def setup_tables_tab(self):
        tab = ttk.Frame(self.notebook)
        self.notebook.add(tab, text="Tabele")

        self.tables_frame = ttk.Frame(tab)
        self.tables_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)

        self.tree = ttk.Treeview(self.tables_frame, columns=("type", "length", "nullable"), selectmode="extended")
        self.tree.heading("#0", text="Tabela/Kolumna")
        self.tree.heading("type", text="Typ")
        self.tree.heading("length", text="Długość")
        self.tree.heading("nullable", text="Nullable")
        self.tree.pack(fill=tk.BOTH, expand=True, side=tk.LEFT)

        scrollbar = ttk.Scrollbar(self.tables_frame, orient="vertical", command=self.tree.yview)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.tree.configure(yscrollcommand=scrollbar.set)

        btn_frame = ttk.Frame(tab)
        btn_frame.pack(fill=tk.X, padx=10, pady=5)

        refresh_btn = ttk.Button(btn_frame, text="Odśwież", command=self.load_tables)
        refresh_btn.pack(side=tk.LEFT)

        configure_btn = ttk.Button(btn_frame, text="Konfiguruj", command=self.configure_table)
        configure_btn.pack(side=tk.LEFT, padx=5)

    def setup_generation_tab(self):
        tab = ttk.Frame(self.notebook)
        self.notebook.add(tab, text="Generacja")

        frame = ttk.LabelFrame(tab, text="Parametry generacji")
        frame.pack(fill=tk.X, padx=10, pady=5)

        ttk.Label(frame, text="Liczba rekordów:").grid(row=0, column=0, sticky=tk.W)
        self.records_entry = ttk.Entry(frame, width=10)
        self.records_entry.grid(row=0, column=1)
        self.records_entry.insert(0, "100")

        ttk.Label(frame, text="Rozmiar partii:").grid(row=0, column=2, sticky=tk.W)
        self.batch_entry = ttk.Entry(frame, width=10)
        self.batch_entry.grid(row=0, column=3)
        self.batch_entry.insert(0, "10")

        generate_btn = ttk.Button(frame, text="Generuj dane", command=self.generate_data)
        generate_btn.grid(row=0, column=4, padx=5)

        self.log_text = tk.Text(tab, height=15, state=tk.DISABLED)
        self.log_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)

        clear_btn = ttk.Button(tab, text="Wyczyść log", command=self.clear_log)
        clear_btn.pack(side=tk.RIGHT, padx=10, pady=5)

    def setup_patterns_tab(self):
        tab = ttk.Frame(self.notebook)
        self.notebook.add(tab, text="Wzorce")

        frame = ttk.LabelFrame(tab, text="Definicje wzorców")
        frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)

        self.patterns_tree = ttk.Treeview(frame, columns=("definition"), selectmode="browse")
        self.patterns_tree.heading("#0", text="Symbol")
        self.patterns_tree.heading("definition", text="Definicja")
        self.patterns_tree.pack(fill=tk.BOTH, expand=True)

        self.pattern_definitions = {
            'C': 'Cyfra (0-9)',
            'L': 'Wielka litera (A-Z)',
            'l': 'Mała litera (a-z)',
            'A': 'Litera (wielka lub mała)',
            'P': 'Płeć (K/M)',
            'D': 'Data (YYYY-MM-DD)',
            'K': 'Suma kontrolna (cyfra)',
            'N': 'Liczba (1-9999)',
            'S': 'PESEL (pełny numer)',
            '9': 'Cyfra PESEL (0-9)'
        }

        for symbol, definition in self.pattern_definitions.items():
            self.patterns_tree.insert("", "end", text=symbol, values=(definition,))

        btn_frame = ttk.Frame(tab)
        btn_frame.pack(fill=tk.X, padx=10, pady=5)

        add_btn = ttk.Button(btn_frame, text="Dodaj wzór", command=self.add_pattern)
        add_btn.pack(side=tk.LEFT)

        remove_btn = ttk.Button(btn_frame, text="Usuń wzór", command=self.remove_pattern)
        remove_btn.pack(side=tk.LEFT, padx=5)

    def setup_medical_tab(self):
        tab = ttk.Frame(self.notebook)
        self.notebook.add(tab, text="Dane medyczne")

        frame = ttk.LabelFrame(tab, text="Generuj dane medyczne")
        frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)

        btn_frame = ttk.Frame(frame)
        btn_frame.pack(fill=tk.X, pady=5)

        ttk.Button(btn_frame, text="Generuj pacjentów", command=lambda: self.generate_medical_data('pacjenci')).pack(
            side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="Generuj lekarzy", command=lambda: self.generate_medical_data('lekarze')).pack(
            side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="Generuj wizyty", command=lambda: self.generate_medical_data('wizyty')).pack(
            side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="Generuj recepty", command=lambda: self.generate_medical_data('recepty')).pack(
            side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="Generuj skierowania",
                   command=lambda: self.generate_medical_data('skierowania')).pack(side=tk.LEFT, padx=5)

        btn_frame2 = ttk.Frame(frame)
        btn_frame2.pack(fill=tk.X, pady=5)

        ttk.Button(btn_frame2, text="Generuj historię chorób",
                   command=lambda: self.generate_medical_data('historia_chorob')).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame2, text="Generuj badania",
                   command=lambda: self.generate_medical_data('badania_diagnostyczne')).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame2, text="Generuj płatności", command=lambda: self.generate_medical_data('platnosci')).pack(
            side=tk.LEFT, padx=5)
        ttk.Button(btn_frame2, text="Generuj eWUŚ", command=lambda: self.generate_medical_data('ewus')).pack(
            side=tk.LEFT, padx=5)

        ttk.Button(frame, text="Generuj WSZYSTKO", command=self.generate_all_medical_data).pack(pady=10)

        self.medical_log_text = tk.Text(frame, height=10, state=tk.DISABLED)
        self.medical_log_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)

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
            self.load_constraints()
            self._cache_column_lengths()
            self.notebook.select(1)
            self.log("Połączono z bazą danych")
        except Exception as e:
            messagebox.showerror("Błąd połączenia", str(e))

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
            self.log(f"Błąd podczas buforowania długości kolumn: {str(e)}")

    def _truncate_value(self, table, column, value):
        if table in self.column_lengths_cache and column in self.column_lengths_cache[table]:
            max_len = self.column_lengths_cache[table][column]
            if max_len and len(str(value)) > max_len:
                return str(value)[:max_len]
        return value

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
            for table, column, data_type, max_length, nullable in self.cursor.fetchall():
                if table not in self.tables:
                    self.tables[table] = []
                    current_table = self.tree.insert("", "end", text=table,
                                                     values=(f"Tabela", "", ""))

                self.tables[table].append({
                    'name': column,
                    'type': data_type,
                    'max_length': max_length,
                    'nullable': nullable == 'YES'
                })

                self.tree.insert(current_table, "end", text=column,
                                 values=(data_type, max_length, nullable))

            self.log("Załadowano strukturę tabel")
        except Exception as e:
            messagebox.showerror("Błąd", str(e))

    def load_constraints(self):
        try:
            self.cursor.execute("""
                SELECT tc.table_name, ccu.column_name, pg_get_constraintdef(con.oid)
                FROM information_schema.table_constraints tc
                JOIN pg_constraint con ON con.conname = tc.constraint_name
                JOIN information_schema.constraint_column_usage ccu 
                  ON ccu.constraint_name = tc.constraint_name
                WHERE tc.constraint_type = 'CHECK'
            """)

            self.constraints = {}
            for table, column, definition in self.cursor.fetchall():
                if table not in self.constraints:
                    self.constraints[table] = {}
                self.constraints[table][column] = definition

            self.log("Załadowano ograniczenia tabel")
        except Exception as e:
            messagebox.showerror("Błąd", f"Nie udało się załadować ograniczeń: {str(e)}")

    def configure_table(self):
        selected = self.tree.selection()
        if not selected:
            return

        item = self.tree.item(selected[0])
        if not item['values'] or item['values'][0] == "Tabela":
            self.configure_whole_table(item['text'])
        else:
            parent = self.tree.parent(selected[0])
            table = self.tree.item(parent)['text']
            column = item['text']
            self.configure_column(table, column)

    def configure_whole_table(self, table):
        top = tk.Toplevel(self.root)
        top.title(f"Konfiguracja tabeli {table}")
        top.geometry("600x400")

        tree = ttk.Treeview(top, columns=("config"), selectmode="browse")
        tree.heading("#0", text="Kolumna")
        tree.heading("config", text="Konfiguracja")
        tree.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)

        for col in self.tables[table]:
            config = self.generation_rules.get(table, {}).get(col['name'], "Domyślny")
            tree.insert("", "end", text=col['name'], values=(config,))

        btn_frame = ttk.Frame(top)
        btn_frame.pack(fill=tk.X, padx=10, pady=5)

        ttk.Button(btn_frame, text="Konfiguruj kolumnę",
                   command=lambda: self.configure_column_from_dialog(table, tree)).pack(side=tk.LEFT)
        ttk.Button(btn_frame, text="Zapisz", command=top.destroy).pack(side=tk.RIGHT)

    def configure_column_from_dialog(self, table, tree):
        selected = tree.selection()
        if not selected:
            return

        column = tree.item(selected[0])['text']
        self.configure_column(table, column)

    def configure_column(self, table, column):
        top = tk.Toplevel(self.root)
        top.title(f"Konfiguracja {table}.{column}")
        top.geometry("500x400")

        ttk.Label(top, text="Wybierz typ generatora:").pack(pady=5)

        var = tk.StringVar(value="default")

        frame = ttk.Frame(top)
        frame.pack(fill=tk.X, padx=10, pady=5)

        ttk.Radiobutton(frame, text="Domyślny", variable=var, value="default").pack(anchor=tk.W)
        ttk.Radiobutton(frame, text="Własne wartości", variable=var, value="custom").pack(anchor=tk.W)
        ttk.Radiobutton(frame, text="Wzór", variable=var, value="pattern").pack(anchor=tk.W)
        ttk.Radiobutton(frame, text="Zależny", variable=var, value="dependent").pack(anchor=tk.W)

        col_info = next(col for col in self.tables[table] if col['name'] == column)
        if col_info['type'] in ['integer', 'bigint', 'smallint', 'numeric', 'decimal']:
            ttk.Radiobutton(frame, text="Funkcja", variable=var, value="function").pack(anchor=tk.W)

        options_frame = ttk.Frame(top)
        options_frame.pack(fill=tk.X, padx=10, pady=5)

        self.custom_values_entry = ttk.Entry(options_frame, state=tk.DISABLED)
        self.custom_values_entry.pack(fill=tk.X)

        self.pattern_entry = ttk.Entry(options_frame, state=tk.DISABLED)
        self.pattern_entry.pack(fill=tk.X)

        self.dependent_var = tk.StringVar()
        self.dependent_menu = ttk.Combobox(options_frame, textvariable=self.dependent_var, state=tk.DISABLED)
        self.dependent_menu.pack(fill=tk.X)

        self.function_entry = tk.Text(options_frame, height=4, state=tk.DISABLED)
        self.function_entry.pack(fill=tk.X)

        def update_options(*args):
            self.custom_values_entry.config(state=tk.DISABLED)
            self.pattern_entry.config(state=tk.DISABLED)
            self.dependent_menu.config(state=tk.DISABLED)
            self.function_entry.config(state=tk.DISABLED)

            if var.get() == "custom":
                self.custom_values_entry.config(state=tk.NORMAL)
            elif var.get() == "pattern":
                self.pattern_entry.config(state=tk.NORMAL)
            elif var.get() == "dependent":
                self.dependent_menu.config(state=tk.NORMAL)
                self.dependent_menu['values'] = [col['name'] for col in self.tables[table]
                                                 if col['name'] != column]
            elif var.get() == "function":
                self.function_entry.config(state=tk.NORMAL)

        var.trace_add("write", update_options)

        if table in self.generation_rules and column in self.generation_rules[table]:
            rule = self.generation_rules[table][column]
            if rule['type'] == "custom":
                var.set("custom")
                self.custom_values_entry.insert(0, ",".join(rule['values']))
            elif rule['type'] == "pattern":
                var.set("pattern")
                self.pattern_entry.insert(0, rule['pattern'])
            elif rule['type'] == "dependent":
                var.set("dependent")
                self.dependent_var.set(rule['depends_on'])
            elif rule['type'] == "function":
                var.set("function")
                self.function_entry.insert("1.0", rule['function'])

        ttk.Button(top, text="Zapisz", command=lambda: self.save_column_config(
            top, table, column, var.get())).pack(pady=10)

    def save_column_config(self, window, table, column, config_type):
        if config_type == "custom":
            values = [v.strip() for v in self.custom_values_entry.get().split(",")]
            if not values:
                messagebox.showerror("Błąd", "Podaj wartości oddzielone przecinkami")
                return
            self.set_generation_rule(table, column, "custom", values=values)
        elif config_type == "pattern":
            pattern = self.pattern_entry.get()
            if not pattern:
                messagebox.showerror("Błąd", "Podaj wzór")
                return
            self.set_generation_rule(table, column, "pattern", pattern=pattern)
        elif config_type == "dependent":
            depends_on = self.dependent_var.get()
            if not depends_on:
                messagebox.showerror("Błąd", "Wybierz kolumnę")
                return
            self.set_generation_rule(table, column, "dependent", depends_on=depends_on)
        elif config_type == "function":
            func_code = self.function_entry.get("1.0", tk.END).strip()
            if not func_code:
                messagebox.showerror("Błąd", "Podaj kod funkcji")
                return
            self.set_generation_rule(table, column, "function", function=func_code)
        else:
            self.set_generation_rule(table, column, "default")

        window.destroy()
        self.log(f"Zapisano konfigurację dla {table}.{column}")

    def set_generation_rule(self, table, column, rule_type, **kwargs):
        if table not in self.generation_rules:
            self.generation_rules[table] = {}

        self.generation_rules[table][column] = {
            'type': rule_type,
            **kwargs
        }

    def add_pattern(self):
        symbol = simpledialog.askstring("Nowy wzór", "Podaj symbol (1 znak):")
        if not symbol or len(symbol) != 1:
            return

        definition = simpledialog.askstring("Nowy wzór", "Podaj definicję:")
        if not definition:
            return

        self.pattern_definitions[symbol] = definition
        self.patterns_tree.insert("", "end", text=symbol, values=(definition,))

    def remove_pattern(self):
        selected = self.patterns_tree.selection()
        if not selected:
            return

        symbol = self.patterns_tree.item(selected[0])['text']
        if symbol in self.pattern_definitions:
            del self.pattern_definitions[symbol]
            self.patterns_tree.delete(selected[0])

    def generate_data(self):
        if not self.conn:
            messagebox.showerror("Błąd", "Najpierw połącz się z bazą danych")
            return

        try:
            count = int(self.records_entry.get())
            batch_size = int(self.batch_entry.get())

            for table in self.generation_rules.keys():
                self.generate_table_data(table, count, batch_size)

            messagebox.showinfo("Sukces", "Generowanie danych zakończone")
        except ValueError:
            messagebox.showerror("Błąd", "Podaj prawidłowe liczby")
        except Exception as e:
            messagebox.showerror("Błąd", str(e))

    def generate_table_data(self, table, count, batch_size):
        columns = [col['name'] for col in self.tables[table]
                   if not col['name'].endswith('_id') and not col['name'].startswith('id_')]

        query = sql.SQL("INSERT INTO {} ({}) VALUES ({})").format(
            sql.Identifier(table),
            sql.SQL(', ').join(map(sql.Identifier, columns)),
            sql.SQL(', ').join([sql.Placeholder()] * len(columns)))

        for i in range(0, count, batch_size):
            current_batch_size = min(batch_size, count - i)
            batch = []

            for _ in range(current_batch_size):
                row = []
                for column in columns:
                    row.append(self.generate_value(table, column))
                batch.append(row)

            try:
                self.cursor.executemany(query, batch)
                self.conn.commit()
                self.log(f"Dodano {len(batch)} rekordów do {table}")
            except Exception as e:
                self.conn.rollback()
                self.log(f"Błąd przy {table}: {str(e)}")

    def generate_value(self, table, column):
        col_info = next(col for col in self.tables[table] if col['name'] == column)

        if table in self.generation_rules and column in self.generation_rules[table]:
            rule = self.generation_rules[table][column]

            if rule['type'] == "custom":
                if col_info['type'] in ['character varying', 'text', 'varchar', 'enum']:
                    return random.choice(rule['values'])
                else:
                    return self.generate_default_value(table, column)
            elif rule['type'] == "pattern":
                if col_info['type'] in ['character varying', 'text', 'varchar', 'enum']:
                    return self.generate_from_pattern(rule['pattern'])
                else:
                    return self.generate_default_value(table, column)
            elif rule['type'] == "dependent":
                return self.generate_dependent_value(table, column, rule['depends_on'])
            elif rule['type'] == "function":
                if col_info['type'] in ['integer', 'bigint', 'smallint', 'numeric', 'decimal']:
                    try:
                        return eval(rule['function'], {
                            'fake': self.faker,
                            'random': random,
                            'table': table,
                            'column': column,
                            'generate_pesel': self.generate_valid_pesel,
                            'generate_nfz_number': self.generate_nfz_number,
                            'generate_pwz_number': self.generate_pwz_number,
                            'generate_icd9_code': self.generate_icd9_code
                        })
                    except Exception as e:
                        self.log(f"Błąd funkcji dla {table}.{column}: {str(e)}")
                        return None
                else:
                    return self.generate_default_value(table, column)

        return self.generate_default_value(table, column)

    def generate_from_pattern(self, pattern):
        pattern_map = {
            'C': lambda: str(random.randint(0, 9)),
            'L': lambda: random.choice('ABCDEFGHIJKLMNOPQRSTUVWXYZ'),
            'l': lambda: random.choice('abcdefghijklmnopqrstuvwxyz'),
            'A': lambda: random.choice('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz'),
            'P': lambda: random.choice(['K', 'M']),
            'D': lambda: self.faker.date_between(start_date='-90y', end_date='-18y').strftime('%Y-%m-%d'),
            'K': lambda: str(random.randint(0, 9)),
            'N': lambda: str(random.randint(1, 9999)),
            'S': lambda: self.generate_valid_pesel()[0],
            '9': lambda: str(random.randint(0, 9))
        }

        for symbol, definition in self.pattern_definitions.items():
            if symbol not in pattern_map:
                pattern_map[symbol] = lambda d=definition: eval(d)

        result = []
        for char in pattern:
            if char in pattern_map:
                result.append(pattern_map[char]())
            else:
                result.append(char)
        return ''.join(result)

    def generate_dependent_value(self, table, column, depends_on):
        if column.lower() == 'imie' and depends_on.lower() == 'pesel':
            pesel = self.generate_value(table, depends_on)
            gender = 'K' if int(pesel[-2]) % 2 == 0 else 'M'
            return self.faker.first_name_female() if gender == 'K' else self.faker.first_name_male()

        return self.generate_default_value(table, column)

    def generate_default_value(self, table, column):
        col_info = next(col for col in self.tables[table] if col['name'] == column)

        if col_info['type'] in ['integer', 'bigint', 'smallint']:
            return random.randint(0, 1000)

        if col_info['type'] in ['numeric', 'decimal']:
            return round(random.uniform(0, 1000), 2)

        if col_info['type'] in ['character varying', 'text', 'varchar', 'enum']:
            if table in self.generation_rules and column in self.generation_rules[table]:
                rule = self.generation_rules[table][column]
                if rule['type'] == "custom":
                    return random.choice(rule['values'])
                elif rule['type'] == "pattern":
                    return self.generate_from_pattern(rule['pattern'])

            if column.lower() == 'specjalizacja':
                return random.choice(['pediatra', 'kardiolog', 'neurolog'])
            elif column.lower() == 'rodzaj_wizyty':
                return random.choice(['NFZ', 'Prywatna'])
            elif column.lower() == 'status':
                return random.choice(['Zrealizowana', 'Odwołana', 'Zaplanowana'])
            elif column.lower() == 'metoda_platnosci':
                return random.choice(['Gotówka', 'Karta', 'Przelew'])
            elif column.lower() == 'status_ewus':
                return random.choice(['Ubezpieczony', 'Brak uprawnień'])

            text = self.faker.text(max_nb_chars=50)
            return text[:col_info['max_length']] if col_info['max_length'] else text

        if col_info['type'] in ['date']:
            return self.faker.date_between(start_date='-10y', end_date='today').strftime('%Y-%m-%d')

        if col_info['type'] in ['timestamp', 'timestamp without time zone']:
            return self.faker.date_time_this_decade().strftime('%Y-%m-%d %H:%M:%S')

        if col_info['type'] in ['boolean']:
            return random.choice([True, False])

        return None

    def generate_valid_pesel(self, birth_date=None):
        """Generuje prawidłowy numer PESEL"""
        if birth_date is None:
            if random.random() < 0.95:
                start_date = datetime(1940, 1, 1)
            else:
                start_date = datetime(1912, 1, 1)
            end_date = datetime(2002, 12, 31)
            birth_date = start_date + timedelta(days=random.randint(0, (end_date - start_date).days))

        year = birth_date.year
        month = birth_date.month
        day = birth_date.day

        if year >= 2000:
            month += 20

        date_part = f"{year % 100:02d}{month:02d}{day:02d}"

        gender_num = random.randint(0, 4) * 2 + random.choice([0, 1])
        random_part = f"{random.randint(0, 999):03d}{gender_num}"

        pesel_without_checksum = date_part + random_part

        weights = [1, 3, 7, 9, 1, 3, 7, 9, 1, 3]
        checksum = 0

        for i in range(10):
            checksum += int(pesel_without_checksum[i]) * weights[i]

        checksum = (10 - (checksum % 10)) % 10

        return pesel_without_checksum + str(checksum), 'K' if gender_num % 2 == 0 else 'M'

    def generate_name_by_gender(self, gender):
        if gender == 'M':
            return self.faker.first_name_male()
        else:
            return self.faker.first_name_female()

    def generate_nfz_number(self):
        return self.faker.bothify(text='??#########')

    def generate_pwz_number(self):
        return str(random.randint(1, 9)) + str(random.randint(0, 999999)).zfill(6)

    def generate_icd9_code(self):
        return self.faker.bothify(text='?##.?#?')

    def generate_medical_data(self, table_type):
        if not self.conn:
            messagebox.showerror("Błąd", "Najpierw połącz się z bazą danych")
            return

        try:
            count = simpledialog.askinteger("Generowanie danych", f"Ile rekordów {table_type} wygenerować?", minvalue=1,
                                            maxvalue=10000)
            if not count:
                return

            batch_size = simpledialog.askinteger("Generowanie danych", "Rozmiar partii:", initialvalue=10, minvalue=1,
                                                 maxvalue=100)
            if not batch_size:
                return

            if table_type == 'pacjenci':
                self.generate_pacjenci(count, batch_size)
            elif table_type == 'lekarze':
                self.generate_lekarze(count, batch_size)
            elif table_type == 'wizyty':
                self.generate_wizyty(count, batch_size)
            elif table_type == 'recepty':
                self.generate_recepty(count, batch_size)
            elif table_type == 'skierowania':
                self.generate_skierowania(count, batch_size)
            elif table_type == 'historia_chorob':
                self.generate_historia_chorob(count, batch_size)
            elif table_type == 'badania_diagnostyczne':
                self.generate_badania_diagnostyczne(count, batch_size)
            elif table_type == 'platnosci':
                self.generate_platnosci(count, batch_size)
            elif table_type == 'ewus':
                self.generate_ewus(count, batch_size)

        except Exception as e:
            messagebox.showerror("Błąd", str(e))

    def generate_all_medical_data(self):
        if not self.conn:
            messagebox.showerror("Błąd", "Najpierw połącz się z bazą danych")
            return

        try:
            counts = {
                'pacjenci': simpledialog.askinteger("Generowanie danych", "Ile pacjentów wygenerować?", minvalue=1,
                                                    maxvalue=10000),
                'lekarze': simpledialog.askinteger("Generowanie danych", "Ile lekarzy wygenerować?", minvalue=1,
                                                   maxvalue=1000),
                'wizyty': simpledialog.askinteger("Generowanie danych", "Ile wizyt wygenerować?", minvalue=1,
                                                  maxvalue=10000),
                'recepty': simpledialog.askinteger("Generowanie danych", "Ile recept wygenerować?", minvalue=1,
                                                   maxvalue=10000),
                'skierowania': simpledialog.askinteger("Generowanie danych", "Ile skierowań wygenerować?", minvalue=1,
                                                       maxvalue=10000),
                'historia_chorob': simpledialog.askinteger("Generowanie danych",
                                                           "Ile wpisów historii chorób wygenerować?", minvalue=1,
                                                           maxvalue=10000),
                'badania_diagnostyczne': simpledialog.askinteger("Generowanie danych",
                                                                 "Ile badań diagnostycznych wygenerować?", minvalue=1,
                                                                 maxvalue=10000),
                'platnosci': simpledialog.askinteger("Generowanie danych", "Ile płatności wygenerować?", minvalue=1,
                                                     maxvalue=10000),
                'ewus': simpledialog.askinteger("Generowanie danych", "Ile weryfikacji eWUŚ wygenerować?", minvalue=1,
                                                maxvalue=10000)
            }

            batch_size = simpledialog.askinteger("Generowanie danych", "Rozmiar partii:", initialvalue=10, minvalue=1,
                                                 maxvalue=100)
            if not batch_size:
                return

            for table_type, count in counts.items():
                if count:
                    if table_type == 'pacjenci':
                        self.generate_pacjenci(count, batch_size)
                    elif table_type == 'lekarze':
                        self.generate_lekarze(count, batch_size)
                    elif table_type == 'wizyty':
                        self.generate_wizyty(count, batch_size)
                    elif table_type == 'recepty':
                        self.generate_recepty(count, batch_size)
                    elif table_type == 'skierowania':
                        self.generate_skierowania(count, batch_size)
                    elif table_type == 'historia_chorob':
                        self.generate_historia_chorob(count, batch_size)
                    elif table_type == 'badania_diagnostyczne':
                        self.generate_badania_diagnostyczne(count, batch_size)
                    elif table_type == 'platnosci':
                        self.generate_platnosci(count, batch_size)
                    elif table_type == 'ewus':
                        self.generate_ewus(count, batch_size)

            messagebox.showinfo("Sukces", "Generowanie danych medycznych zakończone")
        except Exception as e:
            messagebox.showerror("Błąd", str(e))

    def generate_pacjenci(self, count, batch_size):
        self.medical_log("Rozpoczynanie generowania pacjentów...")
        batch = []
        generated = 0

        while generated < count:
            pesel, gender = self.generate_valid_pesel()
            self.cursor.execute("SELECT COUNT(*) FROM Pacjenci WHERE PESEL = %s", (pesel,))
            if self.cursor.fetchone()[0] > 0:
                continue

            imie = self._truncate_value('Pacjenci', 'Imie', self.generate_name_by_gender(gender))
            nazwisko = self._truncate_value('Pacjenci', 'Nazwisko', self.faker.last_name())
            adres = self._truncate_value('Pacjenci', 'Adres', self.faker.address().replace('\n', ', '))
            telefon = self._truncate_value('Pacjenci', 'Telefon', self.faker.phone_number().replace(' ', '')[:15])
            email = self._truncate_value('Pacjenci', 'Email', self.faker.email())

            batch.append({
                'Imie': imie,
                'Nazwisko': nazwisko,
                'PESEL': pesel,
                'Adres': adres,
                'Telefon': telefon,
                'Email': email,
                'NFZ_Numer_Ubezpieczenia': self.generate_nfz_number()
            })

            if len(batch) >= batch_size or generated + len(batch) >= count:
                query = """
                    INSERT INTO Pacjenci (Imie, Nazwisko, PESEL, Adres, Telefon, Email, NFZ_Numer_Ubezpieczenia)
                    VALUES (%(Imie)s, %(Nazwisko)s, %(PESEL)s, %(Adres)s, %(Telefon)s, %(Email)s, %(NFZ_Numer_Ubezpieczenia)s)
                    RETURNING ID_Pacjenta
                """
                if self._insert_medical_batch(query, batch):
                    self.cursor.execute("SELECT ID_Pacjenta FROM Pacjenci ORDER BY ID_Pacjenta DESC LIMIT %s",
                                        (len(batch),))
                    self.pacjenci_ids.extend([row[0] for row in self.cursor.fetchall()])
                    generated += len(batch)
                    self.medical_log(f"Dodano {len(batch)} pacjentów. Łącznie: {generated}")
                batch = []

        self.medical_log(f"Wygenerowano {count} pacjentów.")

    def generate_lekarze(self, count, batch_size):
        self.medical_log("Rozpoczynanie generowania lekarzy...")
        batch = []
        generated = 0
        specjalizacje = ['kardiolog', 'neurolog', 'kardiochirurg', 'pulmonolog', 'internista', 'dermatolog',
                         'neurochirurg', 'ortopeda']

        self.cursor.execute("SELECT COALESCE(MAX(ID_Lekarza), 0) FROM Lekarze")
        max_id = self.cursor.fetchone()[0]
        next_id = max_id + 1

        while generated < count:
            pwz = self.generate_pwz_number()
            self.cursor.execute("SELECT COUNT(*) FROM Lekarze WHERE Numer_PWZ = %s", (pwz,))
            if self.cursor.fetchone()[0] > 0:
                continue

            gender = random.choices(['M', 'K'], weights=[55, 45])[0]
            imie = self._truncate_value('Lekarze', 'Imie', self.generate_name_by_gender(gender))
            nazwisko = self._truncate_value('Lekarze', 'Nazwisko', self.faker.last_name())
            specjalizacja = self._truncate_value('Lekarze', 'Specjalizacja', random.choice(specjalizacje))

            batch.append({
                'ID_Lekarza': next_id,
                'Imie': imie,
                'Nazwisko': nazwisko,
                'Specjalizacja': specjalizacja,
                'Numer_PWZ': pwz,
                'NFZ_Kod_Lekarza': self.generate_nfz_number()
            })
            next_id += 1

            if len(batch) >= batch_size or generated + len(batch) >= count:
                query = """
                    INSERT INTO Lekarze (ID_Lekarza, Imie, Nazwisko, Specjalizacja, Numer_PWZ, NFZ_Kod_Lekarza)
                    VALUES (%(ID_Lekarza)s, %(Imie)s, %(Nazwisko)s, %(Specjalizacja)s, %(Numer_PWZ)s, %(NFZ_Kod_Lekarza)s)
                    RETURNING ID_Lekarza
                """
                if self._insert_medical_batch(query, batch):
                    generated += len(batch)
                    self.medical_log(f"Dodano {len(batch)} lekarzy. Łącznie: {generated}")
                    self.lekarze_ids.extend([row['ID_Lekarza'] for row in batch])
                batch = []

        self.medical_log(f"Wygenerowano {count} lekarzy.")

    def generate_wizyty(self, count, batch_size):
        self.medical_log("Rozpoczynanie generowania wizyt...")
        if not self.pacjenci_ids or not self.lekarze_ids:
            self.medical_log("Błąd: Najpierw wygeneruj pacjentów i lekarzy")
            return

        batch = []
        generated = 0
        rodzaje_wizyt = ['NFZ', 'Prywatna']
        statusy = ['Zrealizowana', 'Odwołana', 'Zaplanowana']

        while generated < count:
            pacjent_id = random.choice(self.pacjenci_ids)
            lekarz_id = random.choice(self.lekarze_ids)
            data_wizyty = self.faker.date_time_between(start_date='-1y', end_date='+1y')
            rodzaj_wizyty = random.choice(rodzaje_wizyt)
            status = random.choice(statusy)

            batch.append({
                'ID_Pacjenta': pacjent_id,
                'ID_Lekarza': lekarz_id,
                'Data_Wizyty': data_wizyty,
                'Rodzaj_Wizyty': rodzaj_wizyty,
                'Status': status
            })

            if len(batch) >= batch_size or generated + len(batch) >= count:
                query = """
                    INSERT INTO Wizyty (ID_Pacjenta, ID_Lekarza, Data_Wizyty, Rodzaj_Wizyty, Status)
                    VALUES (%(ID_Pacjenta)s, %(ID_Lekarza)s, %(Data_Wizyty)s, %(Rodzaj_Wizyty)s, %(Status)s)
                    RETURNING ID_Wizyty
                """
                if self._insert_medical_batch(query, batch):
                    self.cursor.execute("SELECT ID_Wizyty FROM Wizyty ORDER BY ID_Wizyty DESC LIMIT %s", (len(batch),))
                    self.wizyty_ids.extend([row[0] for row in self.cursor.fetchall()])
                    generated += len(batch)
                    self.medical_log(f"Dodano {len(batch)} wizyt. Łącznie: {generated}")
                batch = []

        self.medical_log(f"Wygenerowano {count} wizyt.")

    def generate_recepty(self, count, batch_size):
        self.medical_log("Rozpoczynanie generowania recept...")
        if not self.pacjenci_ids or not self.lekarze_ids:
            self.medical_log("Błąd: Najpierw wygeneruj pacjentów i lekarzy")
            return

        batch = []
        generated = 0
        produkty_lecznicze = [
            'APAP', 'Ibuprom', 'Polopiryna', 'Euthyrox', 'Xanax',
            'Aspirin', 'Paracetamol', 'Ketonal', 'No-Spa', 'Furosemid',
            'Metformax', 'Bisocard', 'Atorvastatin', 'Amlodipine', 'Pantoprazole'
        ]

        while generated < count:
            pacjent_id = random.choice(self.pacjenci_ids)
            lekarz_id = random.choice(self.lekarze_ids)
            kod_produktu = random.choice(produkty_lecznicze)
            dawkowanie = self._truncate_value('Recepty', 'Dawkowanie', self.faker.sentence(nb_words=6))

            batch.append({
                'ID_Pacjenta': pacjent_id,
                'ID_Lekarza': lekarz_id,
                'Data_Wystawienia': self.faker.date_between(start_date='-1y', end_date='today'),
                'Kod_Produktu_Leczniczego': kod_produktu,
                'Dawkowanie': dawkowanie
            })

            if len(batch) >= batch_size or generated + len(batch) >= count:
                query = """
                    INSERT INTO Recepty (ID_Pacjenta, ID_Lekarza, Data_Wystawienia, Kod_Produktu_Leczniczego, Dawkowanie)
                    VALUES (%(ID_Pacjenta)s, %(ID_Lekarza)s, %(Data_Wystawienia)s, %(Kod_Produktu_Leczniczego)s, %(Dawkowanie)s)
                """
                if self._insert_medical_batch(query, batch):
                    generated += len(batch)
                    self.medical_log(f"Dodano {len(batch)} recept. Łącznie: {generated}")
                batch = []

        self.medical_log(f"Wygenerowano {count} recept.")

    def generate_skierowania(self, count, batch_size):
        self.medical_log("Rozpoczynanie generowania skierowań...")
        if not self.pacjenci_ids or not self.lekarze_ids:
            self.medical_log("Błąd: Najpierw wygeneruj pacjentów i lekarzy")
            return

        batch = []
        generated = 0

        while generated < count:
            pacjent_id = random.choice(self.pacjenci_ids)
            lekarz_id = random.choice(self.lekarze_ids)

            batch.append({
                'ID_Pacjenta': pacjent_id,
                'ID_Lekarza': lekarz_id,
                'Data_Wystawienia': self.faker.date_between(start_date='-1y', end_date='today'),
                'Kod_Procedury_ICD9': self.generate_icd9_code()
            })

            if len(batch) >= batch_size or generated + len(batch) >= count:
                query = """
                    INSERT INTO Skierowania (ID_Pacjenta, ID_Lekarza, Data_Wystawienia, Kod_Procedury_ICD9)
                    VALUES (%(ID_Pacjenta)s, %(ID_Lekarza)s, %(Data_Wystawienia)s, %(Kod_Procedury_ICD9)s)
                """
                if self._insert_medical_batch(query, batch):
                    generated += len(batch)
                    self.medical_log(f"Dodano {len(batch)} skierowań. Łącznie: {generated}")
                batch = []

        self.medical_log(f"Wygenerowano {count} skierowań.")

    def generate_historia_chorob(self, count, batch_size):
        self.medical_log("Rozpoczynanie generowania historii chorób...")
        if not self.pacjenci_ids:
            self.medical_log("Błąd: Najpierw wygeneruj pacjentów")
            return

        batch = []
        generated = 0
        diagnozy = [
            'Grypa', 'Zapalenie płuc', 'Nadciśnienie tętnicze', 'Cukrzyca typu 2',
            'Astma oskrzelowa', 'Choroba niedokrwienna serca', 'Zapalenie zatok',
            'Zapalenie ucha', 'Zapalenie gardła', 'Choroba refluksowa przełyku',
            'Niedoczynność tarczycy', 'Nadczynność tarczycy', 'Choroba wrzodowa',
            'Zapalenie stawów', 'Dna moczanowa', 'Migrena', 'Depresja', 'Zaburzenia lękowe'
        ]

        while generated < count:
            pacjent_id = random.choice(self.pacjenci_ids)
            opis = self._truncate_value('Historia_Chorob', 'Opis',
                                        f"Rozpoznanie: {random.choice(diagnozy)}. {self.faker.paragraph(nb_sentences=3)}")

            batch.append({
                'ID_Pacjenta': pacjent_id,
                'Data_Diagnostyki': self.faker.date_between(start_date='-5y', end_date='today'),
                'Opis': opis
            })

            if len(batch) >= batch_size or generated + len(batch) >= count:
                query = """
                    INSERT INTO Historia_Chorob (ID_Pacjenta, Data_Diagnostyki, Opis)
                    VALUES (%(ID_Pacjenta)s, %(Data_Diagnostyki)s, %(Opis)s)
                """
                if self._insert_medical_batch(query, batch):
                    generated += len(batch)
                    self.medical_log(f"Dodano {len(batch)} wpisów. Łącznie: {generated}")
                batch = []

        self.medical_log(f"Wygenerowano {count} wpisów do historii chorób.")

    def generate_badania_diagnostyczne(self, count, batch_size):
        self.medical_log("Rozpoczynanie generowania badań diagnostycznych...")
        if not self.pacjenci_ids:
            self.medical_log("Błąd: Najpierw wygeneruj pacjentów")
            return

        batch = []
        generated = 0
        rodzaje_badan = [
            'Morfologia krwi', 'Badanie moczu', 'EKG', 'USG jamy brzusznej',
            'RTG klatki piersiowej', 'Tomografia komputerowa', 'Rezonans magnetyczny',
            'Badanie poziomu glukozy', 'Badanie cholesterolu', 'Badanie TSH',
            'Badanie CRP', 'Badanie ALT', 'Badanie kreatyniny', 'Kolposkopia',
            'Gastroskopia', 'Kolonoskopia', 'Spirometria', 'Echo serca'
        ]

        while generated < count:
            pacjent_id = random.choice(self.pacjenci_ids)
            rodzaj_badania = self._truncate_value('Badania_Diagnostyczne', 'Rodzaj_Badania',
                                                  random.choice(rodzaje_badan))
            wynik = self._truncate_value('Badania_Diagnostyczne', 'Wynik', self.faker.paragraph(nb_sentences=2))

            batch.append({
                'ID_Pacjenta': pacjent_id,
                'Rodzaj_Badania': rodzaj_badania,
                'Data_Badania': self.faker.date_between(start_date='-1y', end_date='today'),
                'Wynik': wynik
            })

            if len(batch) >= batch_size or generated + len(batch) >= count:
                query = """
                    INSERT INTO Badania_Diagnostyczne (ID_Pacjenta, Rodzaj_Badania, Data_Badania, Wynik)
                    VALUES (%(ID_Pacjenta)s, %(Rodzaj_Badania)s, %(Data_Badania)s, %(Wynik)s)
                """
                if self._insert_medical_batch(query, batch):
                    generated += len(batch)
                    self.medical_log(f"Dodano {len(batch)} badań. Łącznie: {generated}")
                batch = []

        self.medical_log(f"Wygenerowano {count} badań diagnostycznych.")

    def generate_platnosci(self, count, batch_size):
        self.medical_log("Rozpoczynanie generowania płatności...")
        if not self.pacjenci_ids or not self.wizyty_ids:
            self.medical_log("Błąd: Najpierw wygeneruj pacjentów i wizyty")
            return

        batch = []
        generated = 0
        metody_platnosci = ['Gotówka', 'Karta', 'Przelew']

        while generated < count:
            pacjent_id = random.choice(self.pacjenci_ids)
            wizyta_id = random.choice(self.wizyty_ids)

            self.cursor.execute("SELECT Rodzaj_Wizyty FROM Wizyty WHERE ID_Wizyty = %s", (wizyta_id,))
            rodzaj_wizyty = self.cursor.fetchone()[0]

            if rodzaj_wizyty == 'NFZ':
                kwota = 0.00
            else:
                kwota = round(random.uniform(100, 500), 2)

            batch.append({
                'ID_Pacjenta': pacjent_id,
                'ID_Wizyty': wizyta_id,
                'Kwota': kwota,
                'Data_Platnosci': self.faker.date_between(start_date='-1y', end_date='today'),
                'Metoda_Platnosci': random.choice(metody_platnosci)
            })

            if len(batch) >= batch_size or generated + len(batch) >= count:
                query = """
                    INSERT INTO Platnosci (ID_Pacjenta, ID_Wizyty, Kwota, Data_Platnosci, Metoda_Platnosci)
                    VALUES (%(ID_Pacjenta)s, %(ID_Wizyty)s, %(Kwota)s, %(Data_Platnosci)s, %(Metoda_Platnosci)s)
                """
                if self._insert_medical_batch(query, batch):
                    generated += len(batch)
                    self.medical_log(f"Dodano {len(batch)} płatności. Łącznie: {generated}")
                batch = []

        self.medical_log(f"Wygenerowano {count} płatności.")

    def generate_ewus(self, count, batch_size):
        self.medical_log("Rozpoczynanie generowania weryfikacji eWUŚ...")
        if not self.pacjenci_ids:
            self.medical_log("Błąd: Najpierw wygeneruj pacjentów")
            return

        batch = []
        generated = 0
        statusy = ['Ubezpieczony', 'Brak uprawnień']

        while generated < count:
            pacjent_id = random.choice(self.pacjenci_ids)

            batch.append({
                'ID_Pacjenta': pacjent_id,
                'Data_Weryfikacji': self.faker.date_between(start_date='-1y', end_date='today'),
                'Status': random.choices(statusy, weights=[0.85, 0.15])[0]
            })

            if len(batch) >= batch_size or generated + len(batch) >= count:
                query = """
                    INSERT INTO EWUS (ID_Pacjenta, Data_Weryfikacji, Status)
                    VALUES (%(ID_Pacjenta)s, %(Data_Weryfikacji)s, %(Status)s)
                """
                if self._insert_medical_batch(query, batch):
                    generated += len(batch)
                    self.medical_log(f"Dodano {len(batch)} weryfikacji. Łącznie: {generated}")
                batch = []

        self.medical_log(f"Wygenerowano {count} weryfikacji eWUŚ.")

    def _insert_medical_batch(self, query, batch):
        try:
            self.cursor.executemany(query, batch)
            self.conn.commit()
            return True
        except Exception as e:
            self.conn.rollback()
            self.medical_log(f"Błąd podczas wstawiania danych: {str(e)}")
            return False

    def medical_log(self, message):
        self.medical_log_text.config(state=tk.NORMAL)
        self.medical_log_text.insert(tk.END, message + "\n")
        self.medical_log_text.config(state=tk.DISABLED)
        self.medical_log_text.see(tk.END)

    def log(self, message):
        self.log_text.config(state=tk.NORMAL)
        self.log_text.insert(tk.END, message + "\n")
        self.log_text.config(state=tk.DISABLED)
        self.log_text.see(tk.END)

    def clear_log(self):
        self.log_text.config(state=tk.NORMAL)
        self.log_text.delete(1.0, tk.END)
        self.log_text.config(state=tk.DISABLED)

    def load_last_config(self):
        try:
            with open("generator_config.txt", "r") as f:
                lines = f.readlines()
                if len(lines) >= 5:
                    self.host_entry.insert(0, lines[0].strip())
                    self.port_entry.insert(0, lines[1].strip())
                    self.db_entry.insert(0, lines[2].strip())
                    self.user_entry.insert(0, lines[3].strip())
                    self.password_entry.insert(0, lines[4].strip())
        except FileNotFoundError:
            pass

    def on_closing(self):
        with open("generator_config.txt", "w") as f:
            f.write(f"{self.host_entry.get()}\n")
            f.write(f"{self.port_entry.get()}\n")
            f.write(f"{self.db_entry.get()}\n")
            f.write(f"{self.user_entry.get()}\n")
            f.write(f"{self.password_entry.get()}\n")

        if self.conn:
            self.conn.close()
        self.root.destroy()


if __name__ == "__main__":
    root = tk.Tk()
    app = UniversalDataGenerator(root)
    root.protocol("WM_DELETE_WINDOW", app.on_closing)
    root.mainloop()