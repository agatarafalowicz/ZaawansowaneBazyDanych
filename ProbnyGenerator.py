import tkinter as tk
from tkinter import ttk, messagebox, simpledialog, filedialog
import psycopg2
from psycopg2 import sql
from faker import Faker
import random
import BasicDataGenerator
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

        self.setup_ui()
        self.load_last_config()

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

        ttk.Button(frame, text="Generuj dane", command=self.generate_data).grid(row=0, column=4, padx=5)

        self.log_text = tk.Text(tab, height=15, state=tk.DISABLED)
        self.log_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)

        ttk.Button(tab, text="Wyczyść log", command=self.clear_log).pack(side=tk.RIGHT, padx=10, pady=5)

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
            self._cache_column_lengths()
            self.notebook.select(1)
            self.log("Połączono z bazą danych")
        except Exception as e:
            messagebox.showerror("Błąd połączenia", str(e))

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

        var = tk.StringVar(value="default")
        col_info = next(c for c in self.tables[table] if c['name'] == column)

        main_frame = ttk.Frame(top)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)

        radio_frame = ttk.Frame(main_frame)
        radio_frame.pack(fill=tk.X, pady=5)

        ttk.Radiobutton(radio_frame, text="Domyślny", variable=var, value="default").pack(anchor=tk.W)
        ttk.Radiobutton(radio_frame, text="Własne wartości", variable=var, value="custom").pack(anchor=tk.W)
        ttk.Radiobutton(radio_frame, text="Wzór", variable=var, value="pattern").pack(anchor=tk.W)
        ttk.Radiobutton(radio_frame, text="Zależny", variable=var, value="dependent").pack(anchor=tk.W)

        if col_info['type'] in ['integer', 'numeric']:
            ttk.Radiobutton(radio_frame, text="Funkcja", variable=var, value="function").pack(anchor=tk.W)

        input_frame = ttk.Frame(main_frame)
        input_frame.pack(fill=tk.BOTH, expand=True)

        self.current_config_widget = None
        self.custom_entry = ttk.Entry(input_frame)
        self.pattern_entry = ttk.Entry(input_frame)
        self.dependent_combobox = ttk.Combobox(input_frame)
        self.function_text = tk.Text(input_frame, height=4)

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
            elif state == "dependent":
                self.dependent_combobox['values'] = [c['name'] for c in self.tables[table] if c['name'] != column]
                self.dependent_combobox.pack(fill=tk.X, expand=True)
                self.current_config_widget = self.dependent_combobox
            elif state == "function":
                self.function_text.pack(fill=tk.BOTH, expand=True)
                self.current_config_widget = self.function_text

        var.trace_add("write", lambda *args: update_state())
        update_state()

        ttk.Button(main_frame, text="Zapisz", command=lambda: self.save_column_config(
            top, table, column, var.get(),
            self.custom_entry.get(),
            self.pattern_entry.get(),
            self.dependent_combobox.get(),
            self.function_text.get("1.0", tk.END)
        )).pack(pady=5)

    def save_column_config(self, window, table, column, config_type, custom_values, pattern, depends_on, function):
        config = {}
        try:
            if config_type == "custom":
                values = [v.strip() for v in custom_values.split(";") if v.strip()]
                if not values:
                    raise ValueError("Podaj wartości oddzielone średnikami")
                config = {'type': 'custom', 'values': values}
            elif config_type == "pattern":
                if not pattern:
                    raise ValueError("Podaj wzór")
                config = {'type': 'pattern', 'pattern': pattern}
            elif config_type == "dependent":
                if not depends_on:
                    raise ValueError("Wybierz kolumnę")
                config = {'type': 'dependent', 'depends_on': depends_on}
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
            for table in self.generation_rules:
                count = int(self.records_entry.get())
                batch_size = int(self.batch_entry.get())
                self.generate_table_data(table, count, batch_size)
            messagebox.showinfo("Sukces", "Dane wygenerowane!")
        except Exception as e:
            messagebox.showerror("Błąd", str(e))

    def generate_table_data(self, table, count, batch_size):
        columns = [c['name'] for c in self.tables[table] if not c['name'].startswith('id_')]
        query = sql.SQL("INSERT INTO {} ({}) VALUES ({})").format(
            sql.Identifier(table),
            sql.SQL(', ').join(map(sql.Identifier, columns)),
            sql.SQL(', ').join([sql.Placeholder()] * len(columns))
        )

        for i in range(0, count, batch_size):
            current_batch = min(batch_size, count - i)
            batch = []
            for _ in range(current_batch):
                row = [self.generate_value(table, col) for col in columns]
                batch.append(row)
            try:
                self.cursor.executemany(query, batch)
                self.conn.commit()
                self.log(f"Dodano {len(batch)} rekordów do {table}")
            except Exception as e:
                self.conn.rollback()
                self.log(f"Błąd: {str(e)}")

    def generate_value(self, table, column):
        key = (table.lower(), column.lower())
        if key in self.special_data:
            try:
                return BasicDataGenerator.GenerateData(self.special_data[key])
            except Exception as e:
                self.log(f"Błąd specjalnego generatora: {str(e)}")

        if table in self.generation_rules and column in self.generation_rules[table]:
            rule = self.generation_rules[table][column]
            if rule['type'] == "custom":
                return random.choice(rule['values'])
            elif rule['type'] == "pattern":
                return self.generate_from_pattern(rule['pattern'])
            elif rule['type'] == "dependent":
                return self.generate_dependent_value(table, column, rule['depends_on'])
            elif rule['type'] == "function":
                try:
                    return eval(rule['function'], {'fake': self.faker, 'random': random})
                except Exception as e:
                    self.log(f"Błąd funkcji: {str(e)}")
                    return None

        return self.generate_default_value(table, column)

    def generate_from_pattern(self, pattern):
        result = []
        for char in pattern:
            if char == 'C':
                result.append(str(random.randint(0, 9)))
            elif char == 'L':
                result.append(chr(random.randint(65, 90)))
            elif char == 'l':
                result.append(chr(random.randint(97, 122)))
            elif char == 'A':
                result.append(chr(random.choice([random.randint(65, 90), random.randint(97, 122)])))
            elif char == 'P':
                result.append(random.choice(['K', 'M']))
            elif char == 'D':
                result.append(self.faker.date_this_decade().strftime("%Y-%m-%d"))
            elif char == 'K':
                result.append(str(random.randint(0, 9)))
            elif char == 'N':
                result.append(str(random.randint(1, 9999)))
            elif char == 'S':
                result.append(self.faker.pesel())
            elif char == '9':
                result.append(str(random.randint(0, 9)))
            else:
                result.append(char)
        return ''.join(result)

    def generate_dependent_value(self, table, column, depends_on):
        #TO DO: TUTAJ MUSZE DODAC ZALEZNOSCI ZEBY SIE LADNIE LACZYLO
        return "Wartość zależna"

    def generate_default_value(self, table, column):
        col_info = next(c for c in self.tables[table] if c['name'] == column)
        if col_info['type'] in ['integer', 'bigint']:
            return random.randint(1, 1000)
        elif col_info['type'] in ['varchar', 'text']:
            max_len = col_info['max_length'] or 50
            return self.faker.text(max_nb_chars=max_len)[:max_len]
        elif col_info['type'] == 'date':
            return self.faker.date_this_decade()
        elif col_info['type'] == 'boolean':
            return random.choice([True, False])
        return None

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
                    elif rule['type'] == "dependent":
                        line = f"{table}@{col}@DEPENDENT@{rule['depends_on']}\n"
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
                elif rule_type == "DEPENDENT":
                    self.generation_rules[table][col] = {
                        'type': 'dependent',
                        'depends_on': parts[3]
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


if __name__ == "__main__":
    root = tk.Tk()
    app = UniversalDataGenerator(root)
    root.protocol("WM_DELETE_WINDOW", app.on_closing)
    root.mainloop()