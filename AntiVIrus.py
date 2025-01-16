import os
import yara
import time
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from tkinter import Tk, Label, Button, filedialog, Text, Scrollbar, END, StringVar, DISABLED, NORMAL

# Funkcija za nalaganje YARA pravil
def load_yara_rules(rules_directory):
    rules = {}
    for file_name in os.listdir(rules_directory):
        if file_name.endswith(".yar") or file_name.endswith(".yara"):
            file_path = os.path.join(rules_directory, file_name)
            try:
                rules[file_name] = yara.compile(filepath=file_path)
                log_message(f"Naloženo pravilo: {file_name}", "info")
            except yara.YaraSyntaxError as e:
                log_message(f"Napaka pri nalaganju {file_name}: {e}", "error")
    return rules

# Funkcija za skeniranje datoteke
# Posodobljena funkcija za skeniranje datoteke (branje v manjših blokih)
def scan_file(file_path, rules):
    try:
        time.sleep(1)  # Dodaj zamik, če je potreben
        with open(file_path, "rb") as f:
            while chunk := f.read(4096):  # Preberi datoteko v blokih po 4KB
                for rule_name, rule in rules.items():
                    matches = rule.match(data=chunk)
                    if matches:
                        log_message(f"Zaznana grožnja v {file_path}: {matches}", "virus")
                        return True
    except Exception as e:
        log_message(f"Napaka pri skeniranju {file_path}: {e}", "error")
    log_message(f"Datoteka {file_path} ni zlonamerna.", "safe")
    return False

# Pasivno skeniranje (na zahtevo uporabnika)
# Funkcija za pasivno skeniranje z obravnavo napak
def passive_scan(directory, rules):
    log_message(f"Začelo se je skeniranje imenika: {directory}", "info")
    for root, dirs, files in os.walk(directory):
        for file in files:
            file_path = os.path.join(root, file)
            try:
                scan_file(file_path, rules)
            except PermissionError:
                log_message(f"Napaka pri dostopu do {file_path}: Brez dovoljenj.", "error")
            except Exception as e:
                log_message(f"Napaka pri obdelavi {file_path}: {e}", "error")
    log_message("Skeniranje končano.", "info")

# Aktivno spremljanje imenikov (Watchdog)
class FileMonitorHandler(FileSystemEventHandler):
    def __init__(self, rules):
        self.rules = rules

    def on_created(self, event):
        if not event.is_directory:
            log_message(f"Nova datoteka zaznana: {event.src_path}", "info")
            scan_file(event.src_path, self.rules)

def active_monitor(directory, rules):
    event_handler = FileMonitorHandler(rules)
    observer = Observer()
    observer.schedule(event_handler, directory, recursive=True)
    observer.start()
    log_message(f"Aktivno spremljanje imenika: {directory}", "info")
    return observer

# UI funkcije
def log_message(message, message_type):
    log_box.config(state=NORMAL)
    if message_type == "virus":
        log_box.insert(END, message + "\n", ("virus",))
    elif message_type == "safe":
        log_box.insert(END, message + "\n", ("safe",))
    elif message_type == "error":
        log_box.insert(END, message + "\n", ("error",))
    else:
        log_box.insert(END, message + "\n", ("info",))
    log_box.config(state=DISABLED)
    log_box.see(END)

def start_passive_scan():
    passive_scan(scan_directory.get(), yara_rules)

def start_active_monitor():
    global observer
    if observer is None:
        observer = active_monitor(scan_directory.get(), yara_rules)
        monitor_status.set("Aktivno spremljanje: VKLOPLJENO")
    else:
        log_message("Spremljanje že poteka.", "info")

def stop_active_monitor():
    global observer
    if observer is not None:
        observer.stop()
        observer.join()
        observer = None
        monitor_status.set("Aktivno spremljanje: IZKLOPLJENO")
        log_message("Spremljanje ustavljeno.", "info")

def select_scan_directory():
    directory = filedialog.askdirectory()
    if directory:
        scan_directory.set(directory)
        log_message(f"Izbran imenik za skeniranje: {directory}", "info")

def sync_yara_rules():
    log_message("Sinhronizacija pravil... (trenutno ni implementirano)", "info")

# Glavna UI aplikacija
root = Tk()
root.title("AntiVirus")

# Globalne spremenljivke
scan_directory = StringVar(value="./scan_this")
monitor_status = StringVar(value="Aktivno spremljanje: IZKLOPLJENO")
observer = None

# UI elementi
Label(root, text="Izbran imenik za skeniranje:").pack()
Label(root, textvariable=scan_directory).pack()

Button(root, text="Izberi imenik", command=select_scan_directory).pack()
Button(root, text="Začni pasivno skeniranje", command=start_passive_scan).pack()
Button(root, text="Začni aktivno spremljanje", command=start_active_monitor).pack()
Button(root, text="Ustavi aktivno spremljanje", command=stop_active_monitor).pack()


Label(root, textvariable=monitor_status, fg="blue").pack()

log_box = Text(root, height=20, width=80)
log_box.pack()
log_box.tag_config("virus", background="red", foreground="white")
log_box.tag_config("safe", background="green", foreground="black")
log_box.tag_config("error", background="yellow", foreground="black")
log_box.tag_config("info", background="white", foreground="black")
log_box.config(state=DISABLED)

scrollbar = Scrollbar(root, command=log_box.yview)
scrollbar.pack(side="right", fill="y")
log_box.config(yscrollcommand=scrollbar.set)

# Naloži YARA pravila
YARA_RULES_DIR = "./yara_rules"
yara_rules = load_yara_rules(YARA_RULES_DIR)

# Zagon aplikacije
root.mainloop()
