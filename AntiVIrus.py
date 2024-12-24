import os
import yara
import time
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from tkinter import Tk, Label, Button, filedialog, Text, Scrollbar, END, StringVar

# Funkcija za nalaganje YARA pravil
def load_yara_rules(rules_directory):
    rules = {}
    for file_name in os.listdir(rules_directory):
        if file_name.endswith(".yar") or file_name.endswith(".yara"):
            file_path = os.path.join(rules_directory, file_name)
            try:
                rules[file_name] = yara.compile(filepath=file_path)
                log_message(f"Naloženo pravilo: {file_name}")
            except yara.YaraSyntaxError as e:
                log_message(f"Napaka pri nalaganju {file_name}: {e}")
    return rules

# Funkcija za skeniranje datoteke
def scan_file(file_path, rules):
    try:
        with open(file_path, "rb") as f:
            data = f.read()
            for rule_name, rule in rules.items():
                matches = rule.match(data=data)
                if matches:
                    log_message(f"Zaznana grožnja v {file_path}: {matches}")
                    return True
    except Exception as e:
        log_message(f"Napaka pri skeniranju {file_path}: {e}")
    return False

# Pasivno skeniranje (na zahtevo uporabnika)
def passive_scan(directory, rules):
    log_message(f"Začelo se je skeniranje imenika: {directory}")
    for root, _, files in os.walk(directory):
        for file in files:
            file_path = os.path.join(root, file)
            scan_file(file_path, rules)
    log_message("Skeniranje končano.")

# Aktivno spremljanje imenikov (Watchdog)
class FileMonitorHandler(FileSystemEventHandler):
    def __init__(self, rules):
        self.rules = rules

    def on_created(self, event):
        if not event.is_directory:
            log_message(f"Nova datoteka zaznana: {event.src_path}")
            scan_file(event.src_path, self.rules)

def active_monitor(directory, rules):
    event_handler = FileMonitorHandler(rules)
    observer = Observer()
    observer.schedule(event_handler, directory, recursive=True)
    observer.start()
    log_message(f"Aktivno spremljanje imenika: {directory}")
    return observer

# UI funkcije
def log_message(message):
    log_box.insert(END, message + "\n")
    log_box.see(END)

def start_passive_scan():
    passive_scan(scan_directory.get(), yara_rules)

def start_active_monitor():
    global observer
    if observer is None:
        observer = active_monitor(scan_directory.get(), yara_rules)
        monitor_status.set("Aktivno spremljanje: VKLOPLJENO")
    else:
        log_message("Spremljanje že poteka.")

def stop_active_monitor():
    global observer
    if observer is not None:
        observer.stop()
        observer.join()
        observer = None
        monitor_status.set("Aktivno spremljanje: IZKLOPLJENO")
        log_message("Spremljanje ustavljeno.")

def select_scan_directory():
    directory = filedialog.askdirectory()
    if directory:
        scan_directory.set(directory)
        log_message(f"Izbran imenik za skeniranje: {directory}")

def sync_yara_rules():
    log_message("Sinhronizacija pravil... (trenutno ni implementirano)")

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
Button(root, text="Sinhroniziraj YARA pravila", command=sync_yara_rules).pack()

Label(root, textvariable=monitor_status, fg="blue").pack()

log_box = Text(root, height=20, width=80)
log_box.pack()
scrollbar = Scrollbar(root, command=log_box.yview)
scrollbar.pack(side="right", fill="y")
log_box.config(yscrollcommand=scrollbar.set)

# Naloži YARA pravila
YARA_RULES_DIR = "./yara_rules"
yara_rules = load_yara_rules(YARA_RULES_DIR)

# Zagon aplikacije
root.mainloop()
