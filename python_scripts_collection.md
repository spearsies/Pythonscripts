# Python Scripts Collection

A curated collection of Python scripts extracted from Medium articles about Python programming, automation, and best practices.

## Table of Contents

1. [10 Python Errors That Almost Made Me Quit Coding](#10-python-errors-that-almost-made-me-quit-coding)
2. [15 Python Tools I Built Instead of Using Expensive Software](#15-python-tools-i-built-instead-of-using-expensive-software)
3. [3 Python Scripts That Proved Small Ideas Can Go Viral](#3-python-scripts-that-proved-small-ideas-can-go-viral)
4. [4 Python Habits That Turned Me From Beginner to Builder](#4-python-habits-that-turned-me-from-beginner-to-builder)
5. [5 Tiny Python Scripts That Got More Attention Than My Resume](#5-tiny-python-scripts-that-got-more-attention-than-my-resume)
6. [6 Python Lessons I Learned the Hard Way](#6-python-lessons-i-learned-the-hard-way)
7. [7 Python Libraries That Turned Boring Tasks Into One-Liners](#7-python-libraries-that-turned-boring-tasks-into-one-liners)
8. [7 Python Things No One Warned Me About (But I’m Glad I Found Out)](#7-python-things-no-one-warned-me-about-but-im-glad-i-found-out)
9. [7 Simple Python Automations That Run While I Sleep](#7-simple-python-automations-that-run-while-i-sleep)
10. [8 Python Scripts I Shared Once — And Couldn’t Stop the Notifications](#8-python-scripts-i-shared-once--and-couldnt-stop-the-notifications)
11. [9 Tiny Python Scripts That Quietly Upgraded My Brain](#9-tiny-python-scripts-that-quietly-upgraded-my-brain)
12. [From Zero to AI Engineer: The Only Python Roadmap You Need in 2026](#from-zero-to-ai-engineer-the-only-python-roadmap-you-need-in-2026)
13. [I Automated 10 Tasks With Python — Here’s What Happened](#i-automated-10-tasks-with-python--heres-what-happened)

---

## 10 Python Errors That Almost Made Me Quit Coding

*Source: 10 Python Errors That Almost Made Me Quit Coding | by Arfa | Jan, 2026 | Medium.pdf*

### Script 1

```python
run_pipeline()
def run_pipeline():
print("Running")
```

### Script 2

```python
result = get_data()
print(result["value"])
```

### Script 3

```python
status = "INIT"
def run():
```

### Script 4

```python
f = open("data.txt")
process(f)
```

---

## 15 Python Tools I Built Instead of Using Expensive Software

*Source: 15 Python Tools I Built Instead of Using Expensive Software | by Vignesh Selvaraj | Jan, 2026 | Python in Plain English.pdf*

### Script 1

```python
import json
from datetime import datetime
FILE = "tasks.json"
def load_tasks():
try:
with open(FILE, "r") as f:
return json.load(f)
except FileNotFoundError:
return []
def save_tasks(tasks):
with open(FILE, "w") as f:
json.dump(tasks, f, indent=2)
def add_task(title, due_date=None):
tasks = load_tasks()
tasks.append({
```

### Script 2

```python
import csv
from datetime import date
def log_habit(name, completed):
with open("habits.csv", "a", newline="") as f:
writer = csv.writer(f)
writer.writerow([date.today().isoformat(), name, int(completed)])
log_habit("coding", True)
```

### Script 3

```python
import sqlite3
from datetime import datetime
conn = sqlite3.connect("timelog.db")
c = conn.cursor()
c.execute("""CREATE TABLE IF NOT EXISTS sessions
```

### Script 4

```python
def start_session(task):
c.execute("INSERT INTO sessions VALUES (?, ?, ?)", (task, datetime.now().isoformat(), None))
conn.commit()
def end_session():
c.execute("UPDATE sessions SET end=? WHERE end IS NULL", (datetime.now().isoformat(),))
conn.commit()
```

### Script 5

```python
import os
def search_notes(keyword, folder="notes"):
for root, _, files in os.walk(folder):
for file in files:
```

### Script 6

```python
path = os.path.join(root, file)
with open(path) as f:
```

### Script 7

```python
print(path)
search_notes("docker")
```

### Script 8

```python
with timestamps.
import os
import time
from datetime import datetime
WATCH = "screenshots"
while True:
for f in os.listdir(WATCH):
```

### Script 9

```python
new_name = datetime.now().strftime("%Y%m%d_%H%M%S.png")
os.rename(os.path.join(WATCH, f), os.path.join(WATCH, new_name))
time.sleep(5)
```

### Script 10

```python
from fpdf import FPDF
def create_invoice(client, items):
pdf = FPDF()
pdf.add_page()
pdf.set_font("Arial", size=12)
pdf.cell(200, 10, txt=f"Invoice for {client}", ln=True)
total = 0
for desc, price in items:
pdf.cell(200, 10, txt=f"{desc}: ${price}", ln=True)
```

### Script 11

```python
import csv
from datetime import datetime
def load_posts():
with open("posts.csv") as f:
return list(csv.DictReader(f))
for post in load_posts():
```

### Script 12

```python
import shutil
from datetime import date
shutil.make_archive(f"backup_{date.today()}", 'zip', 'important_folder')
```

### Script 13

```python
from PIL import Image
import os
for file in os.listdir("images"):
```

### Script 14

```python
img = Image.open(os.path.join("images", file))
img.resize((1200, 800)).save(os.path.join("resized", file))
```

### Script 15

```python
import requests
import smtplib
def check_site(url):
try:
r = requests.get(url, timeout=5)
return r.status_code == 200
```

### Script 16

```python
import pandas as pd
df = pd.read_csv("raw.csv")
```

### Script 17

```python
from flask import Flask
app = Flask(__name__)
@app.route("/")
def home():
return "My personal dashboard"
app.run(debug=True)
```

### Script 18

```python
import sqlite3
conn = sqlite3.connect("links.db")
c = conn.cursor()
c.execute("CREATE TABLE IF NOT EXISTS links (url TEXT, tags TEXT)")
c.execute("INSERT INTO links VALUES (?, ?)", ("https://example.com", "python,tools"))
conn.commit()
```

### Script 19

```python
from datetime import datetime
def due_today(tasks):
today = datetime.today().date().isoformat()
return [t for t in tasks if t["due"] == today]
```

### Script 20

```python
import json
from datetime import datetime
def log_contact(name, note):
with open("contacts.json", "a") as f:
f.write(json.dumps({
```

### Script 21

```python
import os
import sqlite3
conn = sqlite3.connect("file_index.db")
c = conn.cursor()
c.execute("CREATE TABLE IF NOT EXISTS files (path TEXT, content TEXT)")
def index_folder(folder):
for root, _, files in os.walk(folder):
for name in files:
```

### Script 22

```python
path = os.path.join(root, name)
try:
with open(path, "r", errors="ignore") as f:
content = f.read()
c.execute("INSERT INTO files VALUES (?, ?)", (path, content))
```

### Script 23

```python
import time
import os
import shutil
WATCH = "incoming"
DEST = "processed"
seen = set()
while True:
for f in os.listdir(WATCH):
```

### Script 24

```python
shutil.move(os.path.join(WATCH, f), os.path.join(DEST, f))
print("Processed:", f)
seen.add(f)
time.sleep(10)
```

### Script 25

```python
import os
from datetime import date
def count_words(folder="writing"):
total = 0
for f in os.listdir(folder):
```

### Script 26

```python
import csv
from datetime import datetime
def log_account(service, note):
with open("accounts.csv", "a", newline="") as f:
writer = csv.writer(f)
writer.writerow([service, note, datetime.now().isoformat()])
log_account("Old SaaS Tool", "Check if still needed")
```

### Script 27

```python
import requests
from bs4 import BeautifulSoup
def save_article(url):
r = requests.get(url)
soup = BeautifulSoup(r.text, "html.parser")
text = soup.get_text()
filename = url.replace("https://", "").replace("/", "_")[:50] + ".md"
with open(f"articles/{filename}", "w", encoding="utf-8") as f:
f.write(text)
save_article("https://example.com/article")
```

### Script 28

```python
print("Today’s Focus:\n")
for g in goals:
print("-", g)
```

### Script 29

```python
import pandas as pd
old = pd.read_csv("old.csv")
new = pd.read_csv("new.csv")
diff = pd.concat([new, old]).drop_duplicates(keep=False)
diff.to_csv("differences.csv", index=False)
```

### Script 30

```python
import json
def add_resource(title, status="planned"):
try:
with open("learning.json") as f:
data = json.load(f)
```

### Script 31

```python
data = []
data.append({"title": title, "status": status})
with open("learning.json", "w") as f:
json.dump(data, f, indent=2)
json.dump(data, f, indent=2)
add_resource("Advanced Pandas Tutorial")
```

### Script 32

```python
import os
sizes = []
for root, _, files in os.walk("."):
for f in files:
path = os.path.join(root, f)
try:
sizes.append((path, os.path.getsize(path)))
```

### Script 33

```python
pass
for path, size in sorted(sizes, key=lambda x: x[1], reverse=True)[:10]:
print(size, path)
```

### Script 34

```python
import os
import random
import subprocess
music_folder = "focus_music"
songs = [os.path.join(music_folder, f) for f in os.listdir(music_folder)]
subprocess.run(["open", random.choice(songs)])
```

---

## 3 Python Scripts That Proved Small Ideas Can Go Viral

*Source: 3 Python Scripts That Proved Small Ideas Can Go Viral | by Arfa | Jan, 2026 | Level Up Coding.pdf*

### Script 1

```python
embeddings = model.encode(texts)
clusters = kmeans.fit_predict(embeddings)
```

---

## 4 Python Habits That Turned Me From Beginner to Builder

*Source: 4 Python Habits That Turned Me From Beginner to Builder | by Arfa | Jan, 2026 | Python in Plain English.pdf*

### Script 1

```python
from pathlib import Path
for file in Path("downloads").glob("*.pdf"):
file.rename(Path("reports") / file.name)
```

### Script 2

```python
def normalize_filename(name: str) -> str:
return name.lower().replace(" ", "_")
```

### Script 3

```python
import requests
response = requests.get(url)
data = response.text
```

---

## 5 Tiny Python Scripts That Got More Attention Than My Resume

*Source: 5 Tiny Python Scripts That Got More Attention Than My Resume | by Arfa | Jan, 2026 | Python in Plain English.pdf*

### Script 1

```python
summary = summarize(transcript_text, max_points=5)
save_notes(video_title, summary)
```

### Script 2

```python
def generate_report(data):
return analyze(data).to_markdown()
```

---

## 6 Python Lessons I Learned the Hard Way

*Source: 6 Python Lessons I Learned the Hard Way | by Arfa | Jan, 2026 | Python in Plain English.pdf*

### Script 1

```python
def main():
fetch_data()
transform_data()
store_results()
if __name__ == "__main__":
main()
```

### Script 2

```python
import logging
logging.basicConfig(
filename="pipeline.log",
level=logging.INFO,
format="%(asctime)s - %(levelname)s - %(message)s"
```

### Script 3

```python
import os
API_KEY = os.getenv("API_KEY")
DATA_DIR = os.getenv("DATA_DIR", "/default/path")
```

### Script 4

```python
# Bad (clever, compact, painful)
results = [x for x in data if x.is_valid() and transform(x)]
# Better (boring, readable, durable)
results = []
for item in data:
```

### Script 5

```python
# Instead of calling an API repeatedly
responses = []
for item in items:
responses.append(call_api(item))
# Batch when possible
responses = call_api_batch(items)
```

### Script 6

```python
data = load_data(input_path)
report = analyze(data)
save(report, output_path)
```

---

## 7 Python Libraries That Turned Boring Tasks Into One-Liners

*Source: 7 Python Libraries That Turned Boring Tasks Into One-Liners | by Arfa | Jan, 2026 | Medium.pdf*

### Script 1

```python
from pathlib import Path
files = Path("reports").glob("*.pdf")
```

### Script 2

```python
from rich.console import Console
console = Console()
console.log("Processing started")
```

### Script 3

```python
import schedule
schedule.every().day.at("10:00").do(run_job)
```

### Script 4

```python
import requests
data = requests.get(url).json()
```

### Script 5

```python
import pandas as pd
df = pd.read_csv("data.csv")
df.groupby("status").count()
```

### Script 6

```python
import typer
def main(name: str):
print(f"Hello {name}")
typer.run(main)
```

---

## 7 Python Things No One Warned Me About (But I’m Glad I Found Out)

*Source: 7 Python Things No One Warned Me About (But I’m Glad I Found Out) | by Arfa | Jan, 2026 | Medium.pdf*

### Script 1

```python
def aggregate_daily_sales(file_path: str) -> float:
total_sales = 0.0
with open(file_path) as file:
for line in file:
```

### Script 2

```python
results = []
for user_id in user_ids:
results.append(fetch_user_data(user_id))
```

### Script 3

```python
from concurrent.futures import ThreadPoolExecutor
with ThreadPoolExecutor(max_workers=10) as executor:
results = list(executor.map(fetch_user_data, user_ids))
```

### Script 4

```python
try:
response.raise_for_status()
data = response.json()
except Exception as e:
log_error(e)
notify_admin("API failure")
```

### Script 5

```python
import os
for index, filename in enumerate(os.listdir("reports")):
new_name = f"report_{index}.pdf"
os.rename(f"reports/{filename}", f"reports/{new_name}")
```

### Script 6

```python
import logging
logging.basicConfig(
filename="automation.log",
level=logging.INFO,
format="%(asctime)s - %(levelname)s - %(message)s"
```

---

## 7 Simple Python Automations That Run While I Sleep

*Source: 7 Simple Python Automations That Run While I Sleep | by Vignesh Selvaraj | Jan, 2026 | Python in Plain English.pdf*

### Script 1

```python
import imaplib
import email
from email.header import decode_header
IMAP_SERVER = "imap.gmail.com"
EMAIL_ACCOUNT = "your_email@gmail.com"
PASSWORD = "your_app_password"
mail = imaplib.IMAP4_SSL(IMAP_SERVER)
mail.login(EMAIL_ACCOUNT, PASSWORD)
mail.select("inbox")
```

### Script 2

```python
email_ids = messages[0].split()
for e_id in email_ids:
```

### Script 3

```python
raw_email = msg_data[0][1]
msg = email.message_from_bytes(raw_email)
```

### Script 4

```python
subject = subject.decode(encoding or "utf-8")
subject_lower = subject.lower()
```

### Script 5

```python
import os
import shutil
from pathlib import Path
DOWNLOADS = Path.home() / "Downloads"
FILE_TYPES = {
```

### Script 6

```python
target_dir = DOWNLOADS / folder
target_dir.mkdir(exist_ok=True)
shutil.move(str(file), target_dir / file.name)
break
```

### Script 7

```python
import shutil
from datetime import datetime
from pathlib import Path
SOURCE_DIRS = [
Path.home() / "Documents/Work",
Path.home() / "Documents/Personal"
```

### Script 8

```python
BACKUP_ROOT = Path.home() / "Backups"
BACKUP_ROOT.mkdir(exist_ok=True)
timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M")
backup_path = BACKUP_ROOT / f"backup_{timestamp}"
backup_path.mkdir()
for folder in SOURCE_DIRS:
```

### Script 9

```python
import requests
from bs4 import BeautifulSoup
import smtplib
URL = "https://example.com/product"
TARGET_PRICE = 1999 # in your currency
headers = {"User-Agent": "Mozilla/5.0"}
response = requests.get(URL, headers=headers)
soup = BeautifulSoup(response.text, "html.parser")
price_text = soup.find("span", {"class": "price"}).text
price = int(''.join(filter(str.isdigit, price_text)))
```

### Script 10

```python
with smtplib.SMTP("smtp.gmail.com", 587) as server:
server.starttls()
server.login("your_email@gmail.com", "your_app_password")
message = f"Subject: Price Drop Alert\n\nPrice is now {price}"
server.sendmail("your_email@gmail.com", "your_email@gmail.com", message)
```

### Script 11

```python
import pandas as pd
import smtplib
df = pd.read_csv("sales_data.csv")
total_sales = df["amount"].sum()
total_orders = df.shape[0]
average_order = df["amount"].mean()
report = f"""
```

### Script 12

```python
import feedparser
from datetime import datetime
FEED_URL = "https://exampleblog.com/rss"
feed = feedparser.parse(FEED_URL)
with open("reading_list.txt", "a", encoding="utf-8") as f:
f.write(f"\n\n=== {datetime.now()} ===\n")
for entry in feed.entries[:5]:
f.write(f"{entry.title}\n{entry.link}\n\n")
```

### Script 13

```python
import csv
from datetime import date
today = date.today()
steps = 8234 # pulled from a file or API
hours_worked = 7.5
wrote_words = 650
with open("daily_log.csv", "a", newline="") as file:
writer = csv.writer(file)
writer.writerow([today, steps, hours_worked, wrote_words])
```

### Script 14

```python
VIP_SENDERS = ["boss@company.com", "client@important.com"]
from_email = email.utils.parseaddr(msg.get("From"))[1]
```

### Script 15

```python
EXCLUDE = ["node_modules", ".cache", "Library"]
def should_skip(path):
return any(part in EXCLUDE for part in path.parts)
```

### Script 16

```python
from pathlib import Path
import shutil
from datetime import datetime
desktop = Path.home() / "Desktop"
archive = desktop / "Desktop Archive"
archive.mkdir(exist_ok=True)
today_folder = archive / datetime.now().strftime("%Y-%m-%d")
today_folder.mkdir(exist_ok=True)
for item in desktop.iterdir():
```

### Script 17

```python
import shutil
import smtplib
```

---

## 8 Python Scripts I Shared Once — And Couldn’t Stop the Notifications

*Source: 8 Python Scripts I Shared Once — And Couldn’t Stop the Notifications | by Arfa | Jan, 2026 | Level Up Coding.pdf*

### Script 1

```python
from pathlib import Path
for file in Path(".").iterdir():
```

### Script 2

```python
folder = Path(file.suffix[1:].upper())
folder.mkdir(exist_ok=True)
file.rename(folder / file.name)
```

### Script 3

```python
def tailor_resume(resume, job_desc):
prompt = f"Match this resume to the job:\n{resume}\nJob:\n{job_desc}"
return llm(prompt)
```

### Script 4

```python
from youtube_transcript_api import YouTubeTranscriptApi
transcript = YouTubeTranscriptApi.get_transcript(video_id)
text = " ".join(t["text"] for t in transcript)
summary = summarize(text)
```

### Script 5

```python
from collections import Counter
with open("app.log") as f:
errors = [line for line in f if "ERROR" in line]
print(Counter(errors).most_common(5))
```

### Script 6

```python
from sentence_transformers import SentenceTransformer
model = SentenceTransformer("all-MiniLM-L6-v2")
embeddings = model.encode(abstracts)
```

### Script 7

```python
def should_reply(email):
urgent = ["asap", "urgent", "deadline"]
return any(word in email.lower() for word in urgent)
```

### Script 8

```python
def generate_report(data):
return {
```

### Script 9

```python
def automate(task):
parse(task)
decide(task)
execute(task)
```

---

## 9 Tiny Python Scripts That Quietly Upgraded My Brain

*Source: 9 Tiny Python Scripts That Quietly Upgraded My Brain | by Arfa | Jan, 2026 | Level Up Coding.pdf*

### Script 1

```python
import difflib
diff = difflib.unified_diff(old.splitlines(), new.splitlines())
print("\n".join(diff))
```

---

## From Zero to AI Engineer: The Only Python Roadmap You Need in 2026

*Source: From Zero to AI Engineer: The Only Python Roadmap You Need in 2026 | by Vignesh Selvaraj | Feb, 2026 | Level Up Coding.pdf*

### Script 1

```python
def calculate_average(grades):
return sum(grades) / len(grades)
def find_highest(grades):
return max(grades)
def find_lowest(grades):
return min(grades)
student_grades = [78, 85, 92, 88, 76, 95]
print("Average:", calculate_average(student_grades))
print("Highest:", find_highest(student_grades))
print("Lowest:", find_lowest(student_grades))
```

### Script 2

```python
text = "AI will not replace you. A person using AI will."
words = text.lower().replace(".", "").split()
frequency = {}
for word in words:
```

### Script 3

```python
import numpy as np
arr = np.array([1, 2, 3, 4])
print("Mean:", np.mean(arr))
print("Standard Deviation:", np.std(arr))
```

### Script 4

```python
import pandas as pd
data = {
```

### Script 5

```python
df = pd.read_csv("movies.csv")
top_movies = df.sort_values("rating", ascending=False).head(10)
print(top_movies[["title", "rating"]])
avg_by_genre = df.groupby("genre")["rating"].mean()
print(avg_by_genre)
```

### Script 6

```python
from sklearn.model_selection import train_test_split
from sklearn.linear_model import LinearRegression
import pandas as pd
data = pd.read_csv("housing.csv")
X = data[["area", "bedrooms"]]
y = data["price"]
```

### Script 7

```python
model = LinearRegression()
model.fit(X_train, y_train)
predictions = model.predict(X_test)
print(predictions[:5])
```

### Script 8

```python
from sklearn.feature_extraction.text import CountVectorizer
from sklearn.naive_bayes import MultinomialNB
emails = ["Win money now", "Meeting at 5pm", "Claim your prize"]
labels = [1, 0, 1]
vectorizer = CountVectorizer()
X = vectorizer.fit_transform(emails)
model = MultinomialNB()
model.fit(X, labels)
test_email = ["Free prize waiting"]
test_vector = vectorizer.transform(test_email)
print(model.predict(test_vector))
```

### Script 9

```python
with exercises designed exactly for this transition
from Python learner to ML builder.
```

### Script 10

```python
import torch
import torch.nn as nn
import torch.optim as optim
from torchvision import datasets, transforms
# Load data
transform = transforms.ToTensor()
train_data = datasets.MNIST(root="./data", train=True, download=True, transform=transform)
train_loader = torch.utils.data.DataLoader(train_data, batch_size=64, shuffle=True)
# Define neural network
class DigitModel(nn.Module):
def __init__(self):
super().__init__()
```

### Script 11

```python
def forward(self, x):
x = x.view(-1, 28*28)
x = torch.relu(self.layer1(x))
x = torch.relu(self.layer2(x))
return self.output(x)
model = DigitModel()
criterion = nn.CrossEntropyLoss()
optimizer = optim.Adam(model.parameters(), lr=0.001)
# Training loop
for epoch in range(3):
for images, labels in train_loader:
optimizer.zero_grad()
outputs = model(images)
loss = criterion(outputs, labels)
loss.backward()
optimizer.step()
print(f"Epoch {epoch+1}, Loss: {loss.item():.4f}")
```

### Script 12

```python
import tensorflow as tf
from tensorflow.keras import layers, models
# Load data
```

### Script 13

```python
train_images = train_images / 255.0
# Build model
model = models.Sequential([
layers.Flatten(input_shape=(28, 28)),
layers.Dense(128, activation='relu'),
layers.Dense(64, activation='relu'),
layers.Dense(10, activation='softmax')
```

### Script 14

```python
import torch
import torch.nn as nn
import torch.optim as optim
from torchvision import datasets, transforms
transform = transforms.ToTensor()
train_data = datasets.CIFAR10(root="./data", train=True, download=True, transform=transform)
train_loader = torch.utils.data.DataLoader(train_data, batch_size=64, shuffle=True)
class CNN(nn.Module):
def __init__(self):
super().__init__()
```

### Script 15

```python
def forward(self, x):
x = self.pool(torch.relu(self.conv1(x)))
x = self.pool(torch.relu(self.conv2(x)))
x = x.view(-1, 64 * 6 * 6)
x = torch.relu(self.fc1(x))
return self.fc2(x)
model = CNN()
criterion = nn.CrossEntropyLoss()
optimizer = optim.Adam(model.parameters(), lr=0.001)
for epoch in range(2):
for images, labels in train_loader:
optimizer.zero_grad()
outputs = model(images)
loss = criterion(outputs, labels)
loss.backward()
optimizer.step()
print("Epoch complete")
```

### Script 16

```python
import tensorflow as tf
from tensorflow.keras.preprocessing.text import Tokenizer
from tensorflow.keras.preprocessing.sequence import pad_sequences
sentences = ["I love this product", "This is terrible"]
labels = [1, 0]
tokenizer = Tokenizer(num_words=1000)
tokenizer.fit_on_texts(sentences)
sequences = tokenizer.texts_to_sequences(sentences)
padded = pad_sequences(sequences, maxlen=5)
model = tf.keras.Sequential([
```

### Script 17

```python
from transformers import pipeline
generator = pipeline("text-generation", model="gpt2")
result = generator("The future of AI is", max_length=50, num_return_sequences=1)
print(result[0]["generated_text"])
```

### Script 18

```python
from transformers import pipeline
qa_pipeline = pipeline("question-answering")
context = "Python is a popular programming language used for AI and machine learning."
question = "What is Python used for?"
result = qa_pipeline(question=question, context=context)
print(result["answer"])
```

---

## I Automated 10 Tasks With Python — Here’s What Happened

*Source: I Automated 10 Tasks With Python — Here’s What Happened | by Vignesh Selvaraj | Jan, 2026 | Python in Plain English.pdf*

### Script 1

```python
import os
from datetime import datetime
folder_path = "reports"
for filename in os.listdir(folder_path):
old_path = os.path.join(folder_path, filename)
```

### Script 2

```python
modified_time = os.path.getmtime(old_path)
date_str = datetime.fromtimestamp(modified_time).strftime("%Y-%m-%d")
new_filename = f"sales_report_{date_str}.csv"
new_path = os.path.join(folder_path, new_filename)
os.rename(old_path, new_path)
print("Files renamed successfully.")
```

### Script 3

```python
import pandas as pd
df = pd.read_excel("raw_data.xlsx")
```

### Script 4

```python
df.to_excel("clean_data.xlsx", index=False)
print("Data cleaned and saved.")
```

### Script 5

```python
import smtplib
from email.message import EmailMessage
import pandas as pd
df = pd.read_excel("clean_data.xlsx")
total_sales = df["revenue"].sum()
msg = EmailMessage()
```

### Script 6

```python
msg.set_content(f"Today's total sales: ${total_sales:,.2f}")
with smtplib.SMTP("smtp.gmail.com", 587) as server:
server.starttls()
server.login("me@example.com", "your_password")
server.send_message(msg)
print("Email sent.")
```

### Script 7

```python
import os
import shutil
source = "Downloads"
for file in os.listdir(source):
file_path = os.path.join(source, file)
```

### Script 8

```python
shutil.move(file_path, "Documents/Images")
print("Files organized.")
```

### Script 9

```python
import shutil
from datetime import datetime
source_folder = "important_files"
backup_folder = "backup"
date = datetime.now().strftime("%Y%m%d_%H%M%S")
destination = f"{backup_folder}/backup_{date}"
shutil.copytree(source_folder, destination)
print("Backup created.")
```

### Script 10

```python
import requests
from bs4 import BeautifulSoup
url = "https://example.com/prices"
response = requests.get(url)
soup = BeautifulSoup(response.text, "html.parser")
prices = [p.text for p in soup.select(".price")]
print(prices)
```

### Script 11

```python
import pandas as pd
import os
folder = "csv_files"
for file in os.listdir(folder):
```

### Script 12

```python
df = pd.read_csv(os.path.join(folder, file))
new_name = file.replace(".csv", ".xlsx")
df.to_excel(os.path.join(folder, new_name), index=False)
print("All files converted.")
```

### Script 13

```python
import time
from datetime import datetime
task = input("What are you working on? ")
start = datetime.now()
input("Press Enter when done...")
end = datetime.now()
duration = (end - start).seconds / 60
with open("time_log.txt", "a") as f:
f.write(f"{task} - {duration} minutes\n")
print("Time logged.")
```

### Script 14

```python
import pandas as pd
import matplotlib.pyplot as plt
df = pd.read_excel("weekly_data.xlsx")
summary = df.groupby("week")["revenue"].sum()
summary.plot(kind="bar")
plt.title("Weekly Revenue")
plt.savefig("weekly_report.png")
print("Report generated.")
```

### Script 15

```python
from datetime import datetime
tasks = [
```

### Script 16

```python
today = datetime.today().date()
for task, date_str in tasks:
task_date = datetime.strptime(date_str, "%Y-%m-%d").date()
```

---

