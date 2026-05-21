import os

def search_files(directory, pattern):
    for root, dirs, files in os.walk(directory):
        if ".git" in root or "node_modules" in root:
            continue
        for file in files:
            file_path = os.path.join(root, file)
            try:
                with open(file_path, "r", encoding="utf-8") as f:
                    content = f.read()
                    if pattern in content:
                        print(f"FOUND in {file_path}")
            except Exception:
                pass

if __name__ == "__main__":
    # Fixed path for the active workspace
    search_files(r"c:\Users\Lenovo\Desktop\Runtime-shield- login\Runtime-shield-for-agentic-systems", "EVENTS CALLED")
