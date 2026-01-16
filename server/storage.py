import json 
import os 
from typing import List

class AppendOnlyStorage:
    """
    Disk-backed append only storage.
    """

    def __init__(self, path = "board_data.json"):
        self.path = path 

        if not os.path.exists(self.path):
            with open(self.path, "w") as f:
                json.dump([], f)

    def append(self, obj: dict):
        data = self.load_all()
        data.append(obj)

        with open(self.path, "w") as f:
            json.dump(data, f, indent = 2)

    def load_all(self)-> List[dict]:
        with open(self.path, "r") as f:
            return json.load(f)