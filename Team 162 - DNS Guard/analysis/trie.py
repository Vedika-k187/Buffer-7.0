class TrieNode:
    def __init__(self):
        self.children = {}
        self.is_end = False
        self.domain = ""

class Trie:
    def __init__(self):
        self.root = TrieNode()

    def insert(self, domain):
        node = self.root
        for char in domain:
            if char not in node.children:
                node.children[char] = TrieNode()
            node = node.children[char]
        node.is_end = True
        node.domain = domain

    def search(self, domain):
        node = self.root
        for char in domain:
            if char not in node.children:
                return False
            node = node.children[char]
        return node.is_end

    def get_all_domains(self):
        results = []
        self._dfs(self.root, results)
        return results

    def _dfs(self, node, results):
        if node.is_end:
            results.append(node.domain)
        for child in node.children.values():
            self._dfs(child, results)

    def load_from_file(self, filepath):
        with open(filepath, "r") as f:
            for line in f:
                domain = line.strip()
                if domain:
                    self.insert(domain)
        print(f"Trie loaded with {len(self.get_all_domains())} domains")