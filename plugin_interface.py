class ScannerPlugin:
    def __init__(self, project_dir, scope, results):
        self.project_dir = project_dir
        self.targets = scope
        self.results = results


    def run_scan(self):
        raise NotImplementedError

    def parse_results(self):
        raise NotImplementedError