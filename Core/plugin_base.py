class PluginBase:
    def __init__(self, nmap_results, output_manager):
        self.nmap_results = nmap_results
        self.output_manager = output_manager

    def run(self):
        raise NotImplementedError("Plugins must implement the run method.")
