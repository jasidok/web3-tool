
"""
Tests for the main framework.
"""

import unittest
import tempfile
import os
from pathlib import Path

from web3sec_framework.core.framework import Web3SecFramework
from web3sec_framework.core.config_manager import ConfigManager


class TestWeb3SecFramework(unittest.TestCase):
    """Test cases for Web3SecFramework."""
    
    def setUp(self):
        """Set up test environment."""
        self.temp_dir = tempfile.mkdtemp()
        self.config = ConfigManager()
        self.framework = Web3SecFramework(config=self.config)
    
    def test_framework_initialization(self):
        """Test framework initializes correctly."""
        self.assertIsNotNone(self.framework)
        self.assertIsNotNone(self.framework.scanner_manager)
        self.assertIsNotNone(self.framework.plugin_loader)
    
    def test_plugin_discovery(self):
        """Test plugin discovery works."""
        plugins = self.framework.list_plugins()
        self.assertIsInstance(plugins, list)
    
    def tearDown(self):
        """Clean up test environment."""
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()
